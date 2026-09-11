import { readJsonFile } from './mcp-auth-config'
import { OAuthTokensWithExpiresAtSchema } from './node-oauth-client-provider'
import { AuthCodeResult } from './types'
import { EventEmitter } from 'events'
import { Agent } from 'undici'
import { Server } from 'http'
import express from 'express'
import { log, debugLog, setupOAuthCallbackServerWithLongPoll, MCP_REMOTE_ID_PATH } from './utils'

/** How long to wait on another instance's sign-in before going it alone. Sign-ins involve a human. */
const FOLLOWER_PATIENCE_MS = 3 * 60_000

/**
 * How long to wait on a sibling the *second* time, after its tokens were already refused once.
 *
 * The first wait is the patient one, because a sign-in takes as long as a person takes. By the time
 * this instance is looking again it has already waited that out and been handed something that did
 * not work, so waiting the full window again only doubles a delay the host may already be reading
 * as a hang - and the thing actually worth checking, whether the callback port has been released,
 * is answered in seconds.
 */
const REFRESH_FOLLOWER_PATIENCE_MS = 10_000

export type AuthCoordinator = {
  /** @param options `forceRefresh` discards a cached verdict this instance has already acted on */
  initializeAuth: (options?: { forceRefresh?: boolean }) => Promise<{
    server: Server
    waitForAuthCode: () => Promise<AuthCodeResult>
    skipBrowserAuth: boolean
    actualPort: number
  }>
}

/**
 * Creates a lazy auth coordinator that will only initiate auth when needed
 * @param serverUrlHash The hash of the server URL
 * @param callbackPath The path to serve the callback endpoint on
 * @param callbackPort The port to use for the callback server
 * @param events The event emitter to use for signaling
 * @param strictPort If true, fail rather than fall back to a random port on EADDRINUSE
 * @returns An AuthCoordinator object with an initializeAuth method
 */
export function createLazyAuthCoordinator(
  serverUrlHash: string,
  callbackPath: string,
  callbackPort: number,
  events: EventEmitter,
  authTimeoutMs: number,
  strictPort = false,
): AuthCoordinator {
  // The in-flight promise is what gets shared, not the resolved value. Guarding on the result
  // only rules out sequential re-entry: two 401s landing in the same tick would both find it
  // unset and both start a flow, and the loser of the resulting port race used to take the
  // process down with an unhandled EADDRINUSE (https://github.com/geelen/mcp-remote/issues/317).
  let authState: Promise<{
    server: Server
    waitForAuthCode: () => Promise<AuthCodeResult>
    skipBrowserAuth: boolean
    actualPort: number
  }> | null = null

  return {
    initializeAuth: async (options) => {
      let refreshed = false

      if (authState && options?.forceRefresh) {
        // The cached verdict has been acted on and did not hold. Keeping it would keep answering
        // "wait for the sibling" to an instance that has already waited (issue #352).
        debugLog('Discarding the cached auth coordination verdict and looking again')
        refreshed = true

        // The callback server the old verdict carries is still listening, and nothing else holds a
        // handle to it once this is nulled. Left open it both leaks a socket and answers the port
        // probe of the very `coordinateAuth` about to run - so this instance would find "a sibling"
        // on the port, and the sibling would be itself.
        const stale = authState
        authState = null
        // Awaited, not fired and forgotten: the port has to be free before the fresh
        // `coordinateAuth` below tries to bind it, or that bind races this close and can still
        // find the socket this instance is in the middle of giving up.
        await stale.then(({ server }) => new Promise<void>((resolve) => server.close(() => resolve()))).catch(() => {})
      }

      if (authState) {
        debugLog('Auth already initializing or initialized, reusing it')
        return authState
      }

      log('Initializing auth coordination on-demand')
      debugLog('Initializing auth coordination on-demand', { serverUrlHash, callbackPort })

      authState = coordinateAuth(
        serverUrlHash,
        callbackPath,
        callbackPort,
        events,
        authTimeoutMs,
        strictPort,
        refreshed ? REFRESH_FOLLOWER_PATIENCE_MS : undefined,
      )
      try {
        const resolved = await authState
        debugLog('Auth coordination completed', { skipBrowserAuth: resolved.skipBrowserAuth, actualPort: resolved.actualPort })
        return resolved
      } catch (error) {
        // A failed attempt must not be cached, or every later retry replays the same rejection
        authState = null
        throw error
      }
    },
  }
}

/**
 * Coordinates authentication between multiple instances of the client/proxy
 * @param serverUrlHash The hash of the server URL
 * @param callbackPath The path to serve the callback endpoint on
 * @param callbackPort The port to use for the callback server
 * @param events The event emitter to use for signaling
 * @param strictPort If true, fail rather than fall back to a random port on EADDRINUSE
 * @returns An object with the server, actualPort, waitForAuthCode function, and a flag indicating if browser auth can be skipped
 */
/** How many ports after the deterministic one to try before giving up on strangers holding them. */
const PORT_CANDIDATES = 8

/** How often a follower checks whether the owner has finished, or has died and freed the port. */
const FOLLOWER_POLL_INTERVAL_MS = 250

/**
 * Asks whoever holds a port whether they are an mcp-remote serving this same server.
 *
 * A refused bind says the port is taken, not by what. Without this an unrelated process squatting
 * on the port would make every instance wait for a sign-in that is never coming.
 */
/**
 * Talks to loopback directly, whatever global dispatcher is installed.
 *
 * `--enable-proxy` sets a global EnvHttpProxyAgent, which does not exempt loopback - so without
 * this the identity probe is sent to the corporate proxy, times out, and every sibling is
 * mistaken for a stranger.
 */
const loopbackDispatcher = new Agent()

async function portHeldBySiblingFor(port: number, serverUrlHash: string): Promise<boolean> {
  try {
    const response = await fetch(`http://127.0.0.1:${port}${MCP_REMOTE_ID_PATH}`, {
      signal: AbortSignal.timeout(1000),
      dispatcher: loopbackDispatcher,
    } as RequestInit)
    if (!response.ok) return false
    const body = (await response.json()) as { mcpRemote?: boolean; serverUrlHash?: string }
    return body?.mcpRemote === true && body.serverUrlHash === serverUrlHash
  } catch {
    // No answer, or not something that speaks our identity route
    return false
  }
}

/**
 * Whether the server answers an unauthenticated request with a challenge.
 *
 * Ownership has to be settled before the first connection attempt, because the SDK registers a
 * client from inside `transport.start()`. But that is only worth doing for a server that actually
 * wants OAuth: a public one, or one authenticated by `--header`, never writes tokens, so every
 * instance but the first would wait out the handoff timeout and exit.
 */
export async function serverIssuesAuthChallenge(serverUrl: string, headers: Record<string, string> = {}): Promise<boolean> {
  try {
    const response = await fetch(serverUrl, {
      method: 'GET',
      headers: { ...headers, accept: 'application/json, text/event-stream' },
      signal: AbortSignal.timeout(5000),
    })
    debugLog('Probed the server for an auth challenge', { status: response.status })
    return response.status === 401
  } catch (error) {
    // Unreachable or too slow to say. Leave it to the 401 handler, as before.
    debugLog('Could not probe the server for an auth challenge', error)
    return false
  }
}

/**
 * Whether the tokens on disk make a browser sign-in unnecessary.
 *
 * Not simply "a token exists": an expired one with a refresh token is renewed without the
 * browser, while an expired one without is exactly the case that needs a flow - and treating it
 * as usable is what let every instance skip coordination on re-authentication and open its own
 * tab, which is the storm of login windows people report after a token lapses.
 */
export async function hasUsableTokens(serverUrlHash: string): Promise<boolean> {
  const tokens = await readJsonFile<{ expires_at?: number; refresh_token?: string }>(
    serverUrlHash,
    'tokens.json',
    OAuthTokensWithExpiresAtSchema,
  )
  if (!tokens) return false
  if (tokens.expires_at && Date.now() >= tokens.expires_at - TOKEN_EXPIRY_MARGIN_MS) {
    return !!tokens.refresh_token
  }
  return true
}

/** Tokens another instance has already obtained, if they are on disk and usable. */
/** Treat a token about to expire as expired, matching the provider's own refresh margin. */
const TOKEN_EXPIRY_MARGIN_MS = 60_000

/**
 * Takes ownership of a server's OAuth flow, or waits for whoever has it.
 *
 * Ownership *is* being bound to the callback port. That makes it atomic (the kernel admits one
 * listener), self-releasing (the port comes back when the process dies, however it dies), and
 * exactly the thing correctness depends on - an authorization code can only ever be delivered to
 * whoever holds the port named in its redirect_uri. A lockfile can only ever be a guess about
 * those facts, which is why the previous one needed liveness probes, staleness heuristics and a
 * carve-out disabling it on Windows.
 */
export async function coordinateAuth(
  serverUrlHash: string,
  callbackPath: string,
  callbackPort: number,
  events: EventEmitter,
  authTimeoutMs: number,
  strictPort = false,
  followerPatienceMs = FOLLOWER_PATIENCE_MS,
): Promise<{ server: Server; actualPort: number; waitForAuthCode: () => Promise<AuthCodeResult>; skipBrowserAuth: boolean }> {
  debugLog('Coordinating authentication', { serverUrlHash, callbackPath, callbackPort })

  // Pinned by an explicit port argument or by static client info: that exact port or nothing, since the redirect_uri
  // it implies is not ours to move.
  const candidates = strictPort ? [callbackPort] : Array.from({ length: PORT_CANDIDATES }, (_, i) => callbackPort + i)

  for (const port of candidates) {
    try {
      const { server, actualPort, waitForAuthCode } = await setupOAuthCallbackServerWithLongPoll({
        port,
        path: callbackPath,
        events,
        authTimeoutMs,
        serverUrlHash,
      })

      // Binding is only a mutex between instances contending for the *same* port. Instances that
      // were pushed past a port a stranger holds can race onto different candidates and each
      // conclude it won, so a later candidate has to yield to any sibling already established on
      // an earlier one. Lowest bound candidate wins, which every instance can agree on.
      const established = await firstSiblingBefore(candidates, port, serverUrlHash)
      if (established !== undefined) {
        debugLog('Yielding to a sibling established on an earlier candidate', { ours: actualPort, theirs: established })
        await new Promise<void>((resolve) => server.close(() => resolve()))
        return followUntilTokensOrPort(serverUrlHash, callbackPath, established, events, authTimeoutMs, followerPatienceMs)
      }

      log(`This instance is running the sign-in for this server (callback port ${actualPort})`)
      return { server, actualPort, waitForAuthCode, skipBrowserAuth: false }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (code !== 'EADDRINUSE' && code !== 'EACCES') throw error

      if (code === 'EACCES') {
        // Reserved by the OS rather than held by anyone we can talk to
        debugLog(`Not permitted to bind port ${port}`, { serverUrlHash })
        if (strictPort) throw error
        continue
      }

      if (await portHeldBySiblingFor(port, serverUrlHash)) {
        log(`Another instance is running the sign-in for this server on port ${port}`)
        return followUntilTokensOrPort(serverUrlHash, callbackPath, port, events, authTimeoutMs, followerPatienceMs)
      }

      // Somebody else's process. Ours is not there to be waited for, so keep looking.
      debugLog(`Port ${port} is held by an unrelated process`, { serverUrlHash })
      if (strictPort) throw error
    }
  }

  throw new Error(
    `Could not find a free callback port for this server (tried ${candidates[0]}-${candidates[candidates.length - 1]}). ` +
      `Close whatever is holding those ports, or pass a port as the second argument to choose one.`,
  )
}

/**
 * The earliest candidate before `port` that a sibling has taken, if any.
 *
 * Deliberately one-directional. Binding only arbitrates between instances contending for the same
 * port, so instances pushed past a squatted one can each think they won; yielding to the lowest
 * bound candidate is a rule they can all evaluate identically. Yielding in both directions has no
 * tie-break - two instances would each stand down for the other.
 */
async function firstSiblingBefore(candidates: number[], port: number, serverUrlHash: string): Promise<number | undefined> {
  for (const candidate of candidates) {
    if (candidate === port) return undefined
    if (await portHeldBySiblingFor(candidate, serverUrlHash)) return candidate
  }
  return undefined
}

/**
 * Waits for the instance that owns the flow, and takes over if it dies.
 *
 * The two exits need no timers or liveness checks of their own: tokens appearing means the owner
 * finished, and the port becoming bindable means the owner is gone and we are now the owner.
 */
async function followUntilTokensOrPort(
  serverUrlHash: string,
  callbackPath: string,
  port: number,
  events: EventEmitter,
  authTimeoutMs: number,
  followerPatienceMs: number,
): Promise<{ server: Server; actualPort: number; waitForAuthCode: () => Promise<AuthCodeResult>; skipBrowserAuth: boolean }> {
  // The person at the browser may be going through SSO, MFA or a password manager, so this is
  // deliberately longer than the handoff window - and running out is no longer fatal.
  const deadline = Date.now() + Math.max(authTimeoutMs, followerPatienceMs)

  while (Date.now() < deadline) {
    if (await hasUsableTokens(serverUrlHash)) {
      log('The sign-in was completed by another instance; using the tokens it wrote')
      // This instance never serves callbacks, so it reports the port it would have used rather
      // than a throwaway one - a port that looks changed makes callers re-register the client.
      return unownedFlow(port)
    }

    try {
      const { server, actualPort, waitForAuthCode } = await setupOAuthCallbackServerWithLongPoll({
        port,
        path: callbackPath,
        events,
        authTimeoutMs,
        serverUrlHash,
      })
      // The port came free, so the instance that had it is gone. Whatever tab it opened points
      // here, so its sign-in can still complete against this process.
      log(`The instance running the sign-in exited; taking it over on port ${actualPort}`)
      return { server, actualPort, waitForAuthCode, skipBrowserAuth: false }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EADDRINUSE') throw error
    }

    await new Promise((resolve) => setTimeout(resolve, FOLLOWER_POLL_INTERVAL_MS))
  }

  // Whatever we were waiting for is not coming. Connecting unaided may still work - the server
  // may not need OAuth at all, or may challenge us and let the 401 handler run - and it is always
  // better than exiting, which is what a wrong guess used to cost.
  log(`Gave up waiting for another instance on port ${port}; continuing without owning the sign-in`)
  return unownedFlow(port)
}

/**
 * A result for an instance that owns no callback server and will not run a browser flow.
 *
 * `waitForAuthCode` rejects rather than hanging, so a caller that reaches for a code it was never
 * going to receive fails immediately and visibly instead of waiting out the host's patience.
 */
function unownedFlow(port: number): {
  server: Server
  actualPort: number
  waitForAuthCode: () => Promise<AuthCodeResult>
  skipBrowserAuth: boolean
} {
  return {
    server: express()
      .listen(0, '127.0.0.1')
      .on('error', () => {}),
    actualPort: port,
    waitForAuthCode: () => Promise.reject(new Error('This instance does not own the sign-in; it cannot receive an authorization code')),
    skipBrowserAuth: true,
  }
}
