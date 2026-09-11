import { OAuthClientInformationFullSchema } from '@modelcontextprotocol/core'
import {
  Client,
  OAuthClientProvider,
  OAuthError,
  SdkErrorCode,
  SdkHttpError,
  SSEClientTransport,
  StreamableHTTPClientTransport,
  UnauthorizedError,
} from '@modelcontextprotocol/client'
import type { FetchLike, OAuthClientInformationFull, Transport } from '@modelcontextprotocol/client'
import {
  canFulfilInputRequest,
  discoverRequest,
  inputRequiredRetryParams,
  isDroppedInModernEra,
  isInputRequiredResult,
  isModernOnlyNotification,
  clientDeclaredCapabilityFor,
  MAX_INPUT_REQUESTS_PER_ROUND,
  RETIRED_IN_MODERN_ERA,
  stampLogLevel,
  unacknowledgedSubscriptions,
  localAnswerFor,
  MAX_INPUT_REQUIRED_ROUNDS,
  readEraFromDiscoverResponse,
  stampModernMeta,
  stripSubscriptionMeta,
  subscriptionFilterFor,
  subscriptionsListenRequest,
  synthesizeInitializeResult,
  translateModernResult,
  type EraVerdict,
  type LegacyClientIdentity,
  type ProtocolMode,
} from './protocol-era'
import {
  AuthCodeResult,
  KeepAliveConfig,
  OAuthCallbackServerOptions,
  StaticOAuthClientInformationFull,
  StaticOAuthClientMetadata,
} from './types'
import { getConfigDir, getConfigFilePath, readJsonFile } from './mcp-auth-config'
import {
  discoverProtectedResourceMetadata,
  parseWWWAuthenticateHeader,
  getAuthorizationServerUrl,
  type ProtectedResourceMetadata,
} from './protected-resource-metadata'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import { createCookieJar } from './cookie-jar'
import express from 'express'
import { AddressInfo } from 'net'
import { Server } from 'http'
import crypto from 'crypto'
import fs from 'fs'
import { readFile, rm } from 'fs/promises'
import path from 'path'
import { version as MCP_REMOTE_VERSION } from '../../package.json'
import { Agent, EnvHttpProxyAgent, fetch, Headers, RequestInit, setGlobalDispatcher } from 'undici'

// Global type declaration for typescript
declare global {
  var currentServerUrlHash: string | undefined
}

// Connection constants
const REASON_AUTH_NEEDED = 'authentication-needed'
/**
 * Reconnecting on tokens a sibling instance signed in for.
 *
 * Held apart from {@link REASON_AUTH_NEEDED} because it is a different event with a different
 * remedy: a handover costs no browser tab and no authorization code, and spending the sign-in's one
 * allowance on it left an instance with nothing to try when the handed-over tokens were refused -
 * so it died while the instance that wrote them went on serving (issue #352).
 */
const REASON_SIBLING_TOKENS = 'signed-in-by-another-instance'
const REASON_TRANSPORT_FALLBACK = 'falling-back-to-alternate-transport'
const REASON_REJECTED_TOKEN = 'server-rejected-a-freshly-issued-token'
const DEFAULT_KEEP_ALIVE_INTERVAL_MS = 30_000

/**
 * Which JSON-RPC methods carry an `Mcp-Name`, and where its value comes from.
 *
 * SEP-2243 sources the header from `params.name` for tools and prompts, and from
 * `params.uri` for resources.
 */
const MCP_NAME_SOURCES: Record<string, 'name' | 'uri'> = {
  'tools/call': 'name',
  'prompts/get': 'name',
  'resources/read': 'uri',
}

type MirroredMcpHeaders = { method: string; name?: string }

/**
 * Read the standard MCP request headers out of a JSON-RPC body.
 *
 * A batch body is deliberately skipped: it has no single method to mirror, and
 * mirroring one of several is worse than sending nothing.
 */
function mcpHeadersFromBody(body: RequestInit['body']): MirroredMcpHeaders | undefined {
  if (typeof body !== 'string') return undefined

  let message: unknown
  try {
    message = JSON.parse(body)
  } catch {
    return undefined
  }

  if (!message || typeof message !== 'object' || Array.isArray(message)) return undefined

  const { method, params } = message as { method?: unknown; params?: unknown }
  if (typeof method !== 'string' || method.length === 0) return undefined

  const source = MCP_NAME_SOURCES[method]
  if (!source || !params || typeof params !== 'object') return { method }

  const name = (params as Record<string, unknown>)[source]
  return typeof name === 'string' && name.length > 0 ? { method, name } : { method }
}

/**
 * Encode a header value per the SEP-2243 value rules.
 *
 * RFC 9110 field values are visible ASCII plus space and tab, with no leading or
 * trailing whitespace. Anything outside that - and any literal that would itself
 * be mistaken for the sentinel - travels Base64.
 */
export function encodeMcpHeaderValue(value: string): string {
  const headerSafe = /^[\x21-\x7e](?:[\x20-\x7e\t]*[\x21-\x7e])?$/.test(value)
  const looksEncoded = value.startsWith('=?base64?') && value.endsWith('?=')

  return headerSafe && !looksEncoded ? value : `=?base64?${Buffer.from(value, 'utf8').toString('base64')}?=`
}

/**
 * Mirror the JSON-RPC method and target into the standard MCP request headers.
 *
 * SEP-2243 (spec revision 2026-07-28) requires `Mcp-Method` on every request and
 * `Mcp-Name` on `tools/call`, `resources/read` and `prompts/get`, so that gateways
 * can route and meter without parsing the body. The SDK sends neither, which is
 * what strands mcp-remote behind a method-aware gateway (#306).
 *
 * Both are derived from the exact body being sent, never from anything else: a
 * server that enforces the rule rejects a header that disagrees with the body -
 * or a required one that is missing - with `-32020 HeaderMismatch`. That is also
 * why `Mcp-Method` is never sent alone for a method that requires `Mcp-Name`;
 * a partial set is itself a mismatch.
 *
 * Caller-supplied headers win, so an explicit `--header` still overrides.
 *
 * The cast bridges types only: this module is undici-typed throughout (see the
 * import above) while `FetchLike` is declared against the global DOM types. They
 * are the same implementation at runtime on the Node versions we support.
 */
export const fetchWithMcpHeaders = (async (url: string | URL, init?: RequestInit) => {
  const mirrored = mcpHeadersFromBody(init?.body)
  const cookie = cookieHeaderFor(url)

  let request = init
  if (mirrored || cookie) {
    const headers = new Headers(init?.headers)
    if (mirrored) {
      if (!headers.has('Mcp-Method')) headers.set('Mcp-Method', mirrored.method)
      if (mirrored.name !== undefined && !headers.has('Mcp-Name')) {
        headers.set('Mcp-Name', encodeMcpHeaderValue(mirrored.name))
      }
    }
    if (cookie && !headers.has('Cookie')) headers.set('Cookie', cookie)
    request = { ...init, headers }
  }

  const response = await fetch(url, request)
  captureCookies(url, response)
  return response.ok ? response : asGlobalResponse(response)
}) as unknown as FetchLike

/** Statuses the `Response` constructor refuses a body for, per the fetch spec's null body statuses. */
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304])

/**
 * Rebuilds a response using the *global* `Response` class.
 *
 * The SDK renders OAuth failures through `parseErrorResponse`, which reads the body only when
 * `input instanceof Response` holds against the global class. We hand the SDK undici's `fetch`
 * (see the import above) and this package bundles its own undici, so the responses it gets back
 * are a *different* `Response` class and that check never matches. Every OAuth error body was
 * therefore stringified into the literal `[object Response]`, hiding the server's real
 * `invalid_grant` or `invalid_client` behind noise (see issue #353). It is the same class-identity
 * trap that once dropped every SDK-set header - see `mergeHeaders` below, and issue #157.
 *
 * Switching wholesale to the global `fetch` would be the worse fix: the bundled undici registers
 * its dispatcher under `Symbol(undici.globalDispatcher.2)` while the global `fetch` reads `.1`, so
 * `--connect-timeout`, `--body-timeout`, `--headers-timeout` and `--ipv4` would all quietly stop
 * applying.
 *
 * Only failed responses are rebuilt. Successful ones carry the SSE stream the whole proxy runs on,
 * and nothing reads an error body off those.
 */
function asGlobalResponse(response: Awaited<ReturnType<typeof fetch>>) {
  const body = NULL_BODY_STATUSES.has(response.status) ? null : (response.body as ReadableStream | null)
  const rebuilt = new globalThis.Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: [...response.headers] as [string, string][],
  })
  // `url` is a prototype getter the constructor cannot set, and it is worth keeping: it is what
  // names the endpoint that failed in a debug log.
  Object.defineProperty(rebuilt, 'url', { value: response.url })
  return rebuilt
}

/**
 * The cookies the remote server has set on this process, if it has set any.
 *
 * Held at module scope rather than per connection so that stickiness survives a reconnect: the
 * node a balancer chose for us is still the node holding the session after the transport falls
 * back, re-authorizes, or the stream comes back. Keyed by origin, so nothing crosses between
 * servers.
 */
const cookieJar = createCookieJar()

/** Whether to take part in cookie-based session stickiness at all. See `--disable-cookies`. */
let COOKIES_ENABLED = true

/**
 * Whether a sign-in happens through the device grant rather than a browser on this machine.
 *
 * Global for the same reason the debug and dispatcher settings are: `connectToRemoteServer` calls
 * itself to retry, and threading a flag through that recursion buys nothing over reading the one
 * decision the command line already made.
 */
let NON_INTERACTIVE_FLOW = false

function cookieHeaderFor(url: string | URL): string | undefined {
  return COOKIES_ENABLED ? cookieJar.header(url) : undefined
}

function captureCookies(url: string | URL, response: { headers: { getSetCookie?: () => string[] } }): void {
  if (COOKIES_ENABLED) cookieJar.capture(url, response)
}

/**
 * A transport whose stream can come back on a server-side session that is not the one it left on.
 *
 * The SSE transport opens the stream and POSTs separately, and a server issues a fresh session for
 * each stream it serves. So when the stream drops and the EventSource reconnects - a restart, a
 * container recreate, a network blip - the POST endpoint moves to a session that has never seen an
 * `initialize`, and every request against it is refused (see issue #269). `connectToRemoteServer`
 * raises this; `mcpProxy` answers it by handshaking again.
 */
type StreamReconnectAware = Transport & { onStreamReconnect?: () => void }

/** How long to wait for the reconnected stream to say where its POSTs now go. */
const RECONNECT_ENDPOINT_TIMEOUT_MS = 10_000

/** How often to look, while waiting for it. */
const RECONNECT_ENDPOINT_POLL_MS = 25

/**
 * Whether the server refused a token the SDK had only just obtained.
 *
 * The SDK retries a 401 once by authorizing, and if the fresh token is refused too it gives up so
 * a server that accepts nothing cannot spin the flow forever. What it does not do is clear the
 * token it was refused - so the same dead credential is read back from disk on the next run, and
 * the next, and the connection fails the same way every time with nothing to explain it.
 *
 * This is deliberately narrow, and the SDK draws the line for us: an ordinary challenge - one it
 * has not already tried to authorize past - arrives as `UnauthorizedError`, and only the retry
 * that failed again is an `SdkHttpError`. So the type and the code decide it, with no dependence
 * on the wording of a message (v1 was matched on exactly that, and v2 rephrased it).
 */
function isRejectedAfterAuthorizing(error: unknown): boolean {
  return error instanceof SdkHttpError && error.code === SdkErrorCode.ClientHttpAuthentication && error.status === 401
}

/**
 * Discards the refused token, so the next attempt finds none and runs a full sign-in through the
 * ordinary path rather than anything special-cased here.
 *
 * Nothing has to be reset on the transport: the SDK scopes its "already tried authorizing" flag to
 * a single send rather than to the transport, so a later request starts willing to authorize again
 * on its own.
 */
export async function forgetRejectedAuthorization(authProvider: OAuthClientProvider): Promise<void> {
  try {
    await authProvider.invalidateCredentials?.('tokens')
  } catch (error) {
    debugLog('Could not discard the refused token', error)
  }
}

// Transport strategy types
export type TransportStrategy = 'sse-only' | 'http-only' | 'sse-first' | 'http-first'
export { MCP_REMOTE_VERSION }

const pid = process.pid
// Global debug flag
let DEBUG = false
let SILENT = false

// Helper function for timestamp formatting
function getTimestamp(): string {
  const now = new Date()
  return now.toISOString()
}

// Debug logging function
export function debugLog(message: string, ...args: any[]) {
  if (!DEBUG) return

  const serverUrlHash = global.currentServerUrlHash
  if (!serverUrlHash) {
    console.error('[DEBUG LOG ERROR] global.currentServerUrlHash is not set. Cannot write debug log.')
    return
  }

  try {
    // Format with timestamp and PID
    const formattedMessage = `[${getTimestamp()}][${pid}] ${message}`

    // Log to console
    console.error(formattedMessage, ...args)

    // Ensure config directory exists
    const configDir = getConfigDir()
    fs.mkdirSync(configDir, { recursive: true, mode: 0o700 })

    // Append to log file
    const logPath = path.join(configDir, `${serverUrlHash}_debug.log`)
    const logMessage = `${formattedMessage} ${args.map((arg) => (typeof arg === 'object' ? JSON.stringify(arg) : String(arg))).join(' ')}\n`

    // Same 0600 the token store uses. What lands here is whatever a debug line was given, and some
    // of those carry a whole token response - so the copy in the log has to be as private as the
    // copy in `tokens.json`, not world-readable beside it.
    fs.appendFileSync(logPath, logMessage, { encoding: 'utf8', mode: 0o600 })
  } catch (error) {
    // Fallback to console if file logging fails
    console.error(`[DEBUG LOG ERROR] ${error}`)
  }
}

export function log(str: string, ...rest: unknown[]) {
  if (!SILENT) {
    // Using stderr so that it doesn't interfere with stdout
    console.error(`[${pid}] ${str}`, ...rest)
  }

  // If debug mode is on, also log to debug file
  debugLog(str, ...rest)
}

type Message = any
const MESSAGE_BLOCKED = Symbol('MessageBlocked')

/** How long the client's first requests wait on `notifications/initialized` before going anyway. */
const LIFECYCLE_BARRIER_TIMEOUT_MS = 10_000

/**
 * How long to wait for the remote server to answer the client's `initialize` before giving up.
 *
 * A streaming response can open successfully and then never deliver the message it promised -
 * `send()` resolves once the response starts, not once it answers, because the SDK reads the SSE
 * body unawaited. Nothing above notices that on its own, so without this a server that opens the
 * stream and never writes to it leaves the client waiting forever with no error on either side (see
 * https://github.com/punkpeye/mcp-remote/issues/354).
 *
 * Scoped to `initialize` only: it is the one request never expected to run long, so it is the one
 * request safe to bound without risking a slow `tools/call` that is still legitimately in progress.
 */
const INITIALIZE_TIMEOUT_MS = 30_000

/**
 * How long to wait for `server/discover` before deciding no modern server is listening.
 *
 * Shorter than the handshake's own budget on purpose: this runs before the client has been told
 * anything, and every millisecond spent here is added to a startup that used to have none.
 */
const DISCOVER_TIMEOUT_MS = 10_000

/**
 * How long a `subscriptions/listen` stream is allowed to stay open.
 *
 * It is not a request timeout: the request *is* the stream, and it resolves only when the stream
 * ends. This is the outer bound on a session's worth of change notifications.
 */
const SUBSCRIPTION_LIFETIME_MS = 24 * 60 * 60 * 1000

/**
 * The backstop on one leg of a multi-round-trip exchange.
 *
 * Deliberately generous, and deliberately not {@link INITIALIZE_TIMEOUT_MS}: the legs here are a
 * sampling call the client answers by asking a model, an elicitation a person has to read, and a
 * retried tool call that can legitimately run for as long as any other. None of those is the one
 * request "never expected to run long" that the initialize budget was written for.
 *
 * The client's own SDK times its handlers out and answers with an error, so this only matters for a
 * peer that has stopped answering altogether - which is what it is here to stop holding a request
 * open forever.
 */
const MULTI_ROUND_TRIP_LEG_TIMEOUT_MS = 10 * 60 * 1000

/** How long to wait before reopening a change-notification stream that ended. */
const SUBSCRIPTION_REOPEN_DELAY_MS = 2_000

/** How many times a change-notification stream may end without ever staying open before this stops. */
const SUBSCRIPTION_REOPEN_LIMIT = 5

/**
 * How long a stream has to stay open to count as having worked.
 *
 * Below this it did not really open, whatever it answered, and reopening it on a timer would turn
 * one polite answer into a request every couple of seconds for the life of the process.
 */
const SUBSCRIPTION_HELD_OPEN_MS = 30_000

/** A timer that never keeps the process alive on its own. */
const sleep = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms).unref?.()
  })

const isMessageBlocked = (value: any): value is typeof MESSAGE_BLOCKED => value === MESSAGE_BLOCKED

function createMessageTransformer({
  transformRequestFunction,
  transformResponseFunction,
}: {
  transformRequestFunction?: null | ((request: Message) => Message | typeof MESSAGE_BLOCKED)
  transformResponseFunction?: null | ((request: Message, response: Message) => Message)
} = {}) {
  const pendingRequests = new Map<string | number, Message>()

  /**
   * A request is the only thing worth remembering, and the only thing worth pairing a response to.
   *
   * Both directions carry messages with an `id` that are *not* requests - a response the client
   * sends back to a server-initiated call, for one - and the two directions number their requests
   * independently, so recording those would let one side's id collide with the other's and pair a
   * response with a message that never asked for it.
   */
  const isRequest = (message: Message) => message?.id != null && message.method !== undefined
  const isResponse = (message: Message) => message?.id != null && message.method === undefined

  /**
   * Runs a transform, falling back to the untouched message if it throws.
   *
   * A transform is a convenience; delivery is not. Letting one throw here would abort the
   * `onmessage` handler that was about to forward the message, so a client would be left waiting
   * on a request that was in fact answered (see https://github.com/geelen/mcp-remote/issues/310).
   */
  const applyTransform = (transform: () => Message, message: Message) => {
    try {
      return transform()
    } catch (error) {
      log('Error transforming message, forwarding it unchanged:', error)
      debugLog('Message transform failed', { id: message?.id, method: message?.method, error })
      return message
    }
  }

  const interceptRequest = (message: Message) => {
    if (!isRequest(message)) return message
    pendingRequests.set(message.id, message)
    if (!transformRequestFunction) return message
    return applyTransform(() => transformRequestFunction(message) ?? message, message)
  }

  const interceptResponse = (message: Message) => {
    if (!isResponse(message)) return message
    const originalRequest = pendingRequests.get(message.id)
    if (!originalRequest) return message
    pendingRequests.delete(message.id)
    if (!transformResponseFunction) return message
    return applyTransform(() => transformResponseFunction(originalRequest, message) ?? message, message)
  }

  /**
   * Releases the request held against `id`, for an answer that never came back through here.
   *
   * Several answers are produced by the proxy itself - a locally answered method, a blocked tool
   * call, a request a dropped session failed - and none of them pass through
   * {@link interceptResponse}, so without this the request stays held for the life of the process.
   *
   * `only` guards against freeing the wrong one: an id is the client's to reuse, so by the time a
   * stale exchange gets here the entry may belong to the request that replaced it. Releasing that
   * would leave the new answer with nothing to pair against, and it would reach the client
   * untransformed - with, for instance, the tools `--ignore-tool` was meant to hide.
   *
   * @param id The request id to release
   * @param only Release only if this is the request being held
   */
  const release = (id: string | number, only?: Message) => {
    if (only !== undefined && pendingRequests.get(id) !== only) return
    pendingRequests.delete(id)
  }

  return {
    interceptRequest,
    interceptResponse,
    release,
  }
}

/**
 * Creates a bidirectional proxy between two transports
 * @param params The transport connections to proxy between
 */
export function mcpProxy({
  transportToClient,
  transportToServer,
  ignoredTools = [],
  keepAlive,
  protocolMode = 'legacy',
  reauthorize,
  forgetRejectedAuthorization: forgetRejectedTokens,
}: {
  transportToClient: Transport
  transportToServer: Transport
  ignoredTools?: string[]
  /** Pings the server on an interval, so a connection carrying no traffic is not reaped */
  keepAlive?: KeepAliveConfig
  /**
   * Whether to look for a `2026-07-28` server before handing it a handshake it no longer answers.
   *
   * `legacy` forwards the client's `initialize` untouched, as every release before this one did.
   * `auto` spends one `server/discover` on the first handshake and bridges the eras if it finds a
   * modern server. See {@link ./protocol-era.ts}.
   */
  protocolMode?: ProtocolMode
  /**
   * Completes a sign-in for a request the server refused, or undefined to answer with the error.
   *
   * Supplied by the caller rather than built here, because finishing a flow needs the auth
   * provider and the callback server, neither of which a proxy between two transports should know
   * about.
   */
  reauthorize?: () => Promise<void>
  /**
   * Discards a token the server refused after the SDK had just obtained it.
   *
   * Supplied by the caller for the same reason `reauthorize` is: clearing it needs the auth
   * provider and the transport's own state, neither of which a proxy between two transports has.
   */
  forgetRejectedAuthorization?: () => Promise<void>
}) {
  let transportToClientClosed = false
  let transportToServerClosed = false
  let initializeRequestId: string | number | undefined
  let lastInitialize: Message | null = null
  let reinitSeq = 0
  const pendingReinit = new Map<string, (message: Message) => void>()
  const pendingPings = new Set<string>()
  let pingSeq = 0
  let keepAliveTimer: NodeJS.Timeout | null = null
  let initializedDelivered: Promise<unknown> | null = null
  /** Set once the probe has run. Until then nothing is known about which era the server belongs to. */
  let era: EraVerdict | null = null
  /** What the client said in its `initialize`, replayed into the `_meta` of every modern request. */
  let clientIdentity: LegacyClientIdentity = {}
  /** In-flight `server/discover` probe. Everything the client sends queues behind it. */
  let eraNegotiation: Promise<void> | null = null
  /** Resources the client subscribed to, which the modern era carries on the listen stream instead. */
  const subscribedResources = new Set<string>()
  /** The minimum log level the client asked for, which the modern era carries per request instead. */
  let requestedLogLevel: string | undefined
  /** Reopens the change-notification stream against a filter that has changed. */
  let refreshSubscription: (() => void) | undefined
  /** The stream currently open, if any, so a filter change can end it rather than leave it running. */
  let activeStream: { reopen: () => void } | undefined
  /** Wakes a loop that is idling because there is nothing to listen for yet. */
  let wakeIdleWait: (() => void) | undefined
  /**
   * Whether to leave resource subscriptions out of the filter.
   *
   * Set when a server refuses a filter that named them, so the rest of the subscription survives -
   * and cleared again the next time the client changes what it wants, because the refusal was about
   * the resources it named then, not about every resource it will ever name.
   */
  let dropResourceSubscriptions = false
  /** The remote-side id a client request is currently being retried under, for cancellation. */
  const modernRetryIds = new Map<string | number, string>()
  /**
   * The multi-round-trip exchange currently answering for each client request id, by token.
   *
   * A token rather than a flag, because a request id is the client's to reuse: an exchange stranded
   * by a dropped session can still be running under an id the client has since sent again, and
   * without something to tell the two apart the stale one answers the new request - or the new one
   * is mistaken for the stale one and dropped, leaving the client with nothing.
   *
   * An entry exists only while an exchange is live. Every path that answers the client removes it,
   * so a stale exchange finds its token gone and stays quiet.
   */
  const liveExchanges = new Map<string | number, number>()
  let exchangeSeq = 0
  let discoverSeq = 0
  const pendingDiscover = new Map<string, (message: Message) => void>()
  /**
   * The prefix every id this proxy mints carries.
   *
   * Checked before any of the maps below are consulted, so a client that happens to use the same
   * string as one of our ids cannot have its request swallowed or its answer stolen - and a late
   * answer to a question we have already given up on is dropped rather than forwarded to a server
   * that never asked it.
   */
  const OWN_ID_PREFIX = 'mcp-remote-'
  const isOwnId = (id: unknown): id is string => typeof id === 'string' && id.startsWith(OWN_ID_PREFIX)

  /** Requests this proxy issued to the remote on its own account, keyed by the id it minted. */
  const pendingOwnRequests = new Map<string, (message: Message) => void>()
  /** Requests this proxy put to the local client on the remote's behalf, awaiting its answer. */
  const pendingClientRequests = new Map<string, (message: Message) => void>()
  let ownRequestSeq = 0
  /**
   * Client requests still in flight against the remote, kept so a multi-round-trip exchange can be
   * retried with the same params the client sent.
   */
  const modernOriginals = new Map<string | number, Message>()
  let reauthorizeInFlight: Promise<void> | null = null
  /** In-flight recovery from a reconnected stream. See `onStreamReconnect` below. */
  let sessionResumption: Promise<void> | null = null
  /**
   * Client requests that have gone to the server and are still waiting on an answer.
   *
   * Recorded at the point of sending rather than of receiving, so a request still queued behind a
   * reconnect is not counted as one the vanished session owes an answer for.
   */
  const pendingRequests = new Set<string | number>()

  const messageTransformer = createMessageTransformer({
    transformRequestFunction: (request: Message) => {
      // Block tools/call for ignored tools
      if (request.method === 'tools/call' && request.params?.name) {
        const toolName = request.params.name
        if (!shouldIncludeTool(ignoredTools, toolName)) {
          // Send error response back to client immediately
          const errorResponse = {
            jsonrpc: '2.0' as const,
            id: request.id,
            error: {
              code: -32603,
              message: `Tool "${toolName}" is not available`,
            },
          }
          transportToClient.send(errorResponse).catch(onClientError)
          // Return symbol to indicate this request should not be forwarded
          return MESSAGE_BLOCKED
        }
      }
      return request
    },
    transformResponseFunction: (req: Message, response: Message) => {
      let res = response

      // A modern result is tagged with a `resultType` a 2025-era client has never heard of, and one
      // of those tags - `input_required` - is a question this client has no way to answer
      if (era?.era === 'modern' && res.result !== undefined) {
        const translated = translateModernResult(res.result)
        if ('error' in translated) return { jsonrpc: '2.0' as const, id: res.id, error: translated.error }
        res = { ...res, result: translated.result }
      }

      if (req.method !== 'tools/list') return res
      // Not every answer to tools/list carries a tool list: a JSON-RPC error response has no
      // `result` at all, and a server may answer with one that omits `tools`. Filtering either
      // used to throw, and the throw took the forward down with it, so the client was left with
      // no answer rather than the error the server actually sent (see issues #164 and #310).
      const tools = res.result?.tools
      if (!Array.isArray(tools)) return res
      return {
        ...res,
        result: {
          ...res.result,
          tools: tools.filter((tool: any) => shouldIncludeTool(ignoredTools, tool.name)),
        },
      }
    },
  })

  transportToClient.onmessage = (_message) => {
    const answeringId = (_message as any).id

    // The client answering a question this proxy put to it on the remote's behalf. Everything
    // carrying one of our ids is ours, including an answer that arrives after we stopped waiting -
    // forwarding that on would hand the server a response to a request it never made.
    if (isOwnId(answeringId)) {
      // A *request* from the client in this namespace would collide with one of ours, so it is
      // refused rather than forwarded - the alternative is the client's answer being consumed here
      // and the client waiting for one that never comes.
      if ((_message as any).method !== undefined) {
        log(`Refusing a client request whose id is reserved by this proxy: ${answeringId}`)
        transportToClient
          .send({
            jsonrpc: '2.0',
            id: answeringId,
            error: { code: -32600, message: `mcp-remote reserves request ids beginning with "${OWN_ID_PREFIX}"` },
          } as Message)
          .catch(onClientError)
        return
      }

      const settle = pendingClientRequests.get(answeringId)
      pendingClientRequests.delete(answeringId)
      if (settle) settle(_message as any)
      else debugLog('Discarding a late answer to a question this proxy had given up on', { id: answeringId })
      return
    }

    // TODO: fix types
    const message = messageTransformer.interceptRequest(_message as any)

    // If interceptor returns MESSAGE_BLOCKED, don't forward the message
    if (isMessageBlocked(message)) {
      // Answered without ever reaching the server, so nothing will pair a response with it and
      // release the hold the transformer took on the way in
      const blockedId = (_message as any).id
      if (blockedId !== undefined && blockedId !== null) messageTransformer.release(blockedId)
      return
    }

    log('[Local→Remote]', message.method || message.id)

    debugLog('Local → Remote message', {
      method: message.method,
      id: message.id,
      params: message.params ? JSON.stringify(message.params).substring(0, 500) : undefined,
    })

    if (message.method === 'initialize') {
      initializeRequestId = message.id
      const { clientInfo } = message.params
      if (clientInfo) clientInfo.name = `${clientInfo.name} (via mcp-remote ${MCP_REMOTE_VERSION})`
      log(JSON.stringify(message, null, 2))

      debugLog('Initialize message with modified client info', { clientInfo })

      lastInitialize = message
      clientIdentity = {
        protocolVersion: message.params?.protocolVersion,
        capabilities: message.params?.capabilities ?? {},
        clientInfo,
      }

      // The handshake is the only moment the era can be settled: it is the first thing the client
      // sends, and how every message after it has to be written depends on the answer.
      // `era === null` alone is not enough: it stays null for the whole probe, so a client that
      // re-sends `initialize` before the probe answers - one whose own handshake timeout is shorter
      // than ours - would start a second negotiation, a second synthesized handshake, and a second
      // subscription stream.
      if (protocolMode === 'auto' && era === null && !eraNegotiation) {
        const negotiation = negotiateEra(message).finally(() => {
          // Only the negotiation that owns the gate may open it
          if (eraNegotiation === negotiation) eraNegotiation = null
        })
        eraNegotiation = negotiation
        return
      }
    }

    forwardInOrder(message)
  }

  transportToServer.onmessage = (_message) => {
    const incomingId = (_message as any).id

    // Answers to the requests this proxy made on its own account are ours to consume: the keep-alive
    // pings, the era probe, the subscription, each leg of a multi-round-trip retry, and the
    // re-initialize handshake. The client never sent any of them, so forwarding one would hand it an
    // id it has nothing to match against.
    //
    // Only what is still outstanding is claimed. An id we have already settled belongs to whoever
    // sent it next, and client ids are kept out of this namespace on the way past instead.
    // A server *request* in this proxy's id namespace would collide with one of ours: forwarding it
    // leaves the client's answer to be consumed here as if it were ours, and the server waiting
    // forever. Refused at the boundary instead, the way a client request in it is.
    if (isOwnId(incomingId) && (_message as any).method !== undefined) {
      log(`Refusing a server request whose id is reserved by this proxy: ${incomingId}`)
      transportToServer
        .send({
          jsonrpc: '2.0',
          id: incomingId,
          error: { code: -32600, message: `mcp-remote reserves request ids beginning with "${OWN_ID_PREFIX}"` },
        } as Message)
        .catch(onServerError)
      return
    }

    if (isOwnId(incomingId)) {
      if (pendingPings.delete(incomingId)) return

      for (const pending of [pendingOwnRequests, pendingDiscover, pendingReinit]) {
        const settle = pending.get(incomingId)
        if (settle) {
          pending.delete(incomingId)
          settle(_message as any)
          return
        }
      }

      // Nothing is waiting on it: a duplicate, or the answer to something this proxy cancelled and
      // the server had already begun answering. Forwarding it would hand the client an id it never
      // used - and since client requests are kept out of this namespace, it cannot be the client's.
      debugLog('Discarding an answer to a request this proxy is no longer waiting on', { id: incomingId })
      return
    }

    // Confirmation of a stream this proxy opened for the client, which the client never asked for
    if (era?.era === 'modern' && (_message as any).method && isModernOnlyNotification((_message as any).method)) {
      const requested = subscriptionFilterFor(era.discover.capabilities, [...subscribedResources])
      const missing = requested ? unacknowledgedSubscriptions(requested, (_message as any).params?.notifications) : []
      if (missing.length > 0) {
        // Otherwise a type the server quietly dropped is one the client waits for forever
        log(`The remote server did not subscribe this client to: ${missing.join(', ')}`)
      }
      debugLog('Consuming a notification that belongs to this proxy, not the client', { method: (_message as any).method })
      return
    }

    // A modern server asking for input rather than answering. The client is left waiting on the
    // request it sent while the questions are put to it separately, and is answered once.
    if (era?.era === 'modern' && incomingId !== undefined && incomingId !== null && isInputRequiredResult((_message as any).result)) {
      const original = modernOriginals.get(incomingId)
      if (!original) {
        // Its request was already answered - by a dropped session, or a cancellation - so there is
        // nothing left to retry and nothing left to answer. Translating it would send the client a
        // second response for an id it has already been given one for.
        debugLog('Discarding a request for more input on an exchange that is already over', { id: incomingId })
        return
      }

      {
        modernOriginals.delete(incomingId)
        // Deliberately left in `pendingRequests`: the exchange is still owed an answer, and a
        // dropped session has to be able to fail it rather than leave the client waiting out the
        // whole leg timeout
        log('[Remote→Local]', `${incomingId} (asking for more input)`)
        const exchange = ++exchangeSeq
        liveExchanges.set(incomingId, exchange)
        driveInputRequired(original, (_message as any).result, era.version, exchange).catch((error: Error) => {
          onServerError(error)
          // Through `answerClient`, so the exchange stops being one a dropped session would fail a
          // second time - `replyWithError` answers but leaves it on the books
          answerClient(
            { jsonrpc: '2.0', id: original.id, error: { code: -32001, message: `mcp-remote: ${error.message}` } } as Message,
            exchange,
            original,
          )
        })
        // The transformer is still holding this request against a response that now arrives from
        // `answerClient` rather than from here

        return
      }
    }

    if (incomingId !== undefined && incomingId !== null) {
      pendingRequests.delete(incomingId)
      modernOriginals.delete(incomingId)
      modernRetryIds.delete(incomingId)
    }

    // TODO: fix types
    const message =
      era?.era === 'modern'
        ? stripSubscriptionMeta(messageTransformer.interceptResponse(_message as any))
        : messageTransformer.interceptResponse(_message as any)
    log('[Remote→Local]', message.method || message.id)

    debugLog('Remote → Local message', {
      method: message.method,
      id: message.id,
      result: message.result ? 'result-present' : undefined,
      error: message.error,
    })

    // A Client normally calls setProtocolVersion() on its transport once the
    // initialize response comes back, so every later request carries the
    // MCP-Protocol-Version header. In proxy mode no Client drives the remote
    // transport, so without this the header is missing and servers that only
    // accept the newest version reject every post-initialize request (see #66).
    if (initializeRequestId !== undefined && message.id === initializeRequestId) {
      initializeRequestId = undefined
      applyNegotiatedProtocolVersion(message)
    }

    transportToClient.send(message).catch(onClientError)
  }

  transportToClient.onclose = () => {
    stopKeepAlive()
    transportToClientClosed = true
    failOwnPendingRequests('the connection closed before this could be answered')
    if (transportToServerClosed) {
      return
    }

    debugLog('Local transport closed, closing remote transport')
    transportToServer.close().catch(onServerError)
  }

  transportToServer.onclose = () => {
    stopKeepAlive()
    transportToServerClosed = true
    failOwnPendingRequests('the connection closed before this could be answered')
    if (transportToClientClosed) {
      return
    }

    debugLog('Remote transport closed, closing local transport')
    transportToClient.close().catch(onClientError)
  }

  transportToClient.onerror = onClientError
  transportToServer.onerror = onServerError

  // The stream coming back is not the session coming back. Nothing below this layer notices:
  // the EventSource reconnects, the endpoint moves to a session the server has just created,
  // and requests keep going out against a lifecycle that never started.
  ;(transportToServer as StreamReconnectAware).onStreamReconnect = () => {
    const droppedEndpoint = postEndpoint()

    // Whatever was in flight went to a session that no longer exists, and its answer was going to
    // arrive on a stream that no longer exists either. Nothing will ever complete these, so the
    // client is told now rather than waiting on them for the life of the process.
    failPendingRequests('the connection to the remote server dropped before this could be answered')

    // Assigned before anything is awaited. The gap between the stream coming back and the
    // handshake going out is exactly when a client request is most likely to arrive, and one
    // that arrives to find this unset is one sent to the session that has gone away.
    sessionResumption = (async () => {
      try {
        await awaitReconnectedEndpoint(droppedEndpoint)
        await reinitializeSession()
      } catch (error) {
        // Nothing is waiting on the resumption itself - it runs off the reconnect, not off a
        // request - so a failure has to be reported rather than returned. Requests held behind
        // it are released either way, and answer to the server as they find it.
        onServerError(error as Error)
      }
    })().finally(() => {
      sessionResumption = null
    })
  }

  if (keepAlive?.enabled) {
    keepAliveTimer = startKeepAlive(keepAlive.intervalMs)
  }

  function onClientError(error: Error) {
    log('Error from local client:', error)
    debugLog('Error from local client', { stack: error.stack })
  }

  function applyNegotiatedProtocolVersion(response: Message) {
    const protocolVersion = response.result?.protocolVersion
    if (typeof protocolVersion === 'string') {
      debugLog('Setting negotiated protocol version on remote transport', protocolVersion)
      transportToServer.setProtocolVersion?.(protocolVersion)
    }
  }

  function onServerError(error: Error) {
    log('Error from remote server:', error)
    debugLog('Error from remote server', { stack: error.stack })
  }

  /**
   * A 404 to a request that carried a session id means the server dropped the
   * session (idle expiry, restart, eviction). The spec says the client must then
   * start a new session with a fresh InitializeRequest.
   *
   * The session id has to be there: a 404 without one is an ordinary "no such
   * endpoint" from a stateless server or a mistyped URL, and re-initializing
   * would just add a doomed handshake to every failing request.
   */
  function isSessionExpired(error: Error) {
    return error instanceof SdkHttpError && error.status === 404 && transportToServer.sessionId !== undefined
  }

  /**
   * Where the SSE transport is currently POSTing, which is where the session id lives for a
   * transport that has no `sessionId` of its own. The SDK keeps it private and offers no event
   * when it moves, so reading it is the only way to tell the new stream from the old one.
   */
  function postEndpoint(): string | undefined {
    return (transportToServer as unknown as { _endpoint?: URL })._endpoint?.href
  }

  /**
   * Waits for the reconnected stream to advertise where its POSTs now go.
   *
   * The reconnect is announced when the HTTP response arrives, which is before the SDK has read
   * the `endpoint` event off the body. Handshaking at that moment would POST the handshake itself
   * to the session that just went away.
   *
   * Giving up on the wait does not give up on the handshake: a server that reuses the endpoint
   * still discarded the lifecycle, and re-initializing is what repairs that.
   */
  async function awaitReconnectedEndpoint(droppedEndpoint: string | undefined): Promise<void> {
    const deadline = Date.now() + RECONNECT_ENDPOINT_TIMEOUT_MS
    while (postEndpoint() === droppedEndpoint && Date.now() < deadline) {
      await sleep(RECONNECT_ENDPOINT_POLL_MS)
    }
  }

  /**
   * Finds out which era the remote server belongs to, and answers the client's handshake either way.
   *
   * The probe is one `server/discover`, and the spec makes its answer the evidence: a `DiscoverResult`
   * is a modern server, a *recognised modern error* is a modern server that cannot meet us, and
   * anything else at all - `-32601`, a transport failure, silence - is a server still expecting the
   * handshake this client sent. Only the first of those changes what happens next; the rest end with
   * the `initialize` going out exactly as it did before any of this existed.
   *
   * @param initialize The client's handshake, held back until there is something to do with it
   */
  async function negotiateEra(initialize: Message): Promise<void> {
    const id = `mcp-remote-discover-${++discoverSeq}`

    try {
      const response = await new Promise<Message>((resolve, reject) => {
        const timer = setTimeout(() => {
          pendingDiscover.delete(id)
          reject(new Error('timed out waiting for the server/discover response'))
        }, DISCOVER_TIMEOUT_MS)
        timer.unref?.()
        pendingDiscover.set(id, (message) => {
          clearTimeout(timer)
          resolve(message)
        })
        transportToServer.send(discoverRequest(id, clientIdentity)).catch((error) => {
          clearTimeout(timer)
          pendingDiscover.delete(id)
          reject(error)
        })
      })
      era = readEraFromDiscoverResponse(response)
    } catch (error) {
      debugLog('server/discover produced no evidence of a modern server', error)
      era = { era: 'legacy', reason: (error as Error).message }
    }

    if (era.era === 'modern') {
      log(`Remote server speaks MCP ${era.version}; answering the local client's handshake here and bridging every request`)
      debugLog('Bridging to a modern server', { version: era.version, capabilities: era.discover.capabilities })

      // Nothing will answer an `initialize` we never send, and the header has to name the revision
      // the `_meta` of every request will, or the server answers -32020
      initializeRequestId = undefined
      transportToServer.setProtocolVersion?.(era.version)

      transportToClient
        .send({ jsonrpc: '2.0', id: initialize.id, result: synthesizeInitializeResult(era.discover, clientIdentity) })
        .catch(onClientError)

      openChangeSubscription(era.version, era.discover.capabilities).catch(onServerError)
      return
    }

    if (era.era === 'incompatible') {
      // Falling back to `initialize` here would fail too, and hide why it failed
      log(`Cannot bridge to this server: ${era.reason}`)
      transportToClient
        .send({
          jsonrpc: '2.0',
          id: initialize.id,
          error: { code: -32603, message: `mcp-remote cannot bridge to this server: ${era.reason}` },
        })
        .catch(onClientError)
      return
    }

    debugLog('Treating the remote server as legacy', { reason: era.reason })
    void sendToServer(initialize)
  }

  /**
   * Sends a request this proxy is making on its own account, and waits for its answer.
   *
   * The id is minted here and recorded, so the answer is recognised on the way back and consumed
   * rather than forwarded to a client that never asked the question.
   *
   * `cancelled`, if given, gives up on the answer: it clears the timer, releases the record, and
   * tells the server - because a `subscriptions/listen` that is abandoned rather than cancelled
   * stays open and goes on delivering, so a client that resubscribes would see every change once
   * per filter it had ever asked for.
   *
   * @param build Given the minted id, the message to send
   * @param timeoutMs How long to wait before giving up on an answer
   * @param cancelled Rejects to abandon the request
   * @returns The response the remote sent
   */
  async function askRemote(build: (id: string) => Message, timeoutMs: number, cancelled?: Promise<never>): Promise<Message> {
    const id = `mcp-remote-own-${++ownRequestSeq}`

    // Attached before anything is awaited, and unconditionally. A caller hands `cancelled` over
    // already able to reject - so a rejection arriving while this is still waiting below would
    // otherwise have no handler at all, which in Node is not a lost cancellation but a dead
    // process.
    let cancelledBeforeSending = false
    let cancellation: unknown
    let abandon: ((reason: unknown) => void) | undefined
    cancelled?.catch((reason) => {
      // A flag rather than the reason alone: a caller rejecting with `undefined` would otherwise
      // read as "never cancelled", and the request would go out with nothing able to stop it
      cancelledBeforeSending = true
      cancellation = reason
      abandon?.(reason)
    })

    // The same barrier `sendToServer` waits on. Without it a retry leg is POSTed onto the session
    // that just went away, and the client waits out the full leg timeout for an answer that was
    // never going to come.
    if (sessionResumption) {
      await sessionResumption
    }

    // Cancelled before it was ever sent, so there is nothing to tell the server about
    if (cancelledBeforeSending) throw cancellation

    return new Promise<Message>((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingOwnRequests.delete(id)
        reject(new Error('timed out waiting for the remote server to answer'))
      }, timeoutMs)
      timer.unref?.()

      // Everything that ends the wait comes through here, so a cancelled request leaves neither an
      // armed 24-hour timer nor a record of an answer nobody is listening for
      const release = () => {
        clearTimeout(timer)
        pendingOwnRequests.delete(id)
      }

      pendingOwnRequests.set(id, (message) => {
        release()
        resolve(message)
      })

      abandon = (reason) => {
        release()
        transportToServer.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id } }).catch(() => {})
        reject(reason)
      }

      transportToServer.send(build(id)).catch((error) => {
        release()
        reject(error)
      })
    })
  }

  /**
   * Puts a request to the local client on the remote server's behalf, and waits for its answer.
   *
   * Used for the input a modern server embeds in an `input_required` result: a 2025-era client
   * already knows how to answer sampling, elicitation and roots - that era simply had the server
   * ask directly - so the question is passed on unchanged and the answer collected.
   */
  function askClient(method: string, params: unknown, timeoutMs: number): Promise<Message> {
    const id = `mcp-remote-input-${++ownRequestSeq}`

    return new Promise<Message>((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingClientRequests.delete(id)
        reject(new Error(`the local client did not answer ${method}`))
      }, timeoutMs)
      timer.unref?.()

      pendingClientRequests.set(id, (message) => {
        clearTimeout(timer)
        resolve(message)
      })

      transportToClient.send({ jsonrpc: '2.0', id, method, params } as Message).catch((error) => {
        clearTimeout(timer)
        pendingClientRequests.delete(id)
        reject(error)
      })
    })
  }

  /**
   * Opens the change-notification stream a 2025-era client would never open for itself.
   *
   * That era had `notifications/tools/list_changed` and friends simply arrive; the modern era sends
   * them only down a `subscriptions/listen` stream the client asked for. A client that has never
   * heard of subscriptions will not ask, so it would silently stop learning that anything changed -
   * a failure with no error anywhere to explain it. This asks on its behalf, for exactly the
   * notifications the server said it can send.
   *
   * Deliberately not awaited by anything: the request stays open for the life of the stream, and
   * failing to open it costs the client change notifications, not its session.
   */
  async function openChangeSubscription(version: string, capabilities: Record<string, unknown> | undefined) {
    // Installed once, and never reassigned: an earlier version handed this to a helper that
    // overwrote it and never gave it back, so every subscription after the first was dropped on the
    // floor. Both things it has to do - wake an idle wait, end a stream that is now listening for
    // the wrong thing - are dispatched from here.
    refreshSubscription = () => {
      wakeIdleWait?.()
      activeStream?.reopen()
    }

    // A stream is not a session: it ends on a server restart, a load balancer's idle timeout, or a
    // network flake, and the client would go on believing nothing has changed since. Reopening is
    // the only thing that turns that back into a working subscription, because nothing below this
    // notices it stopped.
    // Counts only streams the *server* ended as soon as they opened. A reopen the client asked
    // for is ordinary work and spends none of this budget, or a client that subscribes a few times
    // would exhaust a limit written for a server that will not hold a stream open.
    let shortLivedStreams = 0

    while (shortLivedStreams < SUBSCRIPTION_REOPEN_LIMIT) {
      const notifications = subscriptionFilterFor(capabilities, dropResourceSubscriptions ? [] : [...subscribedResources])

      if (!notifications) {
        // Nothing to listen for yet. A later `resources/subscribe` is what gives this a reason to
        // exist, so this waits for one rather than giving up on the session.
        debugLog('Nothing to subscribe to yet; waiting for the client to ask for something')
        shortLivedStreams = 0
        if (!(await waitForSubscriptionChange())) return
        continue
      }

      const openedAt = Date.now()
      let reopening = false

      try {
        debugLog('Subscribing to change notifications on the client behalf', { notifications })
        // Resolves only when the stream ends, so this bounds a session's worth of notifications
        // rather than a request
        const cancelled = new Promise<never>((_, rejectStream) => {
          activeStream = {
            reopen: () => {
              reopening = true
              // Cancelled rather than abandoned: a stream left open goes on delivering, so the
              // client would see every change once per filter it has ever asked for
              rejectStream(new Error('the subscription is being reopened against a new filter'))
            },
          }
        })

        const response = await askRemote(
          (id: string) => subscriptionsListenRequest(id, clientIdentity, version, notifications) as Message,
          SUBSCRIPTION_LIFETIME_MS,
          cancelled,
        )

        if (response.error) {
          // A transport that has gone answers everything outstanding with an error, and that is not
          // the server refusing anything
          if (transportToClientClosed || transportToServerClosed) return

          if (!dropResourceSubscriptions && subscribedResources.size > 0) {
            // The filter named resources; the rest of it may still be perfectly acceptable
            log(`The remote server refused a subscription naming resources; listening for the rest: ${JSON.stringify(response.error)}`)
            dropResourceSubscriptions = true
            continue
          }

          // A refusal is a decision, not a flake; reopening would only ask again and be told again
          log(`The remote server refused the change-notification subscription: ${JSON.stringify(response.error)}`)
          return
        }

        debugLog('The change-notification stream ended', { heldForMs: Date.now() - openedAt })
      } catch (error) {
        if (reopening) {
          debugLog('Reopening the change-notification stream against a filter the client changed')
          if (transportToClientClosed || transportToServerClosed) return
          // Debounced, so a client that subscribes in a tight loop cannot turn each call into an
          // immediate round trip
          await sleep(SUBSCRIPTION_REOPEN_DELAY_MS)
          if (transportToClientClosed || transportToServerClosed) return
          continue
        }
        debugLog('The change-notification stream failed', { heldForMs: Date.now() - openedAt, error })
      } finally {
        activeStream = undefined
      }

      // A stream that stayed open did its job, so reopening it is ordinary maintenance and the
      // budget starts again. One that ended immediately is a server that does not really hold this
      // open, and reopening it on a timer is how a proxy comes to send thousands of requests an
      // hour to a server that answered the first one perfectly politely.
      if (Date.now() - openedAt >= SUBSCRIPTION_HELD_OPEN_MS) shortLivedStreams = 0
      else shortLivedStreams++

      if (transportToClientClosed || transportToServerClosed) return

      await sleep(SUBSCRIPTION_REOPEN_DELAY_MS)
      if (transportToClientClosed || transportToServerClosed) return
    }

    log('Giving up on change notifications: the subscription stream kept ending as soon as it opened')
  }

  /**
   * Waits until the client changes what it wants listened to, or the connection goes.
   *
   * @returns Whether there is still a connection worth reopening a stream on
   */
  function waitForSubscriptionChange(): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const timer = setInterval(() => {
        if (transportToClientClosed || transportToServerClosed) {
          clearInterval(timer)
          wakeIdleWait = undefined
          resolve(false)
        }
      }, SUBSCRIPTION_REOPEN_DELAY_MS)
      timer.unref?.()

      // Its own hook, so waking the wait cannot cost the loop the handle it reopens streams with
      wakeIdleWait = () => {
        clearInterval(timer)
        wakeIdleWait = undefined
        resolve(true)
      }
    })
  }

  /**
   * Answers a modern server that asked for more input before it could finish.
   *
   * The 2026-07-28 era turned the server's mid-request questions - sampling, elicitation, roots -
   * from requests it sends into requests it embeds in an `input_required` result, to be answered on
   * a retry. A 2025-era client only understands the first shape, and has no idea it is being asked
   * anything. So the embedded questions are unpacked and put to it as the ordinary server-initiated
   * requests it does understand, and its answers are packed into the retry.
   *
   * The client is never told any of this happened: it is still waiting on the one request it sent,
   * and that is what it is eventually answered with.
   *
   * @param original The request the client sent, which is what gets retried
   * @param firstResult The `input_required` result that started the exchange
   * @param version The revision being spoken to the remote server
   * @param exchange The token this exchange answers under, so a superseded one stays quiet
   */
  /**
   * Answers the client's own request, through the same seam every other answer goes through.
   *
   * Sending straight to the transport would skip {@link messageTransformer}, and with it the
   * `--ignore-tool` filter - so a `tools/list` that happened to be answered across a
   * multi-round-trip exchange would hand back the tools the user asked to hide. Which tools those
   * are is exactly what the remote server would have to control to arrange it.
   */
  function answerClient(message: Message, exchange?: number, original?: Message) {
    if (message.id !== undefined && message.id !== null) {
      // Only the exchange still holding this id may answer it. One that was cancelled, or failed by
      // a dropped session, or superseded by the client reusing the id, finds its token gone - and
      // a second response for one id is what makes a client's SDK complain about an unknown id.
      if (exchange !== undefined && liveExchanges.get(message.id) !== exchange) {
        debugLog('Dropping an answer from an exchange that no longer speaks for this request', { id: message.id, exchange })
        // Releases this exchange's own hold and nobody else's. Freeing the entry unconditionally
        // would free the request that reused this id, whose answer would then pair with nothing and
        // reach the client untransformed.
        if (original) messageTransformer.release(message.id, original)
        return
      }

      pendingRequests.delete(message.id)
      modernRetryIds.delete(message.id)
      liveExchanges.delete(message.id)
    }
    transportToClient.send(messageTransformer.interceptResponse(message)).catch(onClientError)
  }

  async function driveInputRequired(original: Message, firstResult: any, version: string, exchange: number) {
    let pending = firstResult

    for (let round = 0; round < MAX_INPUT_REQUIRED_ROUNDS; round++) {
      const requests: Record<string, { method: string; params?: unknown }> = pending.inputRequests ?? {}
      const responses: Record<string, unknown> = {}

      // Nothing to answer and no state to carry forward means the retry would be byte-identical to
      // the request that produced this - so the tool would simply run again, ten more times, with
      // every side effect that implies
      if (Object.keys(requests).length === 0 && pending.requestState === undefined) {
        throw new Error('the remote server asked for more input but named none, and carried no state to continue from')
      }

      if (Object.keys(requests).length > MAX_INPUT_REQUESTS_PER_ROUND) {
        throw new Error(
          `the remote server embedded ${Object.keys(requests).length} questions in one answer, which is more than this proxy will put to a client at once`,
        )
      }

      for (const [key, request] of Object.entries(requests)) {
        if (!canFulfilInputRequest(request.method, request.params)) {
          throw new Error(`the remote server asked for ${request.method}, which this proxy cannot put to a 2025-era client`)
        }

        // The client told us in its handshake what it can do, and the modern era's embedded form
        // does not change that. Asking anyway earns a -32601 the client is right to send.
        if (!clientDeclaredCapabilityFor(request.method, clientIdentity.capabilities)) {
          throw new Error(`the remote server asked for ${request.method}, which this client did not declare it supports`)
        }

        const answer = await askClient(request.method, request.params, MULTI_ROUND_TRIP_LEG_TIMEOUT_MS)
        if (answer.error) {
          throw new Error(`the local client refused ${request.method}: ${JSON.stringify(answer.error)}`)
        }
        responses[key] = answer.result
      }

      const retryParams = inputRequiredRetryParams(original.params, responses, pending.requestState)
      const reply = await askRemote((id) => {
        // Recorded so a `notifications/cancelled` naming the client's id can be re-addressed to the
        // leg the server is actually running
        modernRetryIds.set(original.id!, id)
        return stampLogLevel(
          stampModernMeta({ ...original, id, params: retryParams }, clientIdentity, version),
          requestedLogLevel,
        ) as Message
      }, MULTI_ROUND_TRIP_LEG_TIMEOUT_MS)

      if (reply.error) {
        answerClient({ jsonrpc: '2.0', id: original.id, error: reply.error } as Message, exchange, original)
        return
      }

      if (!isInputRequiredResult(reply.result)) {
        const translated = translateModernResult(reply.result)
        const answer = 'error' in translated ? { error: translated.error } : { result: translated.result }
        answerClient({ jsonrpc: '2.0', id: original.id, ...answer } as Message, exchange, original)
        return
      }

      pending = reply.result
    }

    throw new Error(`the remote server asked for more input ${MAX_INPUT_REQUIRED_ROUNDS} times without answering`)
  }

  let reinitInFlight: Promise<void> | null = null

  /** Coalesces concurrent callers so several in-flight 404s produce one new session, not one each */
  function reinitializeSession(): Promise<void> {
    if (!reinitInFlight) {
      reinitInFlight = doReinitializeSession().finally(() => {
        reinitInFlight = null
      })
    }
    return reinitInFlight
  }

  async function doReinitializeSession() {
    if (!lastInitialize) {
      throw new Error('no initialize request was seen, cannot re-establish the session')
    }

    // Must be cleared before we send, or the transport re-attaches the dead id
    // and the server 404s the handshake too. The SDK exposes sessionId read-only.
    ;(transportToServer as unknown as { _sessionId?: string })._sessionId = undefined

    const id = `mcp-remote-reinit-${++reinitSeq}`
    const response = await new Promise<Message>((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingReinit.delete(id)
        reject(new Error('timed out waiting for the re-initialize response'))
      }, 30000)
      pendingReinit.set(id, (message) => {
        clearTimeout(timer)
        resolve(message)
      })
      transportToServer.send({ ...lastInitialize, id }).catch((error) => {
        clearTimeout(timer)
        pendingReinit.delete(id)
        reject(error)
      })
    })

    if (response.error) {
      throw new Error(`server rejected re-initialize: ${JSON.stringify(response.error)}`)
    }

    // The new session negotiates its own version; the MCP-Protocol-Version header
    // has to follow it or the server 400s everything sent afterwards
    applyNegotiatedProtocolVersion(response)

    // Not ceremony: the SDK only (re)opens the GET SSE stream when it sees this
    // notification, so without it the server could no longer push to the client.
    await transportToServer.send({ jsonrpc: '2.0', method: 'notifications/initialized' })

    // The client is never told any of this happened, so whatever the server kept
    // per session - subscriptions, roots, progress tokens - is quietly gone. The
    // spec mandates the new session anyway; there is no way to replay that state.
    log(`Re-established session ${transportToServer.sessionId ?? '(none)'} after server expiry`)
  }

  /**
   * Pings the server on an interval so a connection carrying no traffic is not reaped.
   *
   * Servers - and the load balancers in front of them - commonly close a connection that has been
   * idle for a few minutes. Nothing surfaces that to the client until its next request fails, so
   * for a session that is mostly idle a cheap request on a timer is what keeps it usable.
   *
   * Every id here is ours, and so is every answer: they are recorded in `pendingPings` and dropped
   * in the remote handler instead of being forwarded.
   */
  function startKeepAlive(intervalMs: number) {
    const timer = setInterval(() => {
      // `ping` is not a method the 2026-07-28 era defines, and a stateless server has no session
      // whose liveness could lapse in the first place - so there is nothing here to keep alive.
      if (era?.era === 'modern') return

      const id = `mcp-remote-keepalive-${++pingSeq}`
      pendingPings.add(id)
      transportToServer.send({ jsonrpc: '2.0', id, method: 'ping' }).catch((error) => {
        // A failed ping is not fatal on its own - the next request is what decides whether the
        // connection is really gone - so this is reported rather than escalated.
        pendingPings.delete(id)
        log(`Keep-alive ping failed: ${error instanceof Error ? error.message : String(error)}`)
      })
    }, intervalMs)

    // Waiting to send another ping is never a reason to hold the process open
    timer.unref?.()
    log(`Keep-alive enabled, pinging every ${intervalMs / 1000} seconds`)
    return timer
  }

  function stopKeepAlive() {
    if (keepAliveTimer) {
      clearInterval(keepAliveTimer)
      keepAliveTimer = null
    }
    pendingPings.clear()
  }

  /**
   * Forwards a message, keeping the client's requests behind `notifications/initialized`.
   *
   * Every forward here is an independent POST, and a client sends the notification and its first
   * requests back to back, so without this they race - and a server that enforces the lifecycle
   * answers whichever request wins with "Session not initialized". The spec puts the same rule on
   * the client, which it honours over stdio; only the proxy was re-ordering it on the wire (see
   * https://github.com/geelen/mcp-remote/issues/310).
   *
   * Nothing else is serialized. `send` for a JSON-answering server does not resolve until that
   * request's response has been read, so ordering every message this way would turn concurrent
   * requests into sequential ones.
   */
  function forwardInOrder(message: Message) {
    // Nothing can be written correctly until the probe has said which era to write it in
    if (eraNegotiation) {
      eraNegotiation.then(() => forwardInOrder(message)).catch(onServerError)
      return
    }

    if (era?.era === 'modern' && message.method) {
      // A cancellation names the id the client knows; the server is working under the id this proxy
      // minted for the retry leg, so the notification has to be re-addressed or it cancels nothing
      if (message.method === 'notifications/cancelled' && liveExchanges.has(message.params?.requestId)) {
        const cancelledId = message.params.requestId

        // Retired whether or not a leg is running yet: during the first round the question is out
        // with the client and the server has nothing in flight, but the exchange will still finish
        // and must not answer a request the client has abandoned.
        liveExchanges.delete(cancelledId)
        pendingRequests.delete(cancelledId)

        // The server, meanwhile, knows the exchange by the id this proxy minted for the retry leg,
        // so a notification naming the client's id would cancel nothing
        const retryId = modernRetryIds.get(cancelledId)
        // Read first, then cleared: left behind it would outlive the exchange, and a later
        // cancellation under the same client id would name this one's long-dead leg
        modernRetryIds.delete(cancelledId)
        if (retryId !== undefined) {
          debugLog('Re-addressing a cancellation to the leg the server is actually running', { retryId })
          void sendToServer({ ...message, params: { ...message.params, requestId: retryId } })
        } else {
          debugLog('Cancelling an exchange that has nothing in flight with the server yet', { id: cancelledId })
        }
        return
      }

      const answer = localAnswerFor(message.method)
      if (answer) {
        // These are retired methods whose effect this proxy still owes the client
        if (message.method === RETIRED_IN_MODERN_ERA.subscribeResource && typeof message.params?.uri === 'string') {
          subscribedResources.add(message.params.uri)
          dropResourceSubscriptions = false
          refreshSubscription?.()
        } else if (message.method === RETIRED_IN_MODERN_ERA.unsubscribeResource && typeof message.params?.uri === 'string') {
          subscribedResources.delete(message.params.uri)
          dropResourceSubscriptions = false
          refreshSubscription?.()
        } else if (message.method === RETIRED_IN_MODERN_ERA.setLogLevel && typeof message.params?.level === 'string') {
          requestedLogLevel = message.params.level
          debugLog('Recording the log level to carry on every later request', { level: requestedLogLevel })
        }

        // A request is answered; the same method sent as a notification is simply dropped, because
        // there is nothing to answer and the server has no such method to forward it to
        if (message.id !== undefined && message.id !== null) {
          debugLog('Answering locally a method the modern era does not define', { method: message.method })
          messageTransformer.release(message.id)
          transportToClient.send({ jsonrpc: '2.0', id: message.id, result: answer }).catch(onClientError)
        } else {
          debugLog('Dropping a notification for a method the modern era does not define', { method: message.method })
        }
        return
      }

      if (isDroppedInModernEra(message.method)) {
        debugLog('Dropping a notification the modern era has no place for', { method: message.method })
        return
      }

      // The handshake was answered here, so a repeat is this proxy's to answer too - forwarding it
      // would POST a method the 2026-07-28 era retired
      if (message.method === 'initialize' && message.id !== undefined && message.id !== null) {
        debugLog('Answering a repeated handshake from the bridge rather than forwarding it')
        transportToClient
          .send({ jsonrpc: '2.0', id: message.id, result: synthesizeInitializeResult(era.discover, clientIdentity) })
          .catch(onClientError)
        return
      }
    }

    if (message.method === 'notifications/initialized') {
      // Bounded, because a server that never answers the notification must not leave every later
      // request queued behind it forever - racing ahead is the lesser failure.
      initializedDelivered = Promise.race([sendToServer(message), sleep(LIFECYCLE_BARRIER_TIMEOUT_MS)])
      return
    }

    if (initializedDelivered) {
      // Continuations resume in the order they were queued, so this preserves the client's order
      // among the messages waiting on it, not just their order relative to the notification.
      void initializedDelivered.then(() => sendToServer(message))
      return
    }

    void sendToServer(message)
  }

  /**
   * Whether the server refused this because nobody is signed in.
   *
   * The SDK has already opened a browser by the time this surfaces: its transport answers a 401 by
   * running `auth()`, which reaches `redirectToAuthorization` and then throws because the flow has
   * not finished. So the user is looking at a consent screen whose redirect is on its way to the
   * callback port - all that is missing is somebody to receive the code and redeem it.
   */
  function isUnauthorized(error: Error) {
    return error instanceof UnauthorizedError || error.message.includes('Unauthorized')
  }

  /** Coalesces concurrent callers, so several refused requests produce one sign-in, not one each */
  function reauthorizeOnce(): Promise<void> {
    if (!reauthorizeInFlight) {
      reauthorizeInFlight = reauthorize!().finally(() => {
        reauthorizeInFlight = null
      })
    }
    return reauthorizeInFlight
  }

  async function sendToServer(message: Message, alreadyReauthorized = false, alreadyDiscardedToken = false) {
    // The stream came back on a session that has not been handshaked yet. Sending now would race
    // the recovery onto the session the server dropped, and that failure is indistinguishable from
    // a real one. The recovery's own messages go out through `transportToServer.send`, so it never
    // waits on itself.
    if (sessionResumption) {
      await sessionResumption
    }

    const awaitsAnswer = message.method !== undefined && message.id !== undefined && message.id !== null
    if (awaitsAnswer) pendingRequests.add(message.id!)

    // Stamped here rather than in the transformer because the transformer runs the moment the
    // client's message arrives, which can be before the probe has said which era to speak.
    const outgoing =
      era?.era === 'modern' && awaitsAnswer
        ? stampLogLevel(stampModernMeta(message, clientIdentity, era.version), requestedLogLevel)
        : message

    // Kept so that a server answering `input_required` can be retried with what the client sent
    if (era?.era === 'modern' && awaitsAnswer) {
      // The id is the client's to reuse, and doing so ends whatever was running under it: the old
      // exchange loses its claim here rather than answering the request that replaced it
      liveExchanges.delete(message.id!)
      modernRetryIds.delete(message.id!)
      modernOriginals.set(message.id!, message)
    }

    try {
      await transportToServer.send(outgoing)
      if (message.method === 'initialize') scheduleInitializeTimeout(message)
      return
    } catch (error) {
      if (awaitsAnswer) {
        pendingRequests.delete(message.id!)
        // Left behind, a later stray frame for this id would find a request the client has already
        // been told failed, and start a whole multi-round-trip exchange - re-running the tool call
        // and answering the client a second time
        modernOriginals.delete(message.id!)
      }

      // A token the server refused straight after issuing it is not a sign-in problem yet - it is
      // a dead credential the SDK will keep presenting, because it will not ask for another while
      // it holds one. Discarding it turns the next attempt into an ordinary 401, which the branch
      // below then answers with a real sign-in. Once only: a second refusal is the server refusing
      // tokens on principle, and repeating this would just churn credentials.
      if (forgetRejectedTokens && !alreadyDiscardedToken && isRejectedAfterAuthorizing(error)) {
        log('The server rejected a token it had just issued - discarding it and asking for another')
        debugLog('Rejected token mid-session', { id: message.id, method: message.method })
        try {
          await forgetRejectedTokens()
          await sendToServer(message, alreadyReauthorized, true)
        } catch (discardError) {
          onServerError(discardError as Error)
          replyWithError(message, discardError as Error)
        }
        return
      }

      // The sign-in the SDK started can still be completed, but only by someone holding the
      // callback port. Retried once: a second refusal is the server rejecting a token we just
      // obtained, which another flow will not fix (see issues #133, #179, #248, #256, #286).
      if (reauthorize && !alreadyReauthorized && isUnauthorized(error as Error)) {
        log('Remote server requires authorization, completing sign-in')
        debugLog('Unauthorized send, re-authorizing', { id: message.id, method: message.method })
        try {
          await reauthorizeOnce()
          await sendToServer(message, true, alreadyDiscardedToken)
        } catch (authError) {
          onServerError(authError as Error)
          replyWithError(message, authError as Error)
        }
        return
      }

      // Re-initializing in response to a failed initialize would loop
      if (!isSessionExpired(error as Error) || message.method === 'initialize') {
        onServerError(error as Error)
        replyWithError(message, error as Error)
        return
      }

      log('Remote session expired, re-initializing')
      debugLog('Remote session expired', { id: message.id, method: message.method })

      try {
        await reinitializeSession()
        await transportToServer.send(message)
      } catch (retryError) {
        onServerError(retryError as Error)
        replyWithError(message, retryError as Error)
      }
    }
  }

  /**
   * Fails the client's `initialize` if the remote server accepted it but never answered.
   *
   * A no-op once the real response arrives: `transportToServer.onmessage` removes the id from
   * `pendingRequests` on delivery, which is what this checks before doing anything.
   */
  function scheduleInitializeTimeout(message: Message) {
    setTimeout(() => {
      if (!pendingRequests.has(message.id)) return
      pendingRequests.delete(message.id)
      const seconds = INITIALIZE_TIMEOUT_MS / 1000
      log(`Remote server did not answer 'initialize' within ${seconds}s`)
      replyWithError(message, new Error(`timed out after ${seconds}s waiting for the remote server to answer 'initialize'`))
    }, INITIALIZE_TIMEOUT_MS).unref?.()
  }

  /**
   * Answers every request the remote server can no longer answer.
   *
   * A failed send is reported to the client by `replyWithError`, but a request that was accepted
   * and then lost - because the stream carrying its answer went away - has nobody to report it.
   * The client holds it open forever, which is what a wedged bridge looks like from the outside.
   */
  function failPendingRequests(reason: string) {
    if (pendingRequests.size === 0) return

    debugLog('Failing requests the dropped session can no longer answer', { ids: [...pendingRequests] })
    for (const id of pendingRequests) {
      messageTransformer.release(id)
      transportToClient.send({ jsonrpc: '2.0', id, error: { code: -32001, message: `mcp-remote: ${reason}` } }).catch(onClientError)
      // Answered now, so there is nothing left to retry a multi-round-trip exchange for
      modernOriginals.delete(id)
      modernRetryIds.delete(id)
      // An exchange still running would answer this id again when it finishes; retiring its token
      // is what stops it, and costs nothing for an id no exchange is running under
      liveExchanges.delete(id)
    }
    pendingRequests.clear()
  }

  /**
   * Settles everything this proxy is itself waiting on, because nothing will answer it now.
   *
   * These are requests the peers never made and so will never be failed by anything else: the
   * subscription stream, each leg of a multi-round-trip retry, and each question put to the client
   * on the server's behalf. Left alone they would sit until their own timeouts, holding a tool call
   * open long after the transport carrying it went away.
   */
  function failOwnPendingRequests(reason: string) {
    for (const [id, settle] of [...pendingOwnRequests, ...pendingClientRequests, ...pendingDiscover, ...pendingReinit]) {
      settle({ jsonrpc: '2.0', id, error: { code: -32001, message: `mcp-remote: ${reason}` } } as Message)
    }
    pendingOwnRequests.clear()
    pendingClientRequests.clear()
    pendingDiscover.clear()
    pendingReinit.clear()
  }

  /**
   * Without this a failed send leaves the client waiting forever on a request
   * that will never be answered.
   */
  function replyWithError(message: Message, error: Error) {
    // Only requests may be answered. Notifications carry no id, and this handler
    // also sees the client's *responses* to server-initiated requests - those
    // carry an id but no method, and answering one makes the local SDK raise
    // "Received a response for an unknown message ID".
    if (message.method === undefined || message.id === undefined || message.id === null) {
      return
    }
    // Answered here rather than by the server, so the transformer's hold is released here too
    messageTransformer.release(message.id, message)
    transportToClient
      .send({
        jsonrpc: '2.0',
        id: message.id,
        error: { code: -32001, message: `mcp-remote: ${error.message ?? String(error)}` },
      })
      .catch(onClientError)
  }
}

/**
 * Result of OAuth server discovery
 */
export interface OAuthServerDiscoveryResult {
  /** The URL of the authorization server to use for OAuth */
  authorizationServerUrl: string
  /** Authorization server metadata (if successfully fetched) */
  authorizationServerMetadata?: AuthorizationServerMetadata
  /** Protected resource metadata (if discovered) */
  protectedResourceMetadata?: ProtectedResourceMetadata
  /** Scope extracted from WWW-Authenticate header */
  wwwAuthenticateScope?: string
}

/**
 * Probes the MCP server to discover the authorization server via Protected Resource Metadata.
 *
 * This implements the MCP Authorization Server Discovery flow:
 * 1. Make a request to the MCP server
 * 2. If we get a 401, extract the WWW-Authenticate header
 * 3. Use the resource_metadata URL from the header (if present) or well-known URIs
 * 4. Fetch Protected Resource Metadata to get the authorization server URL
 * 5. Fetch Authorization Server Metadata from the discovered server
 *
 * @param serverUrl The MCP server URL
 * @param headers Optional headers to include in the probe request
 * @returns Discovery result with authorization server URL and metadata
 */
export async function discoverOAuthServerInfo(
  serverUrl: string,
  headers: Record<string, string> = {},
): Promise<OAuthServerDiscoveryResult> {
  debugLog('Starting OAuth server discovery', { serverUrl })

  let wwwAuthenticateHeader: string | undefined
  let wwwAuthenticateScope: string | undefined

  // Step 1: Probe the MCP server to get WWW-Authenticate header
  try {
    debugLog('Probing MCP server for WWW-Authenticate header')
    const response = await fetch(serverUrl, {
      method: 'GET',
      headers: {
        ...headers,
        Accept: 'application/json, text/event-stream',
      },
      signal: AbortSignal.timeout(10000),
    })

    // If we get a successful response, the server doesn't require auth
    // Fall back to using serverUrl as authorization server
    if (response.ok) {
      debugLog('Server responded OK without auth, using server URL as authorization server')
      const authServerMetadata = await fetchAuthorizationServerMetadata(serverUrl)
      return {
        authorizationServerUrl: serverUrl,
        authorizationServerMetadata: authServerMetadata,
      }
    }

    // Check for 401 Unauthorized
    if (response.status === 401) {
      wwwAuthenticateHeader = response.headers.get('WWW-Authenticate') || undefined
      debugLog('Received 401 with WWW-Authenticate header', {
        hasHeader: !!wwwAuthenticateHeader,
        header: wwwAuthenticateHeader,
      })

      // Parse scope from WWW-Authenticate header if present
      if (wwwAuthenticateHeader) {
        const params = parseWWWAuthenticateHeader(wwwAuthenticateHeader)
        wwwAuthenticateScope = params.scope
      }
    }
  } catch (error) {
    debugLog('Error probing MCP server', {
      error: error instanceof Error ? error.message : String(error),
    })
    // Continue with discovery even if probe fails
  }

  // Step 2: Discover Protected Resource Metadata
  const protectedResourceMetadata = await discoverProtectedResourceMetadata(serverUrl, wwwAuthenticateHeader)

  // Step 3: Determine authorization server URL
  let authorizationServerUrl: string

  if (protectedResourceMetadata) {
    const discoveredUrl = getAuthorizationServerUrl(protectedResourceMetadata)
    if (discoveredUrl) {
      authorizationServerUrl = discoveredUrl
      debugLog('Using authorization server from Protected Resource Metadata', {
        authorizationServerUrl,
      })
    } else {
      // PRM found but no authorization_servers - fall back to server URL
      authorizationServerUrl = serverUrl
      debugLog('PRM found but no authorization_servers, falling back to server URL')
    }
  } else {
    // No PRM found - fall back to server URL (current behavior)
    authorizationServerUrl = serverUrl
    debugLog('No Protected Resource Metadata found, falling back to server URL as authorization server')
  }

  // Step 4: Fetch Authorization Server Metadata
  const authorizationServerMetadata = await fetchAuthorizationServerMetadata(authorizationServerUrl)

  return {
    authorizationServerUrl,
    authorizationServerMetadata,
    protectedResourceMetadata,
    wwwAuthenticateScope,
  }
}

/**
 * Type for the auth initialization function
 *
 * `forceRefresh` discards a verdict this instance has already acted on. The coordinator caches what
 * it decided, which is right while the decision still holds - and wrong once the tokens a sibling
 * wrote have been refused, because the cache keeps answering "wait for the sibling" to an instance
 * that now needs to sign in itself (see https://github.com/punkpeye/mcp-remote/issues/352).
 */
export type AuthInitializer = (options?: { forceRefresh?: boolean }) => Promise<{
  waitForAuthCode: () => Promise<AuthCodeResult>
  skipBrowserAuth: boolean
}>

/**
 * Expands `${VAR}` placeholders from the environment.
 *
 * The values this is used on - bearer tokens, client secrets - are the ones that should least be
 * sitting in a command line, where every other process on the machine can read them. Only the
 * placeholder and where it appeared are logged, never what it expanded to.
 *
 * @param value The string to expand
 * @param context Where the value came from, for the log line when a variable is missing
 * @returns The string with every placeholder replaced
 */
function substituteEnvVars(value: string, context: string): string {
  return value.replace(/\$\{([^}]+)}/g, (match, envVarName) => {
    // `in` would match `toString`, `constructor` and the rest of Object.prototype, which expand to
    // source text rather than to anything the user set
    if (!Object.hasOwn(process.env, envVarName)) {
      log(`Warning: Environment variable '${envVarName}' not found for ${context}; leaving ${match} as it is.`)
      return match
    }

    log(`Replacing ${match} with environment value in ${context}`)
    return process.env[envVarName]!
  })
}

/**
 * Reads a JSON argument that may carry `${VAR}` placeholders.
 *
 * Two things are deliberate here. A value with no placeholder in it is not touched at all, so a
 * credential that happens to contain `${` survives an upgrade to a version that learned to expand
 * them. And a parse failure is re-thrown without Node's message, because that message quotes the
 * first characters of what failed to parse - which, for an argument that is one placeholder holding
 * a secret, is the secret.
 *
 * @param raw The JSON text, before any expansion
 * @param context Where the value came from, for the log line when a variable is missing
 * @returns The parsed value
 */
function parseJsonWithEnvVars(raw: string, context: string): any {
  const expanded = raw.includes('${') ? substituteEnvVars(raw, context) : raw

  try {
    return JSON.parse(expanded)
  } catch {
    throw new Error(`Could not parse the ${context} as JSON${raw.includes('${') ? ' after expanding its ${...} placeholders' : ''}`)
  }
}

/** The header shapes `fetch` accepts, plus the `Headers` the SDK actually hands over. */
type HeaderSource = RequestInit['headers'] | Headers | globalThis.Headers | undefined

function headerEntries(source: HeaderSource): Array<[string, string]> {
  if (!source) return []
  // Arrays have `entries` too, so this order matters - theirs yields [index, pair], not [name, value]
  if (Array.isArray(source)) return source as Array<[string, string]>
  const iterable = source as { entries?: () => Iterable<[string, string]> }
  if (typeof iterable.entries === 'function') return [...iterable.entries()]
  return Object.entries(source as Record<string, string>)
}

/**
 * Merges header sources into one plain object, with later sources winning.
 *
 * Two things make this less trivial than a spread.
 *
 * The sources are different shapes. The SDK hands over a `Headers` built from the *global* class,
 * while the check here used to be `instanceof Headers` against the one imported from undici - a
 * different class, so it never matched, and the fallback spread of a `Headers` yields no own
 * properties at all. Every header the SDK had set was dropped (see
 * https://github.com/geelen/mcp-remote/issues/157). Duck-typing on `entries` accepts either.
 *
 * And the sources disagree about case. `Headers.entries()` lowercases, while `--header` values and
 * the ones added here keep the case they were written in, so a plain merge emits `authorization`
 * *and* `Authorization` as separate keys - which `fetch` then joins into a single comma-separated
 * value that no server will accept. Merging case-insensitively keeps one entry per header, spelled
 * the way its last writer spelled it, so a server matching on `Company` still sees `Company`.
 *
 * @param sources Header collections in precedence order, lowest first
 * @returns The merged headers
 */
export function mergeHeaders(...sources: HeaderSource[]): Record<string, string> {
  const merged = new Map<string, [string, string]>()
  for (const source of sources) {
    for (const [name, value] of headerEntries(source)) {
      merged.set(name.toLowerCase(), [name, value])
    }
  }
  return Object.fromEntries(merged.values())
}

/**
 * Creates and connects to a remote server with OAuth authentication
 * @param client The client to connect with
 * @param serverUrl The URL of the remote server
 * @param authProvider The OAuth client provider
 * @param headers Additional headers to send with the request
 * @param authInitializer Function to initialize authentication when needed
 * @param transportStrategy Strategy for selecting transport type ('sse-only', 'http-only', 'sse-first', 'http-first')
 * @param protocolMode Whether to look for a 2026-07-28 server rather than assume an `initialize` handshake
 * @param recursionReasons Set of reasons for recursive calls (internal use)
 * @returns The connected transport
 */
export async function connectToRemoteServer(
  client: Client | null,
  serverUrl: string,
  authProvider: OAuthClientProvider,
  headers: Record<string, string>,
  authInitializer: AuthInitializer,
  transportStrategy: TransportStrategy = 'http-first',
  protocolMode: ProtocolMode = 'legacy',
  recursionReasons: Set<string> = new Set(),
): Promise<Transport> {
  log(`[${pid}] Connecting to remote server: ${serverUrl}`)
  const url = new URL(serverUrl)

  // Every attempt the EventSource makes to open the stream comes through the `fetch` below,
  // including the ones it makes on its own after the connection drops. Counting them is how a
  // reconnect becomes observable from out here: the SDK exposes no event for it.
  let sseStreamOpened = 0

  // Create transport with eventSourceInit to pass Authorization header if present
  const eventSourceInit = {
    fetch: (requestUrl: string | URL, init?: RequestInit) => {
      return Promise.resolve(authProvider?.tokens?.())
        .then((tokens) => {
          const cookie = cookieHeaderFor(requestUrl)
          return fetch(requestUrl, {
            ...init,
            headers: mergeHeaders(
              init?.headers,
              // The stream is usually where a balancer plants its cookie, and always where it
              // has to be sent back, or the POSTs land on a node that never saw this session.
              cookie ? { Cookie: cookie } : undefined,
              headers,
              tokens?.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : undefined,
              { Accept: 'text/event-stream' },
            ),
          })
        })
        .then((response) => {
          captureCookies(requestUrl, response)

          // Only a stream that actually opened counts. A failed attempt is followed by another,
          // and announcing a reconnect for each would start a handshake against a stream that
          // is not there.
          if (response.ok && ++sseStreamOpened > 1) {
            log('Remote SSE stream reconnected')
            ;(transport as StreamReconnectAware).onStreamReconnect?.()
          }
          return response
        })
    },
  }

  log(`Using transport strategy: ${transportStrategy}`)
  // Determine if we should attempt to fallback on error
  // Choose transport based on user strategy and recursion history
  const shouldAttemptFallback = transportStrategy === 'http-first' || transportStrategy === 'sse-first'

  // Create transport instance based on the strategy
  const sseTransport = transportStrategy === 'sse-only' || transportStrategy === 'sse-first'
  const transport = sseTransport
    ? new SSEClientTransport(url, {
        authProvider,
        requestInit: { headers },
        eventSourceInit,
        fetch: fetchWithMcpHeaders,
      })
    : new StreamableHTTPClientTransport(url, {
        authProvider,
        requestInit: { headers },
        fetch: fetchWithMcpHeaders,
      })

  // When connecting without a Client (proxy mode), the auth challenge (401) is not received by
  // `transport` itself but by the one-off `testTransport` created below. The SDK stores the
  // `resource_metadata` URL from the WWW-Authenticate header on the transport that received the
  // 401, and `finishAuth` reads it back to discover the authorization server. If we call
  // `finishAuth` on `transport` (which never saw the 401) that URL is missing, so the token
  // exchange falls back to POSTing at the resource origin instead of the discovered
  // `token_endpoint` (see https://github.com/geelen/mcp-remote/issues/270). Track the transport
  // that actually handled the challenge so we can complete auth on it.
  let authChallengeTransport: SSEClientTransport | StreamableHTTPClientTransport | undefined

  try {
    debugLog('Attempting to connect to remote server', { sseTransport })

    if (client) {
      debugLog('Connecting client to transport')
      await client.connect(transport)
    } else {
      debugLog('Starting transport directly')
      await transport.start()
      if (!sseTransport) {
        // Extremely hacky, but we didn't actually send a request when calling transport.start() above, so we don't
        // know if we're even talking to an HTTP server. But if we forced that now we'd get an error later saying that
        // the client is already connected. So let's just create a one-off client to make a single request and figure
        // out if we're actually talking to an HTTP server or not.
        debugLog('Creating test transport for HTTP-only connection test')
        // This probe sends the very first `initialize` POST, so it is the request a
        // method-aware gateway routes on. It needs the mirrored headers as much as the
        // real transport does.
        const testTransport = new StreamableHTTPClientTransport(url, {
          authProvider,
          requestInit: { headers },
          fetch: fetchWithMcpHeaders,
        })
        // This transport is the one that will receive (and store the metadata from) any 401 challenge.
        authChallengeTransport = testTransport
        // The probe opens the connection, so it is the thing that meets a 2026-07-28 server first.
        // Left in the default era it would send an `initialize` that server retired, and fail the
        // connection before `mcpProxy` ever got to bridge anything - so it negotiates too.
        const testClient = new Client(
          { name: 'mcp-remote-fallback-test', version: '0.0.0' },
          { capabilities: {}, ...(protocolMode === 'auto' ? { versionNegotiation: { mode: 'auto' as const } } : {}) },
        )
        await testClient.connect(testTransport)
      }
    }
    log(`Connected to remote server using ${transport.constructor.name}`)

    return transport
  } catch (error: any) {
    // Check if it's a protocol error and we should attempt fallback
    // SdkHttpError carries the HTTP status on `status`; `code` is an SdkErrorCode string
    const httpStatusCode = error instanceof SdkHttpError ? error.status : null
    const shouldFallbackOnError =
      shouldAttemptFallback &&
      error instanceof Error &&
      (httpStatusCode === 404 ||
        httpStatusCode === 405 ||
        error.message.includes('405') ||
        error.message.includes('Method Not Allowed') ||
        error.message.includes('404') ||
        error.message.includes('Not Found'))

    if (shouldFallbackOnError) {
      log(`Received error (status ${httpStatusCode ?? 'unknown'}): ${error.message}`)

      // If we've already tried falling back once, throw an error
      if (recursionReasons.has(REASON_TRANSPORT_FALLBACK)) {
        const errorMessage = `Already attempted transport fallback. Giving up.`
        log(errorMessage)
        throw new Error(errorMessage, { cause: error })
      }

      log(`Recursively reconnecting for reason: ${REASON_TRANSPORT_FALLBACK}`)

      // Add to recursion reasons set
      recursionReasons.add(REASON_TRANSPORT_FALLBACK)

      // Recursively call connectToRemoteServer with the updated recursion tracking
      return connectToRemoteServer(
        client,
        serverUrl,
        authProvider,
        headers,
        authInitializer,
        sseTransport ? 'http-only' : 'sse-only',
        protocolMode,
        recursionReasons,
      )
    } else if (isRejectedAfterAuthorizing(error)) {
      // Nothing else clears this. The token is on disk, the SDK will not ask for another while it
      // holds one, and the server will not take the one it has - so every run fails here until the
      // credential is deleted by hand. Discarding it puts the next attempt back on the ordinary
      // sign-in path rather than repeating any of it here.
      if (recursionReasons.has(REASON_REJECTED_TOKEN)) {
        log('The server rejected a freshly issued token as well. Giving up.')
        throw error
      }

      log('The server rejected a token it had just issued - discarding it and signing in again')
      debugLog('Rejected token after a successful authorization', { message: error.message })
      await forgetRejectedAuthorization(authProvider)

      recursionReasons.add(REASON_REJECTED_TOKEN)
      return connectToRemoteServer(
        client,
        serverUrl,
        authProvider,
        headers,
        authInitializer,
        transportStrategy,
        protocolMode,
        recursionReasons,
      )
    } else if (error instanceof UnauthorizedError || (error instanceof Error && error.message.includes('Unauthorized'))) {
      log('Authentication required. Initializing auth...')
      debugLog('Authentication error detected', {
        errorCode: error instanceof OAuthError ? error.code : undefined,
        errorMessage: error.message,
        stack: error.stack,
      })

      const giveUpIfAlreadyRetried = () => {
        if (!recursionReasons.has(REASON_AUTH_NEEDED)) return
        const errorMessage = `Already attempted reconnection for reason: ${REASON_AUTH_NEEDED}. Giving up.`
        log(errorMessage)
        debugLog('Already attempted auth reconnection, giving up', {
          recursionReasons: Array.from(recursionReasons),
        })
        throw new Error(errorMessage, { cause: error })
      }

      // A non-interactive grant has already finished by the time this is reached: the SDK's
      // redirect step ran the whole flow and wrote the tokens. Nothing is coming to a callback
      // port, so starting one would only bind a port nobody will ever call.
      if (NON_INTERACTIVE_FLOW) {
        log('Signed in without a browser - reconnecting with the tokens it produced')
        giveUpIfAlreadyRetried()

        recursionReasons.add(REASON_AUTH_NEEDED)
        return connectToRemoteServer(
          client,
          serverUrl,
          authProvider,
          headers,
          authInitializer,
          transportStrategy,
          protocolMode,
          recursionReasons,
        )
      }

      // Initialize authentication on-demand. A handover already tried and refused must not be
      // handed back from cache, or this instance keeps being told to wait for a sign-in that has
      // already happened rather than running one of its own.
      debugLog('Calling authInitializer to start auth flow')
      const handoverAlreadyTried = recursionReasons.has(REASON_SIBLING_TOKENS)
      const { waitForAuthCode, skipBrowserAuth } = await authInitializer({ forceRefresh: handoverAlreadyTried })

      // A concurrent instance ran the browser flow for us and persisted the tokens. There is no
      // authorization code of our own to exchange - our callback server never received one, and
      // the sibling's code has already been redeemed - so `waitForAuthCode` here is a promise
      // that never settles (see coordinateAuth). Reconnect instead, which makes the auth provider
      // re-read the tokens the sibling wrote (see https://github.com/geelen/mcp-remote/issues/322).
      if (skipBrowserAuth) {
        // Refreshed above and still a follower: the sibling holds the callback port, and the tokens
        // it wrote have already been refused once. `waitForAuthCode` below would wait on a code
        // that is never coming, so this ends here - saying which of the two things went wrong.
        if (handoverAlreadyTried) {
          log('Another instance owns the sign-in, and the tokens it wrote were refused; giving up')
          throw new Error('Another instance completed the sign-in, but the remote server refused the tokens it wrote', { cause: error })
        }

        log('Authentication was completed by another instance - reconnecting with the tokens it wrote')

        recursionReasons.add(REASON_SIBLING_TOKENS)
        debugLog('Recursively reconnecting using a sibling instance tokens', {
          recursionReasons: Array.from(recursionReasons),
        })
        return connectToRemoteServer(
          client,
          serverUrl,
          authProvider,
          headers,
          authInitializer,
          transportStrategy,
          protocolMode,
          recursionReasons,
        )
      }

      log('Authentication required. Waiting for authorization...')

      // Wait for the authorization code from the callback
      debugLog('Waiting for auth code from callback server')
      const { code, state, iss } = await waitForAuthCode()
      debugLog('Received auth code from callback server')

      // The code may belong to a flow another instance started, whose verifier is not this one's
      if (state && 'useAuthorizationState' in authProvider && typeof authProvider.useAuthorizationState === 'function') {
        authProvider.useAuthorizationState(state)
      }

      // Checked before the exchange, not after: an authorization code is single-use (RFC 6749
      // 4.1.2) and the callback server hands back the same retained code on a second call, so
      // exchanging it again fails with invalid_grant and masks this message.
      giveUpIfAlreadyRetried()

      try {
        log('Completing authorization...')
        // Complete auth on the transport that received the 401 challenge (in proxy mode this is the
        // one-off test transport, not `transport`), so the stored resource_metadata URL is used to
        // discover the correct token_endpoint. Falls back to `transport` for the with-client path.
        await (authChallengeTransport ?? transport).finishAuth(code, iss)
        debugLog('Authorization completed successfully')

        // Track this reason for recursion
        recursionReasons.add(REASON_AUTH_NEEDED)
        log(`Recursively reconnecting for reason: ${REASON_AUTH_NEEDED}`)
        debugLog('Recursively reconnecting after auth', { recursionReasons: Array.from(recursionReasons) })

        // Recursively call connectToRemoteServer with the updated recursion tracking
        return connectToRemoteServer(
          client,
          serverUrl,
          authProvider,
          headers,
          authInitializer,
          transportStrategy,
          protocolMode,
          recursionReasons,
        )
      } catch (authError: any) {
        log('Authorization error:', authError)
        debugLog('Authorization error during finishAuth', {
          errorMessage: authError.message,
          stack: authError.stack,
        })
        throw authError
      }
    } else {
      log('Connection error:', error)
      debugLog('Connection error', {
        errorMessage: error.message,
        stack: error.stack,
        transportType: transport.constructor.name,
      })
      throw error
    }
  }
}

/**
 * Sets up an Express server to handle OAuth callbacks
 * @param options The server options
 * @returns A promise resolving to an object with the server, actualPort, authCode, and waitForAuthCode function
 */
export async function setupOAuthCallbackServerWithLongPoll(options: OAuthCallbackServerOptions): Promise<{
  server: Server
  actualPort: number
  authCode: string | null
  waitForAuthCode: () => Promise<AuthCodeResult>
  authCompletedPromise: Promise<AuthCodeResult>
}> {
  /**
   * Codes that have arrived and nobody has redeemed yet, oldest first.
   *
   * A queue rather than one retained code, because a process signs in more than once: tokens are
   * revoked, refresh tokens lapse, a server starts asking for a scope it did not before. The old
   * single slot handed every later caller the *first* code it ever saw, and an authorization code
   * is single-use (RFC 6749 4.1.2), so redeeming it a second time fails with `invalid_grant`.
   */
  const unclaimedCodes: AuthCodeResult[] = []

  /** Callers waiting for a code that has not arrived yet, in the order they asked. */
  const waitingForCode: Array<{ resolve: (result: AuthCodeResult) => void; reject: (error: Error) => void }> = []

  /**
   * Whether any sign-in has ever completed here.
   *
   * Kept separate from the queue: a sibling polling the long-poll endpoint is asking "has the
   * user finished, so are there tokens on disk for me to read", which stays true once it is true.
   * Draining the queue must not make that answer go backwards.
   */
  let authEverCompleted = false

  const app = express()

  // Create a promise to track when auth is completed
  let authCompletedResolve: (result: AuthCodeResult) => void
  const authCompletedPromise = new Promise<AuthCodeResult>((resolve) => {
    authCompletedResolve = resolve
  })

  // Long-polling endpoint
  app.get(LONG_POLL_PATH, (req, res) => {
    if (authEverCompleted) {
      // Auth already completed - just return 200 without the actual code
      // Secondary instances will read tokens from disk
      log('Auth already completed, returning 200')
      res.status(200).send('Authentication completed')
      return
    }

    if (req.query.poll === 'false') {
      log('Client requested no long poll, responding with 202')
      res.status(202).send('Authentication in progress')
      return
    }

    // Long poll - wait for up to 30 seconds
    const longPollTimeout = setTimeout(() => {
      log('Long poll timeout reached, responding with 202')
      res.status(202).send('Authentication in progress')
    }, options.authTimeoutMs || 30000)

    // If auth completes while we're waiting, send the response immediately
    authCompletedPromise
      .then(() => {
        clearTimeout(longPollTimeout)
        if (!res.headersSent) {
          log('Auth completed during long poll, responding with 200')
          res.status(200).send('Authentication completed')
        }
      })
      .catch(() => {
        clearTimeout(longPollTimeout)
        if (!res.headersSent) {
          log('Auth failed during long poll, responding with 500')
          res.status(500).send('Authentication failed')
        }
      })
  })

  // Lets an instance that lost the bind identify who holds the port. Without it, EADDRINUSE from
  // an unrelated process is indistinguishable from a sibling and every instance waits forever.
  app.get(MCP_REMOTE_ID_PATH, (_req, res) => {
    res.json({ mcpRemote: true, serverUrlHash: options.serverUrlHash })
  })

  // OAuth callback endpoint
  app.get(options.path, (req, res) => {
    const code = req.query.code as string | undefined
    const state = req.query.state as string | undefined
    const iss = req.query.iss as string | undefined
    const authorizationError = req.query.error as string | undefined
    if (authorizationError) {
      const description = (req.query.error_description as string | undefined) ?? authorizationError
      log(`Authorization failed: ${authorizationError} - ${description}`)
      res.status(400).send(`Authorization failed: ${description}\n\nYou may close this window and return to the CLI.`)
      options.events.emit('auth-code-failed', new Error(`Authorization failed: ${authorizationError} - ${description}`))
      return
    }
    if (!code) {
      res.status(400).send('Error: No authorization code received')
      return
    }

    const received: AuthCodeResult = { code, state, iss }
    authEverCompleted = true
    log('Auth code received, resolving promise')
    authCompletedResolve(received)

    // Hand it straight to whoever is waiting; hold it only if nobody is yet. The startup flow
    // reaches `waitForAuthCode` after the browser has already been sent here, so both orders happen.
    const waiter = waitingForCode.shift()
    if (waiter) waiter.resolve(received)
    else unclaimedCodes.push(received)

    res.send(`
      Authorization successful!
      You may close this window and return to the CLI.
      <script>
        // If this is a non-interactive session (no manual approval step was required) then
        // this should automatically close the window. If not, this will have no effect and
        // the user will see the message above.
        window.close();
      </script>
    `)

    // Notify main flow that auth code is available
    options.events.emit('auth-code-received', code, state)
  })

  // Bind the server. There is deliberately no random-port fallback: the deterministic port is
  // what makes concurrent instances agree on an owner, and an instance that quietly moved
  // elsewhere would advertise a redirect_uri no browser can deliver a code to. EADDRINUSE is a
  // signal that somebody else owns this flow, and the caller decides what to do about it.
  const { server, actualPort } = await new Promise<{ server: Server; actualPort: number }>((resolve, reject) => {
    const httpServer = app.listen(options.port, '127.0.0.1')

    httpServer.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        reject(
          Object.assign(new Error(`Callback port ${options.port} is already in use`), { code: 'EADDRINUSE', requestedPort: options.port }),
        )
        return
      }
      reject(err)
    })

    httpServer.once('listening', () => {
      const addr = httpServer.address() as AddressInfo
      log(`OAuth callback server running at http://127.0.0.1:${addr.port}`)
      resolve({ server: httpServer, actualPort: addr.port })
    })
  })

  /** Takes the next unredeemed code, waiting for one if none has arrived. */
  const waitForAuthCode = (): Promise<AuthCodeResult> => {
    const alreadyHere = unclaimedCodes.shift()
    if (alreadyHere) return Promise.resolve(alreadyHere)

    return new Promise((resolve, reject) => {
      const entry = {
        resolve,
        // An authorization the user denied never produces a code, and waiting for one holds the
        // callback port for the life of the process
        reject: (error: Error) => {
          options.events.off('auth-code-failed', onFailure)
          reject(error)
        },
      }
      const onFailure = (error: Error) => {
        const index = waitingForCode.indexOf(entry)
        if (index !== -1) waitingForCode.splice(index, 1)
        entry.reject(error)
      }
      waitingForCode.push(entry)
      options.events.once('auth-code-failed', onFailure)
    })
  }

  return { server, actualPort, authCode: null, waitForAuthCode, authCompletedPromise }
}

/** The callback path the OAuth redirect URI is built on, unless --callback-path overrides it. */
const DEFAULT_CALLBACK_PATH = '/oauth/callback'

/** Endpoint secondary instances long-poll to await the auth flow the primary instance is running. */
export const MCP_REMOTE_ID_PATH = '/.mcp-remote/id'
const LONG_POLL_PATH = '/wait-for-auth'

/**
 * Builds the OAuth redirect URI for a given host/port. Kept in one place because the value
 * registered with the authorization server and the value checked against a cached
 * registration must match exactly - see invalidateMismatchedClientRegistration.
 */
export function buildRedirectUrl(host: string, port: number, callbackPath: string = DEFAULT_CALLBACK_PATH): string {
  return `http://${host}:${port}${callbackPath}`
}

/**
 * Deletes a cached client registration whose redirect_uris do not include the redirect URI
 * this session will send, forcing a fresh dynamic registration on the next request.
 */
async function invalidateMismatchedClientRegistration(serverUrlHash: string, redirectUrl: string): Promise<void> {
  const clientInfo = await readJsonFile<OAuthClientInformationFull>(serverUrlHash, 'client_info.json', OAuthClientInformationFullSchema)
  if (!clientInfo || clientInfo.redirect_uris.includes(redirectUrl)) {
    return
  }

  log(
    `Cached client registration is for ${clientInfo.redirect_uris.join(', ')} but this session will use ${redirectUrl}. ` +
      `Deleting it so the client re-registers.`,
  )
  await rm(getConfigFilePath(serverUrlHash, 'client_info.json'), { force: true })
}

/**
 * Whether a value can serve as a Client ID Metadata Document URL (SEP-991).
 *
 * Mirrors the SDK's own check, which throws deep inside `auth()` rather than at startup. A
 * rejected URL there surfaces long after the flag was typed, so the same rule is applied while
 * the arguments are still being read and the user can be told which one was wrong. The root path
 * is excluded because a client id has to be distinguishable from the origin that serves it.
 */
function isClientMetadataUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && url.pathname !== '/'
  } catch {
    return false
  }
}

export function calculateDefaultPort(serverUrlHash: string): number {
  // Convert the first 4 bytes of the serverUrlHash into a port offset
  const offset = parseInt(serverUrlHash.substring(0, 4), 16)
  // Pick a consistent but random-seeming port from 3335 to 49151
  return 3335 + (offset % 45816)
}

/**
 * Parses command line arguments for MCP clients and proxies
 * @param args Command line arguments
 * @param usage Usage message to show on error
 * @returns A promise that resolves to an object with parsed serverUrl, callbackPort and headers
 */
/** The subset of undici dispatcher options this CLI exposes. Shared by both agent flavours. */
type DispatcherOptions = {
  connect?: { timeout?: number; family?: number }
  bodyTimeout?: number
  headersTimeout?: number
}

/**
 * Reads a flag whose value is a duration in seconds, and returns it in milliseconds.
 *
 * @param args The command line arguments
 * @param flag The flag to read
 * @param options Whether zero is meaningful for this flag - for the timeouts it means "no timeout"
 * @returns The duration in milliseconds, or undefined if the flag was absent or unusable
 */
/**
 * Parameters the flow owns, which `--authorize-param` must not overwrite.
 *
 * Setting any of these does not customise the request so much as break it: the SDK derives them
 * from the PKCE challenge and the registered client, and a value that disagrees surfaces as an
 * opaque error from the authorization server rather than as a bad flag.
 */
const RESERVED_AUTHORIZE_PARAMS = new Set([
  'client_id',
  'redirect_uri',
  'response_type',
  'state',
  'code_challenge',
  'code_challenge_method',
])

/**
 * Collects repeated `--authorize-param key=value` flags.
 *
 * Authorization servers keep asking for parameters that are theirs alone - Google wants
 * `access_type=offline` and `prompt=consent` to part with a refresh token, Auth0 wants an
 * `audience` to issue a JWT rather than an opaque token - and hardcoding a hostname check per
 * vendor does not scale. This is the escape hatch for all of them.
 */
export function parseAuthorizeParams(args: string[]): Record<string, string> {
  const params: Record<string, string> = {}

  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] !== '--authorize-param') continue

    const raw = args[i + 1]
    const separator = raw.indexOf('=')
    if (separator < 1) {
      throw new Error(
        `Invalid --authorize-param value: "${raw}". Expected key=value, e.g. --authorize-param audience=https://api.example.com`,
      )
    }

    // Split on the first `=` only, because values legitimately contain them - base64 padding,
    // nested query strings, JWTs
    const key = raw.slice(0, separator).trim()
    const value = raw.slice(separator + 1)

    if (RESERVED_AUTHORIZE_PARAMS.has(key)) {
      throw new Error(`--authorize-param cannot set "${key}": it is part of the authorization flow itself and is derived per request.`)
    }
    if (key === 'resource') {
      // Accepted rather than refused, but it only reaches the authorize call - RFC 8707 wants the
      // same value on the token and refresh requests, and only --resource puts it there
      log('Warning: --authorize-param resource=... only applies to the authorization request. Use --resource so the token request agrees.')
    }

    params[key] = value
  }

  return params
}

export function parseSecondsOption(args: string[], flag: string, { allowZero = false } = {}): number | undefined {
  const index = args.indexOf(flag)
  if (index === -1 || index >= args.length - 1) return undefined

  const raw = args[index + 1]
  const seconds = Number(raw)
  if (!Number.isFinite(seconds) || seconds < 0 || (seconds === 0 && !allowZero)) {
    log(`Warning: Ignoring invalid ${flag} value: ${raw}. Must be a ${allowZero ? 'non-negative' : 'positive'} number of seconds.`)
    return undefined
  }

  return Math.round(seconds * 1000)
}

/** Splits `Name: value` into its parts, or undefined if it is not that shape. */
function parseHeaderLine(line: string): { name: string; value: string } | undefined {
  const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
  return match ? { name: match[1], value: match[2] } : undefined
}

/**
 * Reads headers from a file, one `Name: value` per line, `#` for comments.
 *
 * A file exists to keep credentials out of the process arguments, where every other user on the
 * machine can read them - so a file named but unreadable is fatal rather than a warning. Carrying
 * on would send the request without its credentials and turn a typo in a path into an
 * authorization error somewhere much less obvious.
 *
 * @param filePath The file to read
 * @returns The headers it declares
 */
async function readHeaderFile(filePath: string): Promise<Record<string, string>> {
  let contents: string
  try {
    contents = await readFile(filePath, 'utf8')
  } catch (error) {
    throw new Error(`Could not read the header file ${filePath}: ${(error as Error).message}`, { cause: error })
  }

  const headers: Record<string, string> = {}
  contents.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) return

    const parsed = parseHeaderLine(trimmed)
    // By line number, never by content - these lines are exactly where the secrets are
    if (!parsed) {
      log(`Warning: ignoring line ${index + 1} of ${filePath}, which is not in Name:Value form`)
      return
    }
    headers[parsed.name] = parsed.value
  })

  log(`Loaded ${Object.keys(headers).length} header(s) from ${filePath}`)
  return headers
}

export async function parseCommandLineArgs(args: string[], usage: string) {
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(`${usage}\n`)
    process.exit(0)
  }

  // Deliberately no `-v` alias: it conventionally means "verbose", and this CLI
  // already has --debug, so leave -v free to become its shorthand later.
  if (args.includes('--version')) {
    process.stdout.write(`${MCP_REMOTE_VERSION}\n`)
    process.exit(0)
  }

  // Process headers
  const headers: Record<string, string> = {}
  let i = 0
  while (i < args.length) {
    if (args[i] === '--header' && i < args.length - 1) {
      const value = args[i + 1]
      const parsed = parseHeaderLine(value)
      // Never the argument itself: a header that failed to parse is usually one whose value
      // contains something unexpected, and the value is a credential more often than not.
      if (parsed) headers[parsed.name] = parsed.value
      else log('Warning: ignoring a --header argument that is not in Name:Value form')
      args.splice(i, 2)
      // Do not increment i, as the array has shifted
      continue
    }
    if (args[i] === '--header-file' && i < args.length - 1) {
      Object.assign(headers, await readHeaderFile(args[i + 1]))
      args.splice(i, 2)
      continue
    }
    i++
  }

  const serverUrl = args[0]
  const specifiedPort = args[1] ? parseInt(args[1]) : undefined
  const allowHttp = args.includes('--allow-http')

  // Check for debug flag
  const debug = args.includes('--debug')
  if (debug) {
    DEBUG = true
    log('Debug mode enabled - detailed logs will be written to ~/.mcp-auth/')
  }

  // Check for silent flag
  const silent = args.includes('--silent')
  if (silent) {
    SILENT = true
    log('Silent mode enabled - stderr output will be suppressed, except when --debug is also enabled')
  }

  // Network tuning. These land on the global undici dispatcher, which both our own `fetch` and the
  // SDK's `globalThis.fetch` resolve through - the slot is keyed by a registered symbol, so the two
  // undici copies share it. Without a dispatcher there is no way to reach these settings at all,
  // which is why people have been patching them in with NODE_OPTIONS (see issues #107 and #263).
  const connectTimeoutMs = parseSecondsOption(args, '--connect-timeout')
  const bodyTimeoutMs = parseSecondsOption(args, '--body-timeout', { allowZero: true })
  const headersTimeoutMs = parseSecondsOption(args, '--headers-timeout', { allowZero: true })
  const forceIpv4 = args.includes('--ipv4')

  const dispatcherOptions: DispatcherOptions = {}
  if (connectTimeoutMs !== undefined || forceIpv4) {
    dispatcherOptions.connect = {
      ...(connectTimeoutMs !== undefined ? { timeout: connectTimeoutMs } : {}),
      // Happy-eyeballs tries every A and AAAA record it gets back. On a network where the IPv6
      // routes are black holes rather than refusals, those attempts time out instead of failing
      // fast and take the whole request with them, even though the IPv4 addresses are reachable.
      ...(forceIpv4 ? { family: 4 } : {}),
    }
  }
  if (bodyTimeoutMs !== undefined) dispatcherOptions.bodyTimeout = bodyTimeoutMs
  if (headersTimeoutMs !== undefined) dispatcherOptions.headersTimeout = headersTimeoutMs

  if (forceIpv4) log('Restricting connections to IPv4')
  if (connectTimeoutMs !== undefined) log(`Using connect timeout: ${connectTimeoutMs / 1000} seconds`)
  if (bodyTimeoutMs !== undefined) log(`Using body timeout: ${bodyTimeoutMs === 0 ? 'disabled' : `${bodyTimeoutMs / 1000} seconds`}`)
  if (headersTimeoutMs !== undefined) {
    log(`Using headers timeout: ${headersTimeoutMs === 0 ? 'disabled' : `${headersTimeoutMs / 1000} seconds`}`)
  }

  const enableProxy = args.includes('--enable-proxy')
  if (enableProxy) {
    // Use env proxy
    setGlobalDispatcher(new EnvHttpProxyAgent(dispatcherOptions))
    log('HTTP proxy support enabled - using system HTTP_PROXY/HTTPS_PROXY environment variables')
  } else if (Object.keys(dispatcherOptions).length > 0) {
    setGlobalDispatcher(new Agent(dispatcherOptions))
  }

  // Keep-alive. `--ping-interval` implies `--keep-alive`, because an interval that silently does
  // nothing unless a second flag is also present is the more surprising reading of the two.
  const pingIntervalMs = parseSecondsOption(args, '--ping-interval')
  const keepAlive: KeepAliveConfig = {
    enabled: args.includes('--keep-alive') || pingIntervalMs !== undefined,
    intervalMs: pingIntervalMs ?? DEFAULT_KEEP_ALIVE_INTERVAL_MS,
  }

  // Parse transport strategy
  let transportStrategy: TransportStrategy = 'http-first' // Default
  const transportIndex = args.indexOf('--transport')
  if (transportIndex !== -1 && transportIndex < args.length - 1) {
    const strategy = args[transportIndex + 1]
    if (strategy === 'sse-only' || strategy === 'http-only' || strategy === 'sse-first' || strategy === 'http-first') {
      transportStrategy = strategy as TransportStrategy
      log(`Using transport strategy: ${transportStrategy}`)
    } else {
      log(`Warning: Ignoring invalid transport strategy: ${strategy}. Valid values are: sse-only, http-only, sse-first, http-first`)
    }
  }

  // Parse protocol mode
  let protocolMode: ProtocolMode = 'legacy'
  const protocolIndex = args.indexOf('--protocol')
  if (protocolIndex !== -1 && protocolIndex < args.length - 1) {
    const mode = args[protocolIndex + 1]
    if (mode === 'legacy' || mode === 'auto') {
      protocolMode = mode
      log(`Using protocol mode: ${protocolMode}`)
    } else {
      log(`Warning: Ignoring invalid protocol mode: ${mode}. Valid values are: legacy, auto`)
    }
  }

  // Parse host
  let host = process.platform === 'win32' ? '127.0.0.1' : 'localhost' // Default
  const hostIndex = args.indexOf('--host')
  if (hostIndex !== -1 && hostIndex < args.length - 1) {
    host = args[hostIndex + 1]
    log(`Using callback hostname: ${host}`)
  }

  // Parse callback path. It has to be a path Express can route and that does not shadow the
  // long-poll endpoint the coordination protocol between concurrent instances relies on,
  // otherwise the authorization server redirects back to an endpoint that never resolves.
  let callbackPath = DEFAULT_CALLBACK_PATH
  const callbackPathIndex = args.indexOf('--callback-path')
  if (callbackPathIndex !== -1 && callbackPathIndex < args.length - 1) {
    const value = args[callbackPathIndex + 1]
    if (!value.startsWith('/')) {
      log(`Warning: Ignoring invalid callback path: ${value}. It must start with '/'.`)
    } else if (value === LONG_POLL_PATH || value === MCP_REMOTE_ID_PATH) {
      log(`Warning: Ignoring reserved callback path: ${value}. It is used to coordinate concurrent instances.`)
    } else {
      callbackPath = value
      log(`Using callback path: ${callbackPath}`)
    }
  }

  let staticOAuthClientMetadata: StaticOAuthClientMetadata = null
  const staticOAuthClientMetadataIndex = args.indexOf('--static-oauth-client-metadata')
  if (staticOAuthClientMetadataIndex !== -1 && staticOAuthClientMetadataIndex < args.length - 1) {
    const staticOAuthClientMetadataArg = args[staticOAuthClientMetadataIndex + 1]
    if (staticOAuthClientMetadataArg.startsWith('@')) {
      const filePath = staticOAuthClientMetadataArg.slice(1)
      staticOAuthClientMetadata = JSON.parse(await readFile(filePath, 'utf8'))
      log(`Using static OAuth client metadata from file: ${filePath}`)
    } else {
      staticOAuthClientMetadata = JSON.parse(staticOAuthClientMetadataArg)
      log(`Using static OAuth client metadata from string`)
    }
  }

  // parse static OAuth client information, if provided
  // defaults to OAuth dynamic client registration
  let staticOAuthClientInfo: StaticOAuthClientInformationFull = null
  const staticOAuthClientInfoIndex = args.indexOf('--static-oauth-client-info')
  if (staticOAuthClientInfoIndex !== -1 && staticOAuthClientInfoIndex < args.length - 1) {
    const staticOAuthClientInfoArg = args[staticOAuthClientInfoIndex + 1]
    if (staticOAuthClientInfoArg.startsWith('@')) {
      const filePath = staticOAuthClientInfoArg.slice(1)
      staticOAuthClientInfo = parseJsonWithEnvVars(await readFile(filePath, 'utf8'), 'static OAuth client information')
      log(`Using static OAuth client information from file: ${filePath}`)
    } else {
      staticOAuthClientInfo = parseJsonWithEnvVars(staticOAuthClientInfoArg, 'static OAuth client information')
      log(`Using static OAuth client information from string`)
    }
  }

  // Parse the Client ID Metadata Document URL (SEP-991), used in place of dynamic registration
  let clientMetadataUrl: string | undefined
  const clientMetadataUrlIndex = args.indexOf('--client-metadata-url')
  if (clientMetadataUrlIndex !== -1 && clientMetadataUrlIndex < args.length - 1) {
    const value = args[clientMetadataUrlIndex + 1].trim()
    if (isClientMetadataUrl(value)) {
      clientMetadataUrl = value
      log(`Using client metadata document: ${value}`)
    } else {
      log(`Warning: Ignoring invalid client metadata URL: ${value}. It must be an HTTPS URL with a path.`)
    }
  }

  // Cookie-based session stickiness, on unless it is turned off
  if (args.includes('--disable-cookies')) {
    COOKIES_ENABLED = false
    log('Cookies disabled; requests will not carry session stickiness')
  }

  // No browser on this machine: sign in from wherever the person actually is
  const useDeviceCode = args.includes('--device-code')
  if (useDeviceCode) {
    log('Using the OAuth device grant; no browser will be opened on this machine')
  }

  // No person at all: the client is the one being authorized
  const useClientCredentials = args.includes('--client-credentials')
  if (useClientCredentials) {
    log('Using the OAuth client_credentials grant; no browser will be opened and no user will be asked')
  }

  // Both finish inside the provider's redirect step, so neither has a code arriving at a port
  NON_INTERACTIVE_FLOW = useDeviceCode || useClientCredentials

  // An MCP server that verifies who the caller is, rather than what they may do, wants the ID token
  const useIdToken = args.includes('--use-id-token')
  if (useIdToken) {
    log('Using the ID token as the bearer credential')
  }

  // Parse the RFC 8707 resource indicator, and whether to omit it entirely
  let authorizeResource: string | undefined
  let skipResourceParameter = args.includes('--disable-resource-parameter')

  const resourceIndex = args.indexOf('--resource')
  if (resourceIndex !== -1 && resourceIndex < args.length - 1) {
    const value = args[resourceIndex + 1].trim()
    if (value.length === 0) {
      // `--resource ""` is how people have been trying to switch this off
      skipResourceParameter = true
    } else {
      authorizeResource = value
    }
  }

  if (skipResourceParameter) {
    if (authorizeResource) {
      log(`Warning: --disable-resource-parameter overrides --resource ${authorizeResource}; the resource parameter will be omitted.`)
      // Cleared so it cannot silently split the credential cache - see getServerUrlHash
      authorizeResource = undefined
    }
    log('Resource parameter disabled - it will be omitted from authorization and token requests')
  } else if (authorizeResource) {
    try {
      new URL(authorizeResource)
    } catch {
      throw new Error(`Invalid --resource value: "${authorizeResource}". RFC 8707 requires an absolute URI, e.g. https://example.com/mcp`)
    }
    log(`Using authorize resource: ${authorizeResource}`)
  }

  const authorizeParams = parseAuthorizeParams(args)
  if (Object.keys(authorizeParams).length > 0) {
    log(`Using extra authorization parameters: ${Object.keys(authorizeParams).join(', ')}`)
  }

  // Parse ignored tools
  const ignoredTools: string[] = []
  let j = 0
  while (j < args.length) {
    if (args[j] === '--ignore-tool' && j < args.length - 1) {
      const toolName = args[j + 1]
      ignoredTools.push(toolName)
      log(`Ignoring tool: ${toolName}`)
      args.splice(j, 2)
      // Do not increment j, as the array has shifted
      continue
    }
    j++
  }

  // Parse auth timeout
  let authTimeoutMs = 30000 // Default 30 seconds
  const authTimeoutIndex = args.indexOf('--auth-timeout')
  if (authTimeoutIndex !== -1 && authTimeoutIndex < args.length - 1) {
    const timeoutSeconds = parseInt(args[authTimeoutIndex + 1], 10)
    if (!isNaN(timeoutSeconds) && timeoutSeconds > 0) {
      authTimeoutMs = timeoutSeconds * 1000
      log(`Using auth callback timeout: ${timeoutSeconds} seconds`)
    } else {
      log(`Warning: Ignoring invalid auth timeout value: ${args[authTimeoutIndex + 1]}. Must be a positive number.`)
    }
  }

  if (!serverUrl) {
    log(usage)
    process.exit(1)
  }

  const url = new URL(serverUrl)
  const isLocalhost = (url.hostname === 'localhost' || url.hostname === '127.0.0.1') && url.protocol === 'http:'

  if (!(url.protocol == 'https:' || isLocalhost || allowHttp)) {
    log('Error: Non-HTTPS URLs are only allowed for localhost or when --allow-http flag is provided')
    log(usage)
    process.exit(1)
  }
  // Calculate hash with all parsed parameters for cache isolation
  const serverUrlHash = getServerUrlHash(serverUrl, authorizeResource, headers, authorizeParams, clientMetadataUrl)

  // Set server hash globally for debug logging
  global.currentServerUrlHash = serverUrlHash

  debugLog(`Starting mcp-remote with server URL: ${serverUrl}`)

  const defaultPort = calculateDefaultPort(serverUrlHash)

  // Derived, never probed. `findAvailablePort` used to bind the port, close it, and hand back the
  // number - so concurrent instances could each be told the same port was free, or be pushed onto
  // random ones, before any coordination ran. Whether the port is actually free is settled by
  // binding it for real, in coordinateAuth, where losing tells us somebody else owns the flow.
  let callbackPort: number
  if (specifiedPort) {
    log(`Using specified callback port: ${specifiedPort}`)
    callbackPort = specifiedPort
  } else {
    log(`Using callback port derived from the server URL: ${defaultPort}`)
    callbackPort = defaultPort
  }

  // A cached dynamic client registration is only usable if it was registered with the exact
  // redirect_uri this run will send. If it wasn't, the authorization server rejects the
  // authorize request (RFC 6749 §3.1.2.4) and, because it refuses to redirect back, the user
  // sees an opaque error at the AS rather than anything actionable here. Worse, the callback
  // port is re-picked on each run, so it never self-heals. Dropping the registration lets the
  // next request re-register cleanly.
  //
  // Static client info is pinned by the user, so it is never discarded.
  if (!staticOAuthClientInfo) {
    await invalidateMismatchedClientRegistration(serverUrlHash, buildRedirectUrl(host, callbackPort, callbackPath))
  }

  if (Object.keys(headers).length > 0) {
    // Names only - values routinely carry bearer tokens and API keys, and this
    // goes to stderr, which MCP clients capture into their own logs.
    log(`Using custom headers: ${Object.keys(headers).join(', ')}`)
  }
  // Replace environment variables in headers
  // example `Authorization: Bearer ${TOKEN}` will read process.env.TOKEN
  for (const [key, value] of Object.entries(headers)) {
    headers[key] = substituteEnvVars(value, `header '${key}'`)
  }

  return {
    serverUrl,
    callbackPath,
    callbackPort,
    specifiedPort,
    headers,
    transportStrategy,
    host,
    debug,
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    clientMetadataUrl,
    useIdToken,
    useDeviceCode,
    useClientCredentials,
    authorizeResource,
    skipResourceParameter,
    authorizeParams,
    ignoredTools,
    authTimeoutMs,
    serverUrlHash,
    keepAlive,
    protocolMode,
  }
}

/**
 * Sets up signal handlers for graceful shutdown
 * @param cleanup Cleanup function to run on shutdown
 */
export function setupSignalHandlers(cleanup: () => Promise<void>) {
  process.on('SIGINT', async () => {
    log('\nShutting down...')
    await cleanup()
    process.exit(0)
  })

  // Keep the process alive
  process.stdin.resume()
  process.stdin.on('end', async () => {
    log('\nShutting down...')
    await cleanup()
    process.exit(0)
  })
}

/**
 * Generates a hash for the server URL configuration
 * Includes resource and headers to isolate OAuth sessions per unique
 * server configuration (fixes #25: multi-instance support)
 * @param serverUrl The server URL
 * @param authorizeResource Optional resource parameter for OAuth
 * @param headers Optional custom headers
 * @param authorizeParams Optional extra authorization parameters
 * @param clientMetadataUrl Optional Client ID Metadata Document URL used as the client_id
 * @returns MD5 hash of the configuration
 */
export function getServerUrlHash(
  serverUrl: string,
  authorizeResource?: string,
  headers?: Record<string, string>,
  authorizeParams?: Record<string, string>,
  clientMetadataUrl?: string,
): string {
  // Include resource and headers in hash to isolate OAuth sessions
  // per unique server configuration (fixes #25)
  const parts = [serverUrl]
  if (authorizeResource) parts.push(authorizeResource)
  // Authorize params belong here for the same reason: `audience` decides which API the token is
  // for, and `access_type` decides whether a refresh token comes back at all. Reusing one set of
  // credentials across two of those is how you get a token that silently does not work.
  if (authorizeParams && Object.keys(authorizeParams).length > 0) {
    const sorted = Object.keys(authorizeParams).sort()
    parts.push(JSON.stringify(authorizeParams, sorted))
  }
  if (headers && Object.keys(headers).length > 0) {
    const sortedKeys = Object.keys(headers).sort()
    parts.push(JSON.stringify(headers, sortedKeys))
  }
  // And so does the client id, when it comes from a metadata document rather than a registration.
  // A refresh token is bound to the client that obtained it, so tokens from a dynamic registration
  // cannot be refreshed once this client starts identifying itself by a URL instead.
  if (clientMetadataUrl) parts.push(clientMetadataUrl)
  return crypto.createHash('md5').update(parts.join('|')).digest('hex')
}

/**
 * Converts a glob pattern to a regular expression
 * @param pattern The glob pattern (e.g., "create*", "*account")
 * @returns The corresponding regular expression
 */
function patternToRegex(pattern: string): RegExp {
  // Split by asterisks, escape each part, then join with .*
  const parts = pattern.split('*')
  const escapedParts = parts.map((part) => part.replace(/\W/g, '\\$&'))
  const regexPattern = escapedParts.join('.*')
  // Match the entire string from start to end, case-insensitive
  return new RegExp(`^${regexPattern}$`, 'i')
}

/**
 * Determines if a tool name should be ignored based on ignore patterns
 * @param ignorePatterns Array of patterns to ignore (supports wildcards with *)
 * @param toolName The name of the tool to check
 * @returns false if the tool should be ignored (matches a pattern), true if it should be included
 */
export function shouldIncludeTool(ignorePatterns: string[], toolName: string): boolean {
  // If no patterns are provided, include all tools
  if (!ignorePatterns || ignorePatterns.length === 0) {
    return true
  }

  // Check if the tool name matches any ignore pattern
  for (const pattern of ignorePatterns) {
    const regex = patternToRegex(pattern)
    if (regex.test(toolName)) {
      return false // Tool matches an ignore pattern, so exclude it
    }
  }

  return true // Tool doesn't match any ignore pattern, so include it
}
