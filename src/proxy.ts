#!/usr/bin/env node

/**
 * MCP Proxy with OAuth support
 * A bidirectional proxy between a local STDIO MCP server and a remote SSE server with OAuth authentication.
 *
 * Run with: npx tsx proxy.ts https://example.remote/server [callback-port]
 *
 * If callback-port is not specified, an available port will be automatically selected.
 */

import { EventEmitter } from 'events'
import type { Transport } from '@modelcontextprotocol/client'
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio'
import {
  connectToRemoteServer,
  log,
  debugLog,
  mcpProxy,
  parseCommandLineArgs,
  setupSignalHandlers,
  TransportStrategy,
  discoverOAuthServerInfo,
  forgetRejectedAuthorization,
} from './lib/utils'
import { KeepAliveConfig, StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './lib/types'
import type { ProtocolMode } from './lib/protocol-era'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
import { createLazyAuthCoordinator, hasUsableTokens, serverIssuesAuthChallenge } from './lib/coordination'

/** A transport that can redeem an authorization code, which the `Transport` interface does not promise. */
type AuthCompletable = Transport & { finishAuth: (code: string, iss?: string) => Promise<void> }

const canFinishAuth = (transport: Transport): transport is AuthCompletable =>
  typeof (transport as Partial<AuthCompletable>).finishAuth === 'function'

/**
 * Main function to run the proxy
 */
async function runProxy(
  serverUrl: string,
  callbackPath: string,
  callbackPort: number,
  specifiedPort: number | undefined,
  headers: Record<string, string>,
  transportStrategy: TransportStrategy = 'http-first',
  host: string,
  staticOAuthClientMetadata: StaticOAuthClientMetadata,
  staticOAuthClientInfo: StaticOAuthClientInformationFull,
  clientMetadataUrl: string | undefined,
  useIdToken: boolean,
  useDeviceCode: boolean,
  useClientCredentials: boolean,
  authorizeResource: string | undefined,
  skipResourceParameter: boolean,
  authorizeParams: Record<string, string>,
  ignoredTools: string[],
  authTimeoutMs: number,
  serverUrlHash: string,
  keepAlive: KeepAliveConfig,
  protocolMode: ProtocolMode,
) {
  // Set up event emitter for auth flow
  const events = new EventEmitter()

  // A redirect_uri pinned outside this process - by a static registration, or by the redirect_uris
  // in a client metadata document - stops being valid the moment we wander onto another port.
  const strictPort = !!specifiedPort || !!staticOAuthClientInfo || !!clientMetadataUrl

  // Create a lazy auth coordinator
  const authCoordinator = createLazyAuthCoordinator(serverUrlHash, callbackPath, callbackPort, events, authTimeoutMs, strictPort)

  // Discover OAuth server info via Protected Resource Metadata (RFC 9728)
  // This probes the MCP server for WWW-Authenticate header and fetches PRM
  log('Discovering OAuth server configuration...')
  const discoveryResult = await discoverOAuthServerInfo(serverUrl, headers)

  if (discoveryResult.protectedResourceMetadata) {
    log(`Discovered authorization server: ${discoveryResult.authorizationServerUrl}`)
    if (discoveryResult.protectedResourceMetadata.scopes_supported) {
      debugLog('Protected Resource Metadata scopes', {
        scopes_supported: discoveryResult.protectedResourceMetadata.scopes_supported,
      })
    }
  } else {
    debugLog('No Protected Resource Metadata found, using server URL as authorization server')
  }

  // Create the OAuth client provider with discovered server info
  const authProvider = new NodeOAuthClientProvider({
    serverUrl: discoveryResult.authorizationServerUrl,
    resourceServerUrl: serverUrl,
    callbackPath,
    callbackPort,
    host,
    clientName: 'MCP CLI Proxy',
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    clientMetadataUrl,
    useIdToken,
    useDeviceCode,
    useClientCredentials,
    authorizeResource,
    skipResourceParameter,
    authorizeParams,
    serverUrlHash,
    authorizationServerMetadata: discoveryResult.authorizationServerMetadata,
    protectedResourceMetadata: discoveryResult.protectedResourceMetadata,
    wwwAuthenticateScope: discoveryResult.wwwAuthenticateScope,
  })

  // Create the STDIO transport for local connections
  const localTransport = new StdioServerTransport()

  // Keep track of the server instance for cleanup
  let server: any = null

  // Define an auth initializer function
  const authInitializer = async (options?: { forceRefresh?: boolean }) => {
    const authState = await authCoordinator.initializeAuth(options)

    // Store server in outer scope for cleanup
    server = authState.server

    // A stranger on an earlier candidate can push us onto a later port than the one the startup
    // check compared the cached registration against, so a stale registration can still name the
    // wrong redirect_uri here. Invalidating unconditionally is not the answer - this runs again on
    // the post-auth reconnect, and deleting the registration then breaks the code exchange.
    if (authState.actualPort !== callbackPort) {
      log(`Using callback port ${authState.actualPort}`)
      authProvider.setCallbackPort(authState.actualPort)
    }

    return {
      waitForAuthCode: authState.waitForAuthCode,
      skipBrowserAuth: authState.skipBrowserAuth,
    }
  }

  // Ownership is settled before the first connection attempt, not after a 401. The SDK builds the
  // authorize URL and registers a client from inside `transport.start()`, so an instance that only
  // discovered it was a follower afterwards would already have registered its own client and
  // issued its own PKCE challenge - which is what produced one registration and one tab per
  // instance. Skipped when tokens are already on disk, so a warm start still binds nothing - and
  // skipped entirely under the device grant, which has no callback port to contend over.
  const signsInWithoutACallbackPort = useDeviceCode || useClientCredentials
  if (!signsInWithoutACallbackPort && !(await hasUsableTokens(serverUrlHash)) && (await serverIssuesAuthChallenge(serverUrl, headers))) {
    await authInitializer()
  }

  try {
    // Connect to remote server with lazy authentication
    const remoteTransport = await connectToRemoteServer(
      null,
      serverUrl,
      authProvider,
      headers,
      authInitializer,
      transportStrategy,
      protocolMode,
    )

    // Set up bidirectional proxy between local and remote transports
    mcpProxy({
      transportToClient: localTransport,
      transportToServer: remoteTransport,
      ignoredTools,
      keepAlive,
      protocolMode,
      /**
       * Discards a token the server refused straight after issuing it.
       *
       * Clearing it is what turns the next attempt back into an ordinary 401, which `reauthorize`
       * below can actually answer. Left alone, the same dead credential is read back from disk and
       * presented again, so the failure repeats on every run.
       */
      forgetRejectedAuthorization: () => forgetRejectedAuthorization(authProvider),

      /**
       * Finishes a sign-in the remote server asked for mid-session.
       *
       * Startup is not the only time a server can demand one: tokens get revoked, refresh tokens
       * lapse, and a server may leave `initialize` public while protecting a tool. Until now those
       * all ended the same way - the SDK opened a browser, nothing was listening on the callback
       * port, and the code was dropped on the floor.
       */
      reauthorize: async () => {
        // A grant that needs no browser has already finished inside the SDK's redirect step, which
        // ran it to completion and wrote the tokens. The retry finds them; there is no code to wait
        // for and no port to wait on.
        if (signsInWithoutACallbackPort) {
          log('Signed in without a browser; retrying with the tokens it produced')
          return
        }

        const { waitForAuthCode, skipBrowserAuth } = await authInitializer()

        // Another instance is running the flow; it will write the tokens and the retry will pick
        // them up. Waiting for a code of our own here would wait for one nobody will deliver.
        if (skipBrowserAuth) {
          log('Another instance is completing the sign-in; retrying with the tokens it writes')
          return
        }

        const { code, state, iss } = await waitForAuthCode()
        // The code may belong to a flow another instance started, whose verifier is not this one's
        if (state) authProvider.useAuthorizationState(state)

        // Both transports this proxy can be given have it; the interface they share does not
        if (!canFinishAuth(remoteTransport)) {
          throw new Error(`${remoteTransport.constructor.name} cannot complete an authorization`)
        }
        await remoteTransport.finishAuth(code, iss)
        log('Re-authorized with the remote server')
      },
    })

    // Start the local STDIO server
    await localTransport.start()
    log('Local STDIO server running')
    log(`Proxy established successfully between local STDIO and remote ${remoteTransport.constructor.name}`)
    log('Press Ctrl+C to exit')

    // Setup cleanup handler
    const cleanup = async () => {
      await remoteTransport.close()
      await localTransport.close()
      // Only close the server if it was initialized
      if (server) {
        server.close()
      }
    }
    setupSignalHandlers(cleanup)
  } catch (error) {
    log('Fatal error:', error)
    if (error instanceof Error && error.message.includes('self-signed certificate in certificate chain')) {
      log(`You may be behind a VPN!

If you are behind a VPN, you can try setting the NODE_EXTRA_CA_CERTS environment variable to point
to the CA certificate file. If using claude_desktop_config.json, this might look like:

{
  "mcpServers": {
    "\${mcpServerName}": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "\${your CA certificate file path}.pem"
      }
    }
  }
}
        `)
    }
    // Only close the server if it was initialized
    if (server) {
      server.close()
    }
    process.exit(1)
  }
}

// Parse command-line arguments and run the proxy
parseCommandLineArgs(process.argv.slice(2), 'Usage: mcp-remote <https://server-url> [callback-port] [--debug]')
  .then(
    ({
      serverUrl,
      callbackPath,
      callbackPort,
      specifiedPort,
      headers,
      transportStrategy,
      host,
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
    }) => {
      return runProxy(
        serverUrl,
        callbackPath,
        callbackPort,
        specifiedPort,
        headers,
        transportStrategy,
        host,
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
      )
    },
  )
  .catch((error) => {
    log('Fatal error:', error)
    process.exit(1)
  })
