#!/usr/bin/env node

/**
 * MCP Client with OAuth support
 * A command-line client that connects to an MCP server using SSE with OAuth authentication.
 *
 * Run with: npx tsx client.ts https://example.remote/server [callback-port]
 *
 * If callback-port is not specified, an available port will be automatically selected.
 */

import { EventEmitter } from 'events'
import { Client } from '@modelcontextprotocol/client'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
import {
  parseCommandLineArgs,
  setupSignalHandlers,
  log,
  debugLog,
  MCP_REMOTE_VERSION,
  connectToRemoteServer,
  TransportStrategy,
  discoverOAuthServerInfo,
} from './lib/utils'
import { StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './lib/types'
import { createLazyAuthCoordinator, hasUsableTokens, serverIssuesAuthChallenge } from './lib/coordination'
import { attachClientDiagnostics } from './lib/client-diagnostics'

/**
 * Main function to run the client
 */
async function runClient(
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
  tokenEndpoint: string | undefined,
  authorizeResource: string | undefined,
  skipResourceParameter: boolean,
  authorizeParams: Record<string, string>,
  authTimeoutMs: number,
  serverUrlHash: string,
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
  const discoveryResult = await discoverOAuthServerInfo(serverUrl, headers, tokenEndpoint)

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
    clientName: 'MCP CLI Client',
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    clientMetadataUrl,
    useIdToken,
    useDeviceCode,
    useClientCredentials,
    tokenEndpoint,
    authorizeResource,
    skipResourceParameter,
    authorizeParams,
    serverUrlHash,
    authorizationServerMetadata: discoveryResult.authorizationServerMetadata,
    protectedResourceMetadata: discoveryResult.protectedResourceMetadata,
    wwwAuthenticateScope: discoveryResult.wwwAuthenticateScope,
  })

  // Create the client
  const client = new Client(
    {
      name: 'mcp-remote',
      version: MCP_REMOTE_VERSION,
    },
    {
      capabilities: {},
    },
  )

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
  if (!useDeviceCode && !(await hasUsableTokens(serverUrlHash)) && (await serverIssuesAuthChallenge(serverUrl, headers))) {
    await authInitializer()
  }

  try {
    // Connect to remote server with lazy authentication
    const transport = await connectToRemoteServer(client, serverUrl, authProvider, headers, authInitializer, transportStrategy)

    // Log what arrives without displacing the dispatcher client.connect() installed
    attachClientDiagnostics(client, transport, () => process.exit(0))

    // Set up cleanup handler
    const cleanup = async () => {
      log('\nClosing connection...')
      await client.close()
      // If auth was initialized and server was created, close it
      if (server) {
        server.close()
      }
    }
    setupSignalHandlers(cleanup)

    log('Connected successfully!')

    try {
      // Request tools list
      log('Requesting tools list...')
      const tools = await client.request({ method: 'tools/list' })
      log('Tools:', JSON.stringify(tools, null, 2))
    } catch (e) {
      log('Error requesting tools list:', e)
    }

    try {
      // Request resources list
      log('Requesting resource list...')
      const resources = await client.request({ method: 'resources/list' })
      log('Resources:', JSON.stringify(resources, null, 2))
    } catch (e) {
      log('Error requesting resources list:', e)
    }

    // log('Listening for messages. Press Ctrl+C to exit.')
    log('Exiting OK...')
    // Only close the server if it was initialized
    if (server) {
      server.close()
    }
    process.exit(0)
  } catch (error) {
    log('Fatal error:', error)
    // Only close the server if it was initialized
    if (server) {
      server.close()
    }
    process.exit(1)
  }
}

// Parse command-line arguments and run the client
parseCommandLineArgs(process.argv.slice(2), 'Usage: mcp-remote-client <https://server-url> [callback-port] [--debug]')
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
      tokenEndpoint,
      authorizeResource,
      skipResourceParameter,
      authorizeParams,
      authTimeoutMs,
      serverUrlHash,
    }) => {
      return runClient(
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
        tokenEndpoint,
        authorizeResource,
        skipResourceParameter,
        authorizeParams,
        authTimeoutMs,
        serverUrlHash,
      )
    },
  )
  .catch((error) => {
    console.error('Fatal error:', error)
    process.exit(1)
  })
