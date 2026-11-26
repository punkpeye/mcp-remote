import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EventEmitter } from 'node:events'
import { createHash } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import net from 'node:net'
import { StreamableHTTPClientTransport, type Transport } from '@modelcontextprotocol/client'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import { createLazyAuthCoordinator } from './coordination'
import { mcpProxy } from './utils'
import { writeJsonFile } from './mcp-auth-config'

/**
 * Stands in for a browser: it follows the URL the moment it is opened, as a browser on the same
 * machine does. That is the whole point - the callback server has to exist by then.
 */
const browser = vi.hoisted(() => ({ follow: vi.fn() }))
vi.mock('./open-browser', () => ({
  openBrowser: async (url: string) => {
    await browser.follow(url)
    return true
  },
}))

const serverUrl = 'https://mcp.example.test/mcp'
const resourceMetadataUrl = 'https://mcp.example.test/.well-known/oauth-protected-resource/mcp'
const issuer = 'https://auth.example.test'
const tokenEndpoint = issuer + '/token'
const serverUrlHash = 'mid-session-401-test'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

class FakeOAuthServer {
  /** Access tokens the MCP server accepts. Ending the sessions empties it. */
  validAccessTokens = new Set(['at-1'])
  codes = new Map<string, { challenge: string | null }>()
  issued = 1
  /** What the equivalent of a user's browser saw when it landed on the callback. */
  browserResult: { callbackStatus?: number; refused?: boolean } | undefined

  endSessions() {
    this.validAccessTokens.clear()
  }

  fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init)
    const url = request.url

    if (url === resourceMetadataUrl) return json(200, { resource: serverUrl, authorization_servers: [issuer] })
    if (url === issuer + '/.well-known/oauth-authorization-server') {
      return json(200, {
        issuer,
        authorization_endpoint: issuer + '/authorize',
        token_endpoint: tokenEndpoint,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['none'],
        code_challenge_methods_supported: ['S256'],
      })
    }
    if (url.startsWith(issuer + '/authorize')) {
      const authorizationUrl = new URL(url)
      const code = 'code-' + ++this.issued
      this.codes.set(code, { challenge: authorizationUrl.searchParams.get('code_challenge') })
      const redirect = new URL(authorizationUrl.searchParams.get('redirect_uri')!)
      redirect.searchParams.set('code', code)
      const state = authorizationUrl.searchParams.get('state')
      if (state) redirect.searchParams.set('state', state)
      return new Response(null, { status: 302, headers: { location: redirect.toString() } })
    }
    if (url === tokenEndpoint) {
      const body = new URLSearchParams(await request.text())
      const grant = body.get('grant_type')
      if (grant === 'refresh_token') {
        // The sign-in was revoked, so nothing on disk can be renewed
        return json(400, { error: 'invalid_grant', error_description: 'the sign-in was ended' })
      }
      if (grant === 'authorization_code') {
        const record = this.codes.get(body.get('code') ?? '')
        if (!record) return json(400, { error: 'invalid_grant', error_description: 'unknown code' })
        const verifier = body.get('code_verifier') ?? ''
        const challenge = createHash('sha256').update(verifier).digest('base64url')
        if (record.challenge !== challenge) return json(400, { error: 'invalid_grant', error_description: 'pkce mismatch' })
        this.issued++
        const access = 'at-' + this.issued
        this.validAccessTokens.add(access)
        return json(200, { access_token: access, refresh_token: 'rt-' + this.issued, token_type: 'Bearer', expires_in: 3600 })
      }
      return json(400, { error: 'unsupported_grant_type' })
    }
    if (url === serverUrl) {
      if (request.method !== 'POST') return new Response(null, { status: 405 })
      const message = (await request.json()) as { id?: number; method: string }
      const bearer = request.headers.get('authorization')?.replace(/^Bearer /, '')
      if (!bearer || !this.validAccessTokens.has(bearer)) {
        return new Response(JSON.stringify({ error: 'invalid_token' }), {
          status: 401,
          headers: {
            'content-type': 'application/json',
            'www-authenticate': 'Bearer error="invalid_token", resource_metadata="' + resourceMetadataUrl + '"',
          },
        })
      }
      if (message.id === undefined) return new Response(null, { status: 202 })
      return json(200, { jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'text', text: 'ok' }] } })
    }
    return new Response(null, { status: 404 })
  }
}

const freePort = async () =>
  await new Promise<number>((resolve) => {
    const server = net.createServer()
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as net.AddressInfo).port
      server.close(() => resolve(port))
    })
  })

describe('Feature: A 401 on a mid-session request', () => {
  let configDir: string
  let server: FakeOAuthServer
  let provider: NodeOAuthClientProvider
  let coordinator: ReturnType<typeof createLazyAuthCoordinator>
  let transport: StreamableHTTPClientTransport
  let clientTransport: Transport
  let sendToClient: ReturnType<typeof vi.fn>

  beforeEach(async () => {
    configDir = await mkdtemp(join(tmpdir(), 'mcp-remote-mid-session-'))
    vi.stubEnv('MCP_REMOTE_CONFIG_DIR', configDir)
    server = new FakeOAuthServer()

    // Signed in before this test began: a token the MCP server takes until the sessions end
    await writeJsonFile(serverUrlHash, 'tokens.json', {
      access_token: 'at-1',
      refresh_token: 'rt-1',
      token_type: 'Bearer',
      expires_in: 3600,
      expires_at: Date.now() + 3_600_000,
      issuer,
    })

    const callbackPort = await freePort()
    coordinator = createLazyAuthCoordinator(serverUrlHash, '/oauth/callback', callbackPort, new EventEmitter(), 2000, true)
    provider = new NodeOAuthClientProvider({
      serverUrl,
      resourceServerUrl: serverUrl,
      serverUrlHash,
      callbackPath: '/oauth/callback',
      callbackPort,
      host: '127.0.0.1',
      staticOAuthClientInfo: {
        client_id: 'static-client',
        redirect_uris: ['http://127.0.0.1:' + callbackPort + '/oauth/callback'],
        token_endpoint_auth_method: 'none',
      },
      // The wiring proxy.ts and client.ts supply: the listener exists before the browser is sent
      ensureCallbackServer: async () => {
        const authState = await coordinator.initializeAuth()
        if (authState.actualPort !== callbackPort) provider.setCallbackPort(authState.actualPort)
        return { skipBrowserAuth: authState.skipBrowserAuth }
      },
    })

    browser.follow.mockImplementation(async (url: string) => {
      const authorized = await server.fetch(url, { redirect: 'manual' })
      const location = authorized.headers.get('location')!
      try {
        const callback = await fetch(location)
        server.browserResult = { callbackStatus: callback.status }
      } catch {
        server.browserResult = { refused: true }
      }
    })

    // The same fetch wiring connectToRemoteServer uses: the provider has to see the token endpoint
    // refuse the refresh, so the discarded credential is the one that was actually refused
    transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
      authProvider: provider,
      fetch: provider.coordinateTokenRequests(server.fetch),
    })
    await transport.start()

    sendToClient = vi.fn().mockResolvedValue(undefined)
    clientTransport = {
      send: sendToClient,
      start: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
    } as unknown as Transport

    // What proxy.ts supplies to mcpProxy: finish the flow the SDK started, with the code the
    // callback server received
    const reauthorize = async () => {
      const authState = await coordinator.initializeAuth()
      if (authState.skipBrowserAuth) return
      const { code, state } = await authState.waitForAuthCode()
      if (state) provider.useAuthorizationState(state)
      await transport.finishAuth(code)
    }
    mcpProxy({ transportToClient: clientTransport, transportToServer: transport, reauthorize })
  })

  afterEach(async () => {
    await transport.close()
    await coordinator.release()
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    await rm(configDir, { recursive: true, force: true })
  })

  it('Scenario: the first refused request completes its sign-in instead of waiting for a lost code', async () => {
    // Given a server that ends every session, as a revoked sign-in would
    server.endSessions()

    // When the client sends a request
    clientTransport.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } } as never)

    // Then the request is answered once the browser has signed in - it is not left waiting for a
    // code that the browser dropped on a port nothing was listening to
    await vi.waitFor(() => expect(sendToClient).toHaveBeenCalled(), { timeout: 5000 })
    expect(sendToClient).toHaveBeenCalledWith(
      expect.objectContaining({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'ok' }] } }),
    )

    // And the browser's trip to the callback was served, not refused
    expect(server.browserResult).toEqual({ callbackStatus: 200 })
  })
})
