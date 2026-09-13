import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import { getConfigFilePath, writeJsonFile } from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'

vi.mock('open', () => ({ default: vi.fn(() => Promise.reject(new Error('Browser auth must not run'))) }))
vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
  MCP_REMOTE_VERSION: 'test',
  buildRedirectUrl: (host: string, port: number, path: string) => `http://${host}:${port}${path}`,
}))

const serverUrl = 'https://mcp.example.test/mcp'
const tokenEndpoint = 'https://identity.example.test/oauth2/v1/token'
const serverUrlHash = 'explicit-client-credentials-test'
const tool = { name: 'mcp_search', description: 'Search records', inputSchema: { type: 'object' as const } }
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

/** Exercises the real SDK's auth discovery and retry logic, mocking only HTTP and browser launch. */
class TestNetwork {
  tokenRequests: Array<{ headers: Headers; params: URLSearchParams }> = []
  mcpRequests: Array<{ method: string; bearer: string | null }> = []
  discoveryRequests: string[] = []
  acceptedToken = 'issued-1'
  challengeMetadataUrl?: string
  challengeScope?: string
  rejectAllTokens = false
  tokenFailure = false

  fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init)
    if (request.url === tokenEndpoint) {
      this.tokenRequests.push({ headers: request.headers, params: new URLSearchParams(await request.text()) })
      if (this.tokenFailure) return json(400, { error: 'invalid_client', error_description: 'Client credentials rejected' })
      const accessToken = `issued-${this.tokenRequests.length}`
      this.acceptedToken = accessToken
      return json(200, { access_token: accessToken, token_type: 'Bearer', expires_in: 3600 })
    }
    if (request.url !== serverUrl) {
      this.discoveryRequests.push(request.url)
      if (new URL(request.url).pathname === '/login') {
        return new Response('<html>Enterprise sign-in</html>', { headers: { 'content-type': 'text/html' } })
      }
      return new Response(null, { status: 302, headers: { location: 'https://mcp.example.test/login' } })
    }
    if (request.method === 'GET') return new Response(null, { status: 405 })
    const message = (await request.json()) as { id?: number; method: string }
    const bearer = request.headers.get('authorization')
    this.mcpRequests.push({ method: message.method, bearer })
    if (this.rejectAllTokens || bearer !== `Bearer ${this.acceptedToken}`) {
      const challenge = ['realm="MCP"']
      if (this.challengeMetadataUrl) challenge.push(`resource_metadata="${this.challengeMetadataUrl}"`)
      if (this.challengeScope) challenge.push(`scope="${this.challengeScope}"`)
      return new Response('Token required', {
        status: 401,
        headers: { 'www-authenticate': `Bearer ${challenge.join(', ')}` },
      })
    }
    if (message.id === undefined) return new Response(null, { status: 202 })
    const result =
      message.method === 'initialize'
        ? { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'mcp-simulator', version: '1' } }
        : { tools: [tool] }
    return json(200, { jsonrpc: '2.0', id: message.id, result })
  }
}

describe('Explicit client credentials with an MCP server behind enterprise discovery redirects', () => {
  let configDir: string
  let network: TestNetwork
  const clients: Client[] = []

  beforeEach(async () => {
    configDir = await mkdtemp(join(tmpdir(), 'mcp-remote-explicit-'))
    vi.stubEnv('MCP_REMOTE_CONFIG_DIR', configDir)
    network = new TestNetwork()
    vi.stubGlobal('fetch', network.fetch)
  })

  afterEach(async () => {
    await Promise.all(clients.splice(0).map((client) => client.close()))
    vi.unstubAllGlobals()
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    await rm(configDir, { recursive: true, force: true })
  })

  function provider(overrides: Partial<OAuthProviderOptions> = {}) {
    return new NodeOAuthClientProvider({
      serverUrl,
      tokenEndpoint,
      serverUrlHash,
      host: 'localhost',
      callbackPort: 0,
      useClientCredentials: true,
      staticOAuthClientInfo: { client_id: 'machine-client', client_secret: 'test-secret', redirect_uris: [] },
      ...overrides,
    })
  }

  async function connect(authProvider: NodeOAuthClientProvider) {
    const client = new Client({ name: 'explicit-auth-regression', version: '1' }, { capabilities: {} })
    clients.push(client)
    await client.connect(new StreamableHTTPClientTransport(new URL(serverUrl), { authProvider }), { timeout: 2000 })
    return client
  }

  it('initializes and lists tools from a cold cache without any discovery or browser authorization', async () => {
    const authProvider = provider()
    const redirect = vi.spyOn(authProvider, 'redirectToAuthorization')
    const client = await connect(authProvider)

    expect((await client.listTools()).tools).toEqual([tool])
    expect(network.tokenRequests).toHaveLength(1)
    expect(network.discoveryRequests).toEqual([])
    expect(redirect).not.toHaveBeenCalled()
    expect(network.mcpRequests.filter((request) => request.method === 'initialize')).toEqual([
      { method: 'initialize', bearer: null },
      { method: 'initialize', bearer: 'Bearer issued-1' },
    ])
    const cached = JSON.parse(await readFile(getConfigFilePath(serverUrlHash, 'tokens.json'), 'utf8'))
    expect(cached).toMatchObject({ access_token: 'issued-1' })
    expect(cached.expires_at).toBeGreaterThan(Date.now())
    expect(cached.refresh_token).toBeUndefined()
  })

  it('replaces a rejected, unexpired cached token and retries initialize', async () => {
    await writeJsonFile(serverUrlHash, 'tokens.json', {
      access_token: 'stale-token',
      token_type: 'Bearer',
      expires_in: 3600,
      expires_at: Date.now() + 3600000,
    })

    const client = await connect(provider())

    expect((await client.listTools()).tools).toEqual([tool])
    expect(network.tokenRequests).toHaveLength(1)
    expect(network.mcpRequests.filter((request) => request.method === 'initialize').map((request) => request.bearer)).toEqual([
      'Bearer stale-token',
      'Bearer issued-1',
    ])
    expect(network.discoveryRequests).toEqual([])
  })

  it('reacquires a token and retries tools/list after authorization expires on the server', async () => {
    const client = await connect(provider())
    network.acceptedToken = 'revoked'
    network.challengeMetadataUrl = 'https://different-identity.example.test/.well-known/oauth-protected-resource'

    expect((await client.listTools()).tools).toEqual([tool])
    expect(network.tokenRequests).toHaveLength(2)
    expect(network.mcpRequests.filter((request) => request.method === 'tools/list').map((request) => request.bearer)).toEqual([
      'Bearer issued-1',
      'Bearer issued-2',
    ])
    expect(network.discoveryRequests).toEqual([])
  })

  it('renews an expired token before tools/list on an already initialized transport', async () => {
    const client = await connect(provider())
    const cached = JSON.parse(await readFile(getConfigFilePath(serverUrlHash, 'tokens.json'), 'utf8'))
    await writeJsonFile(serverUrlHash, 'tokens.json', { ...cached, expires_at: Date.now() - 1000 })

    expect((await client.listTools()).tools).toEqual([tool])

    expect(network.tokenRequests).toHaveLength(2)
    expect(network.mcpRequests.filter((request) => request.method === 'tools/list')).toEqual([
      { method: 'tools/list', bearer: 'Bearer issued-2' },
    ])
    expect(network.discoveryRequests).toEqual([])
  })

  it('renews an expired cached token without a refresh token before sending it, sharing concurrent renewal', async () => {
    await writeJsonFile(serverUrlHash, 'tokens.json', {
      access_token: 'expired',
      token_type: 'Bearer',
      expires_in: 3600,
      expires_at: Date.now() - 1000,
    })
    const authProvider = provider()

    const tokens = await Promise.all([authProvider.tokens(), authProvider.tokens(), authProvider.tokens()])

    expect(tokens.map((token) => token?.access_token)).toEqual(['issued-1', 'issued-1', 'issued-1'])
    expect(network.tokenRequests).toHaveLength(1)
    expect(network.tokenRequests[0].params.get('grant_type')).toBe('client_credentials')
    const client = await connect(authProvider)
    expect((await client.listTools()).tools).toEqual([tool])
    expect(network.mcpRequests.every((request) => request.bearer === 'Bearer issued-1')).toBe(true)
    expect(network.discoveryRequests).toEqual([])
  })

  it.each([
    {
      authMethod: 'client_secret_basic',
      authorization: `Basic ${Buffer.from('machine-client:test-secret').toString('base64')}`,
      clientId: null,
      clientSecret: null,
    },
    { authMethod: 'client_secret_post', authorization: null, clientId: 'machine-client', clientSecret: 'test-secret' },
  ])(
    'uses metadata $authMethod authentication over a conflicting client info method',
    async ({ authMethod, authorization, clientId, clientSecret }) => {
      await connect(
        provider({
          staticOAuthClientInfo: {
            client_id: 'machine-client',
            client_secret: 'test-secret',
            redirect_uris: [],
            token_endpoint_auth_method: authMethod === 'client_secret_basic' ? 'client_secret_post' : 'client_secret_basic',
          },
          staticOAuthClientMetadata: { redirect_uris: [], token_endpoint_auth_method: authMethod },
        }),
      )

      const { headers, params } = network.tokenRequests[0]
      expect(params.get('grant_type')).toBe('client_credentials')
      expect(params.has('scope')).toBe(false)
      // An explicit token endpoint does not advertise RFC 8707 support on the MCP server's behalf.
      expect(params.has('resource')).toBe(false)
      expect(headers.get('authorization')).toBe(authorization)
      expect(params.get('client_id')).toBe(clientId)
      expect(params.get('client_secret')).toBe(clientSecret)
    },
  )

  it.each([false, true])('preserves explicit scope and honors resource omission=%s', async (skipResourceParameter) => {
    await connect(
      provider({
        staticOAuthClientMetadata: { redirect_uris: [], scope: 'mcp.read' },
        authorizeResource: 'https://mcp.example.test/api',
        skipResourceParameter,
      }),
    )

    expect(network.tokenRequests[0].params.get('scope')).toBe('mcp.read')
    expect(network.tokenRequests[0].params.get('resource')).toBe(skipResourceParameter ? null : 'https://mcp.example.test/api')
    expect(network.discoveryRequests).toEqual([])
  })

  it('preserves the configured scope when a 401 challenge requests a conflicting scope', async () => {
    network.challengeScope = 'mcp.admin'
    const client = await connect(provider({ staticOAuthClientMetadata: { redirect_uris: [], scope: 'mcp.read' } }))
    network.acceptedToken = 'revoked'
    network.challengeScope = 'mcp.write'

    expect((await client.listTools()).tools).toEqual([tool])

    expect(network.tokenRequests.map((request) => request.params.get('scope'))).toEqual(['mcp.read', 'mcp.read'])
    expect(network.discoveryRequests).toEqual([])
  })

  it('retains a challenge scope across expiry and restart when the token response omits scope', async () => {
    network.challengeScope = 'mcp.read'
    const client = await connect(provider())
    const cachePath = getConfigFilePath(serverUrlHash, 'tokens.json')
    let cached = JSON.parse(await readFile(cachePath, 'utf8'))
    expect(cached.scope).toBeUndefined()
    expect(cached.requested_scope).toBe('mcp.read')
    await writeJsonFile(serverUrlHash, 'tokens.json', { ...cached, expires_at: Date.now() - 1000 })

    expect((await client.listTools()).tools).toEqual([tool])
    await client.close()
    cached = JSON.parse(await readFile(cachePath, 'utf8'))
    await writeJsonFile(serverUrlHash, 'tokens.json', { ...cached, expires_at: Date.now() - 1000 })
    network.challengeScope = undefined
    const restartedClient = await connect(provider())

    expect((await restartedClient.listTools()).tools).toEqual([tool])
    expect(network.tokenRequests.map((request) => request.params.get('scope'))).toEqual(['mcp.read', 'mcp.read', 'mcp.read'])
    expect(network.discoveryRequests).toEqual([])
  })

  it('stops after the freshly acquired token is rejected instead of starting another authorization loop', async () => {
    network.rejectAllTokens = true

    await expect(connect(provider())).rejects.toThrow(/401 after re-authentication/)

    expect(network.tokenRequests).toHaveLength(1)
    expect(network.mcpRequests).toHaveLength(2)
    expect(network.discoveryRequests).toEqual([])
  })

  it('reports a token endpoint rejection without discovery or browser fallback', async () => {
    network.tokenFailure = true
    const authProvider = provider()
    const redirect = vi.spyOn(authProvider, 'redirectToAuthorization')

    await expect(connect(authProvider)).rejects.toThrow(/Client credentials rejected/)

    expect(network.tokenRequests.length).toBeLessThanOrEqual(2)
    expect(network.discoveryRequests).toEqual([])
    expect(redirect).not.toHaveBeenCalled()
  })

  it('reports a missing client secret without a token request or browser fallback', async () => {
    const authProvider = provider({ staticOAuthClientInfo: { client_id: 'machine-client', redirect_uris: [] } })
    const redirect = vi.spyOn(authProvider, 'redirectToAuthorization')

    await expect(connect(authProvider)).rejects.toThrow(/needs a client secret/)

    expect(network.tokenRequests).toHaveLength(0)
    expect(network.discoveryRequests).toEqual([])
    expect(redirect).not.toHaveBeenCalled()
  })
})
