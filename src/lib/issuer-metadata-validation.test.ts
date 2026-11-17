import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client, IssuerMismatchError, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import type { OAuthClientInformationFull } from '@modelcontextprotocol/client'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'

vi.mock('open', () => ({ default: vi.fn(() => Promise.reject(new Error('Browser auth must not run'))) }))
vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
  MCP_REMOTE_VERSION: 'test',
  buildRedirectUrl: (host: string, port: number, path: string) => `http://${host}:${port}${path}`,
}))

// The shape of Agent 365 in front of Entra ID's multi-tenant v2.0 endpoint
const serverUrl = 'https://agent365.example.test/agents/tenants/tenant-1/servers/mcp_CalendarTools'
const resourceMetadataUrl =
  'https://agent365.example.test/.well-known/oauth-protected-resource/agents/tenants/tenant-1/servers/mcp_CalendarTools'
const authority = 'https://login.microsoftonline.com/organizations/v2.0'
// What Entra really publishes at /organizations/v2.0/.well-known/openid-configuration: a template, not a URL
const templatedIssuer = 'https://login.microsoftonline.com/{tenantid}/v2.0'
const authorizationEndpoint = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize'
const tokenEndpoint = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
const serverUrlHash = 'issuer-metadata-validation-test'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

/** An MCP server that wants a token, and an Entra-like authorization server that publishes a templated issuer. */
class EntraLikeServer {
  issuer = templatedIssuer
  tokenRequests: URLSearchParams[] = []
  metadataRequests: string[] = []

  fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init)
    if (request.url === resourceMetadataUrl) {
      return json(200, { resource: serverUrl, authorization_servers: [authority], scopes_supported: ['api://agent365/.default'] })
    }
    if (request.url === `${authority}/.well-known/openid-configuration`) {
      this.metadataRequests.push(request.url)
      return json(200, {
        issuer: this.issuer,
        authorization_endpoint: authorizationEndpoint,
        token_endpoint: tokenEndpoint,
        jwks_uri: 'https://login.microsoftonline.com/organizations/discovery/v2.0/keys',
        response_types_supported: ['code', 'id_token', 'code id_token', 'id_token token'],
        subject_types_supported: ['pairwise'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'private_key_jwt', 'client_secret_basic'],
        scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      })
    }
    if (request.url === tokenEndpoint) {
      this.tokenRequests.push(new URLSearchParams(await request.text()))
      return json(200, { access_token: 'entra-access-token', token_type: 'Bearer', expires_in: 3600 })
    }
    if (request.url === serverUrl) {
      return new Response('Unauthorized', {
        status: 401,
        headers: { 'www-authenticate': `Bearer resource_metadata="${resourceMetadataUrl}"` },
      })
    }
    // Every other discovery candidate (RFC 8414 shapes, OIDC path-inserted) is absent, as on Entra
    return new Response(null, { status: 404 })
  }
}

describe('Feature: Authorization server metadata issuer validation (RFC 8414 §3.3)', () => {
  let configDir: string
  let server: EntraLikeServer
  const clients: Client[] = []

  beforeEach(async () => {
    configDir = await mkdtemp(join(tmpdir(), 'mcp-remote-issuer-'))
    vi.stubEnv('MCP_REMOTE_CONFIG_DIR', configDir)
    server = new EntraLikeServer()
  })

  afterEach(async () => {
    await Promise.all(clients.splice(0).map((client) => client.close()))
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    await rm(configDir, { recursive: true, force: true })
  })

  /** Wired as `connectToRemoteServer` wires it, with an Entra app registration supplied statically. */
  function instance(skipIssuerMetadataValidation?: boolean) {
    const authProvider = new NodeOAuthClientProvider({
      serverUrl: authority,
      resourceServerUrl: serverUrl,
      serverUrlHash,
      host: '127.0.0.1',
      callbackPort: 51001,
      callbackPath: '/',
      // What `--static-oauth-client-info '{"client_id":"..."}'` parses to; the type wants `redirect_uris`, the CLI does not
      staticOAuthClientInfo: { client_id: 'entra-client-id' } as OAuthClientInformationFull,
      ...(skipIssuerMetadataValidation === undefined ? {} : { skipIssuerMetadataValidation }),
    })
    const redirects: URL[] = []
    vi.spyOn(authProvider, 'redirectToAuthorization').mockImplementation(async (url) => {
      redirects.push(url)
    })
    const client = new Client({ name: 'issuer-validation', version: '1' }, { capabilities: {} })
    clients.push(client)
    const transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
      authProvider,
      fetch: authProvider.coordinateTokenRequests(server.fetch),
      skipIssuerMetadataValidation: authProvider.skipIssuerMetadataValidation,
    })
    return { authProvider, transport, redirects, connect: () => client.connect(transport, { timeout: 5000 }) }
  }

  it('Scenario: By default, a templated Entra issuer is rejected before any sign-in starts', async () => {
    const { authProvider, connect, redirects } = instance()

    // The provider keeps validation unless told otherwise
    expect(authProvider.skipIssuerMetadataValidation).toBe(false)

    const failure = await connect().catch((error: unknown) => error)
    expect(failure).toBeInstanceOf(IssuerMismatchError)
    expect(failure).toMatchObject({ kind: 'metadata', expected: authority, received: templatedIssuer })
    expect(String(failure)).toContain(
      'Issuer mismatch in authorization server metadata (RFC 8414 §3.3): expected "https://login.microsoftonline.com/organizations/v2.0", received "https://login.microsoftonline.com/{tenantid}/v2.0"',
    )
    expect(redirects).toHaveLength(0)
  })

  it('Scenario: Passing false explicitly behaves as the default', async () => {
    const { connect, redirects } = instance(false)

    await expect(connect()).rejects.toBeInstanceOf(IssuerMismatchError)
    expect(redirects).toHaveLength(0)
  })

  it('Scenario: With the opt-in, discovery succeeds and the sign-in keeps PKCE, state and the static client', async () => {
    const { connect, redirects } = instance(true)

    // The connection is now waiting on the browser, as for any other sign-in
    await expect(connect()).rejects.toThrow(/Unauthorized/)

    expect(server.metadataRequests).toEqual([`${authority}/.well-known/openid-configuration`])
    expect(redirects).toHaveLength(1)
    const [authorizationUrl] = redirects
    expect(`${authorizationUrl.origin}${authorizationUrl.pathname}`).toBe(authorizationEndpoint)
    expect(authorizationUrl.searchParams.get('client_id')).toBe('entra-client-id')
    expect(authorizationUrl.searchParams.get('redirect_uri')).toBe('http://127.0.0.1:51001/')
    expect(authorizationUrl.searchParams.get('response_type')).toBe('code')
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256')
    expect(authorizationUrl.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(authorizationUrl.searchParams.get('state')).toBeTruthy()
  })

  it('Scenario: With the opt-in, the callback is still checked against the issuer (RFC 9207) and redeemed with the PKCE verifier', async () => {
    const { authProvider, connect, redirects, transport } = instance(true)
    await expect(connect()).rejects.toThrow(/Unauthorized/)
    const state = redirects[0].searchParams.get('state')!

    // The callback arrives naming the flow it belongs to
    authProvider.useAuthorizationState(state)

    // A response claiming to come from some other issuer is still refused, and no code is redeemed
    await expect(transport.finishAuth('stolen-code', 'https://login.microsoftonline.com/attacker-tenant/v2.0')).rejects.toMatchObject({
      kind: 'authorization_response',
    })
    expect(server.tokenRequests).toHaveLength(0)

    // Entra does not advertise RFC 9207, so a callback without `iss` is redeemed - with the verifier
    await transport.finishAuth('entra-code')
    expect(server.tokenRequests).toHaveLength(1)
    const [tokenRequest] = server.tokenRequests
    expect(tokenRequest.get('grant_type')).toBe('authorization_code')
    expect(tokenRequest.get('code')).toBe('entra-code')
    expect(tokenRequest.get('client_id')).toBe('entra-client-id')
    expect(tokenRequest.get('code_verifier')).toMatch(/^[A-Za-z0-9._~-]{43,128}$/)
  })

  it('Scenario: Without the opt-in, an unrelated authorization server publishing a foreign issuer is rejected', async () => {
    // Given metadata that names somebody else entirely, not a template of the server it came from
    server.issuer = 'https://attacker.example.test'
    const { connect, redirects } = instance()

    await expect(connect()).rejects.toMatchObject({ kind: 'metadata', received: 'https://attacker.example.test' })
    expect(redirects).toHaveLength(0)
  })
})
