import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { auth } from '@modelcontextprotocol/client'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import { getConfigFilePath, writeJsonFile, writeTextFile } from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'

vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
  MCP_REMOTE_VERSION: 'test',
  buildRedirectUrl: (host: string, port: number, path: string) => `http://${host}:${port}${path}`,
}))
// A sign-in must never reach for a real browser (or its platform fallbacks) under test.
vi.mock('./open-browser', () => ({ openBrowser: vi.fn().mockResolvedValue(false) }))
vi.mock('./authorization-server-metadata', () => ({ fetchAuthorizationServerMetadata: vi.fn().mockResolvedValue(undefined) }))

const serverUrl = 'https://mcp.example.test/mcp'
const authorizationServerUrl = 'https://as.example.test'
const serverUrlHash = 'discovery-state-test'

const authorizationServerMetadata = {
  issuer: authorizationServerUrl,
  authorization_endpoint: `${authorizationServerUrl}/authorize`,
  token_endpoint: `${authorizationServerUrl}/token`,
  registration_endpoint: `${authorizationServerUrl}/register`,
  response_types_supported: ['code'],
}

const resourceMetadata = { resource: serverUrl, authorization_servers: [authorizationServerUrl] }

/** The discovery state an authorize leg leaves behind for the callback leg to pick up. */
const discoveryState = {
  authorizationServerUrl,
  resourceMetadataUrl: 'https://mcp.example.test/.well-known/oauth-protected-resource/mcp',
  resourceMetadata,
  authorizationServerMetadata,
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

/** Answers discovery, registration and token requests like a real OAuth deployment would. */
class TestNetwork {
  discoveryRequests: string[] = []
  registrationRequests: string[] = []
  tokenRequests: Array<{ params: URLSearchParams }> = []

  fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init)

    if (request.url === `${authorizationServerUrl}/token`) {
      this.tokenRequests.push({ params: new URLSearchParams(await request.text()) })
      return json(200, { access_token: 'issued-1', token_type: 'Bearer', expires_in: 3600 })
    }
    if (request.url === `${authorizationServerUrl}/register`) {
      this.registrationRequests.push(request.url)
      return json(200, { client_id: 'registered-client', ...(await request.json()) })
    }

    this.discoveryRequests.push(request.url)
    if (request.url === 'https://mcp.example.test/.well-known/oauth-protected-resource/mcp') {
      return json(200, resourceMetadata)
    }
    if (request.url === `${authorizationServerUrl}/.well-known/oauth-authorization-server`) {
      return json(200, authorizationServerMetadata)
    }
    return new Response('not found', { status: 404 })
  }
}

/**
 * The callback leg of a sign-in can land in a different process than the authorize leg, so the
 * SDK asks the provider to persist discovery state with the same durability as the code
 * verifier. Without it the callback leg discovers the authorization server all over again,
 * the freshly resolved issuer can fail the SEP-2352 check against the credential that the
 * authorize leg stored, and the first sign-in fails where a second attempt would succeed.
 */
describe('NodeOAuthClientProvider - persisted OAuth discovery state', () => {
  let configDir: string
  let network: TestNetwork

  beforeEach(async () => {
    configDir = await mkdtemp(join(tmpdir(), 'mcp-remote-discovery-'))
    vi.stubEnv('MCP_REMOTE_CONFIG_DIR', configDir)
    network = new TestNetwork()
    vi.stubGlobal('fetch', network.fetch)
  })

  afterEach(async () => {
    vi.unstubAllGlobals()
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    await rm(configDir, { recursive: true, force: true })
  })

  function provider(overrides: Partial<OAuthProviderOptions> = {}) {
    return new NodeOAuthClientProvider({
      serverUrl,
      serverUrlHash,
      host: 'localhost',
      callbackPort: 0,
      ...overrides,
    })
  }

  it('saves discovery state to the config store and reads it back from another instance', async () => {
    await provider().saveDiscoveryState(discoveryState)

    const onDisk = JSON.parse(await readFile(getConfigFilePath(serverUrlHash, 'discovery_state.json'), 'utf8'))
    expect(onDisk.authorizationServerMetadata.issuer).toBe(authorizationServerUrl)

    // The callback leg reads it through a new instance, as a second process would
    const readBack = await provider().discoveryState()
    expect(readBack).toMatchObject({
      authorizationServerUrl,
      resourceMetadataUrl: discoveryState.resourceMetadataUrl,
      resourceMetadata,
    })
    // The SEP-2352 issuer stamp the callback leg checks must survive the round trip
    expect(readBack?.authorizationServerMetadata?.issuer).toBe(authorizationServerUrl)
  })

  it('returns undefined for the authorization-code flow when nothing was persisted', async () => {
    expect(await provider().discoveryState()).toBeUndefined()
  })

  it('treats a corrupted discovery state file as absent rather than failing the sign-in', async () => {
    await writeJsonFile(serverUrlHash, 'discovery_state.json', { authorizationServerUrl: 42 })
    expect(await provider().discoveryState()).toBeUndefined()
  })

  it('keeps the explicit token endpoint path configured rather than persisted', async () => {
    const explicit = provider({
      useClientCredentials: true,
      tokenEndpoint: 'https://identity.example.test/oauth2/v1/token',
      staticOAuthClientInfo: { client_id: 'machine-client', client_secret: 'test-secret', redirect_uris: [] },
    })

    await explicit.saveDiscoveryState(discoveryState)
    await expect(readFile(getConfigFilePath(serverUrlHash, 'discovery_state.json'), 'utf8')).rejects.toThrow(/ENOENT/)

    const state = await explicit.discoveryState()
    expect(state?.authorizationServerUrl).toBe('https://identity.example.test')
    expect(state?.authorizationServerMetadata).toMatchObject({
      issuer: 'https://identity.example.test',
      token_endpoint: 'https://identity.example.test/oauth2/v1/token',
      grant_types_supported: ['client_credentials'],
    })
  })

  it('deletes discovery state when the discovery or all scopes are invalidated', async () => {
    await provider().saveDiscoveryState(discoveryState)
    await provider().invalidateCredentials('discovery')
    await expect(readFile(getConfigFilePath(serverUrlHash, 'discovery_state.json'), 'utf8')).rejects.toThrow(/ENOENT/)

    await provider().saveDiscoveryState(discoveryState)
    await provider().invalidateCredentials('all')
    await expect(readFile(getConfigFilePath(serverUrlHash, 'discovery_state.json'), 'utf8')).rejects.toThrow(/ENOENT/)
  })

  it('round-trips the issuer stamp the SDK saves onto the stored client registration', async () => {
    const registering = provider()
    await registering.saveClientInformation({
      client_id: 'registered-client',
      redirect_uris: ['http://localhost:0/oauth/callback'],
      issuer: authorizationServerUrl,
    } as any)

    const clientInformation = await provider().clientInformation()
    expect((clientInformation as { issuer?: string } | undefined)?.issuer).toBe(authorizationServerUrl)
  })

  it('persists discovery state during the authorize leg', async () => {
    const result = await auth(provider(), { serverUrl, fetchFn: network.fetch })

    expect(result).toBe('REDIRECT')
    const onDisk = JSON.parse(await readFile(getConfigFilePath(serverUrlHash, 'discovery_state.json'), 'utf8'))
    expect(onDisk).toMatchObject({
      authorizationServerUrl,
      resourceMetadata,
    })
    expect(onDisk.authorizationServerMetadata.issuer).toBe(authorizationServerUrl)
    // The registered client is stamped with the issuer that vouched for it (SEP-2352)
    const clientInfo = JSON.parse(await readFile(getConfigFilePath(serverUrlHash, 'client_info.json'), 'utf8'))
    expect(clientInfo.issuer).toBe(authorizationServerUrl)
  })

  it('redeems an authorization code against the persisted discovery state without re-discovering', async () => {
    // The authorize leg, in whatever process ran it
    await provider().saveDiscoveryState(discoveryState)
    await writeJsonFile(serverUrlHash, 'client_info.json', {
      client_id: 'registered-client',
      redirect_uris: ['http://localhost:0/oauth/callback'],
      issuer: authorizationServerUrl,
    })
    await writeTextFile(serverUrlHash, 'code_verifier_issued-state.txt', 'verifier-1')

    // The callback leg, in a fresh instance as the port-owning process would be
    const callback = provider()
    callback.useAuthorizationState('issued-state')
    const warn = vi.spyOn(console, 'warn')
    const result = await auth(callback, { serverUrl, authorizationCode: 'code-1', fetchFn: network.fetch })

    expect(result).toBe('AUTHORIZED')
    // The whole point of the persisted state: the callback leg must not discover again,
    // since a re-discovered issuer is what trips the SEP-2352 credential check
    expect(network.discoveryRequests).toEqual([])
    expect(network.tokenRequests.map(({ params }) => params.get('grant_type'))).toEqual(['authorization_code'])
    expect(network.tokenRequests[0].params.get('code_verifier')).toBe('verifier-1')
    expect(warn).not.toHaveBeenCalledWith(expect.stringContaining('saveDiscoveryState'))
  })
})
