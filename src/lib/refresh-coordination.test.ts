import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import { getConfigFilePath, writeJsonFile } from './mcp-auth-config'

vi.mock('open', () => ({ default: vi.fn(() => Promise.reject(new Error('Browser auth must not run'))) }))
vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
  MCP_REMOTE_VERSION: 'test',
  buildRedirectUrl: (host: string, port: number, path: string) => `http://${host}:${port}${path}`,
}))

const serverUrl = 'https://mcp.example.test/mcp'
const resourceMetadataUrl = 'https://mcp.example.test/.well-known/oauth-protected-resource/mcp'
const issuer = 'https://auth.example.test'
const tokenEndpoint = `${issuer}/token`
const serverUrlHash = 'refresh-coordination-test'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

/**
 * An authorization server that rotates refresh tokens with no grace period - what issues #389 and
 * #380 were reported against - in front of an MCP server that takes only the latest access token.
 */
class RotatingServer {
  accessToken = 'at-1'
  refreshToken = 'rt-1'
  private issued = 1
  /** Access tokens the MCP server refuses although they are the latest: revoked, say. */
  revoked = new Set<string>()
  /** Refresh tokens the authorization server refuses although they are the latest. */
  dead = new Set<string>()
  redeemed: string[] = []
  refused: string[] = []
  /** Runs when a refresh token is presented, before the token endpoint answers. */
  onRedeem?: (refreshToken: string) => Promise<void>

  rotate() {
    this.issued++
    this.accessToken = `at-${this.issued}`
    this.refreshToken = `rt-${this.issued}`
    return { access_token: this.accessToken, refresh_token: this.refreshToken, token_type: 'Bearer', expires_in: 3600 }
  }

  fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init)
    if (request.url === resourceMetadataUrl) return json(200, { resource: serverUrl, authorization_servers: [issuer] })
    if (request.url === `${issuer}/.well-known/oauth-authorization-server`) {
      return json(200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: tokenEndpoint,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['none'],
        code_challenge_methods_supported: ['S256'],
      })
    }
    if (request.url === tokenEndpoint) {
      const presented = new URLSearchParams(await request.text()).get('refresh_token') ?? ''
      this.redeemed.push(presented)
      await this.onRedeem?.(presented)
      if (presented !== this.refreshToken || this.dead.has(presented)) {
        this.refused.push(presented)
        return json(400, { error: 'invalid_grant', error_description: 'The refresh token is no longer valid' })
      }
      return json(200, this.rotate())
    }
    if (request.url === serverUrl) {
      if (request.method !== 'POST') return new Response(null, { status: 405 })
      const bearer = request.headers.get('authorization')?.replace(/^Bearer /, '')
      if (bearer !== this.accessToken || this.revoked.has(bearer)) {
        return new Response('Unauthorized', {
          status: 401,
          headers: { 'www-authenticate': `Bearer resource_metadata="${resourceMetadataUrl}"` },
        })
      }
      const message = (await request.json()) as { id?: number; method: string }
      if (message.id === undefined) return new Response(null, { status: 202 })
      const result =
        message.method === 'initialize'
          ? { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'rotating', version: '1' } }
          : { tools: [] }
      return json(200, { jsonrpc: '2.0', id: message.id, result })
    }
    return new Response(null, { status: 404 })
  }
}

describe('Feature: Instances sharing a store redeem a refresh token once between them', () => {
  let configDir: string
  let server: RotatingServer
  const clients: Client[] = []

  beforeEach(async () => {
    configDir = await mkdtemp(join(tmpdir(), 'mcp-remote-refresh-'))
    vi.stubEnv('MCP_REMOTE_CONFIG_DIR', configDir)
    server = new RotatingServer()

    // Signed in earlier: a registered client, and a token the MCP server took until now
    await writeJsonFile(serverUrlHash, 'client_info.json', {
      client_id: 'public-client',
      redirect_uris: ['http://localhost:0/oauth/callback'],
      token_endpoint_auth_method: 'none',
      issuer,
    })
    await writeJsonFile(serverUrlHash, 'tokens.json', {
      access_token: 'at-1',
      refresh_token: 'rt-1',
      token_type: 'Bearer',
      expires_in: 3600,
      expires_at: Date.now() + 3_600_000,
      issuer,
    })
  })

  afterEach(async () => {
    await Promise.all(clients.splice(0).map((client) => client.close()))
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    await rm(configDir, { recursive: true, force: true })
  })

  /** One mcp-remote process: its own provider and transport, wired as `connectToRemoteServer` wires them. */
  function instance() {
    const authProvider = new NodeOAuthClientProvider({ serverUrl, serverUrlHash, host: 'localhost', callbackPort: 0 })
    const signIn = vi.spyOn(authProvider, 'redirectToAuthorization').mockResolvedValue(undefined)
    const client = new Client({ name: 'refresh-coordination', version: '1' }, { capabilities: {} })
    clients.push(client)
    const transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
      authProvider,
      fetch: authProvider.coordinateTokenRequests(server.fetch),
    })
    return { connect: () => client.connect(transport, { timeout: 5000 }), signIn }
  }

  const stored = async () => JSON.parse(await readFile(getConfigFilePath(serverUrlHash, 'tokens.json'), 'utf8'))

  it('Scenario: Three instances refused the same token redeem its refresh token once', async () => {
    // Given a token the MCP server stops taking before it expires
    server.revoked.add('at-1')
    const instances = [instance(), instance(), instance()]

    // When all three meet the 401 together
    await Promise.all(instances.map(({ connect }) => connect()))

    // Then one of them redeemed the refresh token, and the others took the token it saved
    expect(server.redeemed).toEqual(['rt-1'])
    expect(server.refused).toEqual([])
    expect(await stored()).toMatchObject({ access_token: 'at-2', refresh_token: 'rt-2' })
    for (const { signIn } of instances) expect(signIn).not.toHaveBeenCalled()
  })

  it("Scenario: A refusal that lost the race to an instance outside the lease keeps that instance's token", async () => {
    // Given an instance of an older release, which redeems without the lease, getting there first
    server.revoked.add('at-1')
    server.onRedeem = async (presented) => {
      server.onRedeem = undefined
      const rotated = server.rotate()
      await writeJsonFile(serverUrlHash, 'tokens.json', { ...rotated, expires_at: Date.now() + 3_600_000, issuer })
      expect(presented).toBe('rt-1')
    }
    const { connect, signIn } = instance()

    // When this instance's redemption of the same refresh token is refused
    await connect()

    // Then the token the other instance saved survives the refusal, and nobody signs in again
    expect(server.refused).toEqual(['rt-1'])
    expect(signIn).not.toHaveBeenCalled()
    expect(await stored()).toMatchObject({ access_token: 'at-2', refresh_token: 'rt-2' })
  })

  it('Scenario: A refresh token the server really refused is discarded, and a sign-in follows', async () => {
    server.revoked.add('at-1')
    server.dead.add('rt-1')
    const { connect, signIn } = instance()

    // Headed for the browser: the sign-in is what the connection now waits on
    await expect(connect()).rejects.toThrow(/Unauthorized/)

    expect(server.refused).toEqual(['rt-1'])
    expect(signIn).toHaveBeenCalledTimes(1)
    await expect(readFile(getConfigFilePath(serverUrlHash, 'tokens.json'))).rejects.toThrow(/ENOENT/)
  })
})
