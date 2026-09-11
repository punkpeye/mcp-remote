import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { authorizeWithClientCredentials } from './client-credentials'

vi.mock('./utils', () => ({ log: vi.fn(), debugLog: vi.fn() }))

const metadata = {
  issuer: 'https://auth.example.com',
  token_endpoint: 'https://auth.example.com/token',
}

const clientInformation = { client_id: 'c1', client_secret: 's1' }

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const tokens = { access_token: 'at', token_type: 'Bearer', expires_in: 3600 }

/** The body of the single POST this grant makes. */
const sentBody = (fetchMock: any) => new URLSearchParams(fetchMock.mock.calls[0][1].body.toString())
const sentHeaders = (fetchMock: any) => fetchMock.mock.calls[0][1].headers as Headers

describe('Feature: Signing in as the software itself', () => {
  let fetchMock: any

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  it('Scenario: Exchange the client credentials for a token, with no user and no browser', async () => {
    fetchMock.mockResolvedValue(json(200, tokens))

    const result = await authorizeWithClientCredentials({ metadata, clientInformation, scope: 'api://app/read' })

    expect(result.access_token).toBe('at')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toBe('https://auth.example.com/token')
    expect(sentBody(fetchMock).get('grant_type')).toBe('client_credentials')
    expect(sentBody(fetchMock).get('scope')).toBe('api://app/read')
  })

  it('Scenario: The secret travels on the Authorization header when the server takes it there', async () => {
    fetchMock.mockResolvedValue(json(200, tokens))

    await authorizeWithClientCredentials({
      metadata: { ...metadata, token_endpoint_auth_methods_supported: ['client_secret_basic'] },
      clientInformation,
    })

    expect(sentHeaders(fetchMock).get('Authorization')).toBe(`Basic ${Buffer.from('c1:s1').toString('base64')}`)
    expect(sentBody(fetchMock).has('client_secret')).toBe(false)
  })

  it('Scenario: Name the MCP server the token is for, so an audience-bound one is usable', async () => {
    fetchMock.mockResolvedValue(json(200, tokens))

    await authorizeWithClientCredentials({ metadata, clientInformation, resource: new URL('https://mcp.example.com/mcp') })

    expect(sentBody(fetchMock).get('resource')).toBe('https://mcp.example.com/mcp')
  })

  it('Scenario: Say what the server said when it refuses the credentials', async () => {
    fetchMock.mockResolvedValue(json(401, { error: 'invalid_client', error_description: 'client secret is wrong' }))

    await expect(authorizeWithClientCredentials({ metadata, clientInformation })).rejects.toThrow('client secret is wrong')
  })

  it('Scenario: Ask for the secret before sending a request that cannot succeed without one', async () => {
    await expect(authorizeWithClientCredentials({ metadata, clientInformation: { client_id: 'c1' } })).rejects.toThrow(
      'needs a client secret',
    )

    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('Scenario: Say so when the authorization server advertises no token endpoint', async () => {
    await expect(authorizeWithClientCredentials({ metadata: { issuer: 'https://auth.example.com' }, clientInformation })).rejects.toThrow(
      'no token endpoint',
    )
  })
})
