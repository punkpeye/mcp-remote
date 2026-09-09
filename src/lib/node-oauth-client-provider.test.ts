import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import * as mcpAuthConfig from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'
import { log } from './utils'
import { authorizeWithDeviceCode, DEVICE_CODE_GRANT_TYPE } from './device-authorization'
import { auth, refreshAuthorization } from '@modelcontextprotocol/sdk/client/auth.js'
import { InvalidClientError, UnauthorizedClientError } from '@modelcontextprotocol/sdk/server/auth/errors.js'

vi.mock('./mcp-auth-config')
vi.mock('./authorization-server-metadata', () => ({
  fetchAuthorizationServerMetadata: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('./utils', () => ({
  getServerUrlHash: () => 'test-hash',
  log: vi.fn(),
  debugLog: vi.fn(),
  DEBUG: false,
  MCP_REMOTE_VERSION: '1.0.0',
  // Must mirror the real implementation: the redirect URI registered with the authorization
  // server and the one checked against a cached registration have to match exactly.
  buildRedirectUrl: (host: string, port: number, callbackPath = '/oauth/callback') => `http://${host}:${port}${callbackPath}`,
}))
vi.mock('open', () => ({ default: vi.fn() }))
vi.mock('./device-authorization', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  authorizeWithDeviceCode: vi.fn(),
}))
vi.mock('@modelcontextprotocol/sdk/client/auth.js', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  refreshAuthorization: vi.fn(),
}))

describe('NodeOAuthClientProvider - OAuth Scope Handling', () => {
  let provider: NodeOAuthClientProvider
  let mockReadJsonFile: any
  let mockWriteJsonFile: any
  let mockDeleteConfigFile: any

  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://example.com',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }

  beforeEach(() => {
    mockReadJsonFile = vi.mocked(mcpAuthConfig.readJsonFile)
    mockWriteJsonFile = vi.mocked(mcpAuthConfig.writeJsonFile)
    mockDeleteConfigFile = vi.mocked(mcpAuthConfig.deleteConfigFile)

    mockReadJsonFile.mockResolvedValue(undefined)
    mockWriteJsonFile.mockResolvedValue(undefined)
    mockDeleteConfigFile.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  describe('scope priority', () => {
    it('should prioritize custom scope from staticOAuthClientMetadata', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom read write',
        } as any,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom read write')
    })

    it('should use scope from registration response', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile read:user',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile read:user')
    })

    it('should fallback to default scopes when none provided', () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })
  })

  describe('authorization URL', () => {
    it('should include scope parameter in authorization URL', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'github read:user',
        } as any,
      })

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('github read:user')
    })

    it('should include default scope in authorization URL when none specified', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email profile')
    })

    it.each(['invalid_client', 'unauthorized_client'])('reports a cached dynamic registration rejected with %s', async (errorCode) => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      mockReadJsonFile.mockResolvedValueOnce({
        client_id: 'stale-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      await provider.clientInformation()
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          status: 400,
          json: async () => ({ error: errorCode }),
        }),
      )

      await expect(
        provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=stale-client')),
      ).rejects.toBeInstanceOf(errorCode === 'invalid_client' ? InvalidClientError : UnauthorizedClientError)

      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
    })

    it('lets the SDK clear and re-register a cached dynamic client once', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      mockReadJsonFile.mockResolvedValueOnce({
        client_id: 'stale-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      const requests: string[] = []
      const fetchFn = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const url = input.toString()
        requests.push(`${init?.method ?? 'GET'} ${url}`)

        if (url === 'https://example.com/.well-known/oauth-protected-resource') {
          return new Response(null, { status: 404 })
        }
        if (url === 'https://example.com/.well-known/oauth-authorization-server') {
          return Response.json({
            issuer: 'https://example.com',
            authorization_endpoint: 'https://example.com/authorize',
            token_endpoint: 'https://example.com/token',
            registration_endpoint: 'https://example.com/register',
            response_types_supported: ['code'],
          })
        }
        if (url === 'https://example.com/register') {
          return Response.json(
            {
              client_id: 'fresh-client',
              redirect_uris: ['http://localhost:8080/oauth/callback'],
            },
            { status: 201 },
          )
        }
        if (url.startsWith('https://example.com/authorize?')) {
          return Response.json({ error: 'invalid_client' }, { status: 400 })
        }

        throw new Error(`Unexpected request: ${url}`)
      })
      vi.stubGlobal('fetch', fetchFn)

      await expect(
        auth(provider, {
          serverUrl: new URL(defaultOptions.serverUrl),
          fetchFn,
        }),
      ).resolves.toBe('REDIRECT')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'client_info.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(requests.filter((request) => request === 'POST https://example.com/register')).toHaveLength(1)
      expect(requests.filter((request) => request.startsWith('GET https://example.com/authorize?'))).toHaveLength(1)
    })

    it('does not infer a stale registration from error_description text', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      mockReadJsonFile.mockResolvedValueOnce({
        client_id: 'cached-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      await provider.clientInformation()
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          status: 400,
          json: async () => ({
            error: 'invalid_request',
            error_description: "Client ID 'cached-client' is not registered with this server",
          }),
        }),
      )

      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=cached-client'))

      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
    })

    it('does not preflight a freshly registered dynamic client', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      await provider.saveClientInformation({
        client_id: 'fresh-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      const preflight = vi.fn()
      vi.stubGlobal('fetch', preflight)

      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=fresh-client'))

      expect(preflight).not.toHaveBeenCalled()
    })

    it('does not preflight a static client registration', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientInfo: {
          client_id: 'static-client',
          redirect_uris: ['http://localhost:8080/oauth/callback'],
        },
      })
      const preflight = vi.fn()
      vi.stubGlobal('fetch', preflight)

      await provider.clientInformation()
      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=static-client'))

      expect(preflight).not.toHaveBeenCalled()
    })
  })

  describe('scope from a live WWW-Authenticate challenge', () => {
    it('should keep the scopes a 403 insufficient_scope asked for', async () => {
      // Given a resource advertising only "read", and a call that turned out to need more
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        protectedResourceMetadata: { resource: 'https://example.com', scopes_supported: ['read'] } as any,
      })

      // When the SDK re-runs authorization with the scopes the challenge named
      const authUrl = new URL('https://auth.example.com/authorize')
      authUrl.searchParams.set('scope', 'read write admin')
      await provider.redirectToAuthorization(authUrl)

      // Then they survive. Re-requesting "read" would just be refused again.
      expect(authUrl.searchParams.get('scope')).toBe('read write admin')
    })

    it('should still impose its own order on the scopes it supplied itself', async () => {
      // Given a client whose own priority puts the WWW-Authenticate scope above the resource's
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        wwwAuthenticateScope: 'mcp:full',
        protectedResourceMetadata: { resource: 'https://example.com', scopes_supported: ['read'] } as any,
      })

      // When the SDK offers the resource metadata scopes, which it prefers and this client does not
      const authUrl = new URL('https://auth.example.com/authorize')
      authUrl.searchParams.set('scope', 'read')
      await provider.redirectToAuthorization(authUrl)

      // Then this client's choice still wins
      expect(authUrl.searchParams.get('scope')).toBe('mcp:full')
    })

    it('should let a user-pinned scope override the challenge', async () => {
      // Given a scope the user pinned because the advertised ones do not work for them
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: { scope: 'custom:only' } as any,
        protectedResourceMetadata: { resource: 'https://example.com', scopes_supported: ['read'] } as any,
      })

      const authUrl = new URL('https://auth.example.com/authorize')
      authUrl.searchParams.set('scope', 'read write admin')
      await provider.redirectToAuthorization(authUrl)

      // Then a challenge does not talk them out of it
      expect(authUrl.searchParams.get('scope')).toBe('custom:only')
    })
  })

  describe('backward compatibility', () => {
    it('should preserve existing custom scope behavior', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'user:email repo',
          client_name: 'My Custom Client',
        } as any,
      })

      const metadata = provider.clientMetadata

      expect(metadata).toMatchObject({
        scope: 'user:email repo',
        client_name: 'My Custom Client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        software_id: '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d',
        software_version: '1.0.0',
      })
    })
  })

  describe('client id metadata document', () => {
    const CLIENT_METADATA_URL = 'https://client.example.com/.well-known/oauth-client-metadata'

    const providerFor = (client_id_metadata_document_supported?: boolean, clientMetadataUrl = CLIENT_METADATA_URL) =>
      new NodeOAuthClientProvider({
        ...defaultOptions,
        clientMetadataUrl,
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          ...(client_id_metadata_document_supported === undefined ? {} : { client_id_metadata_document_supported }),
        } as AuthorizationServerMetadata,
      })

    it('identifies the client by its metadata URL when the server accepts one', async () => {
      // Given a server advertising SEP-991 support
      provider = providerFor(true)

      // Then the URL is the client id, and nothing is registered
      await expect(provider.clientInformation()).resolves.toEqual({ client_id: CLIENT_METADATA_URL })
      expect(mockReadJsonFile).not.toHaveBeenCalledWith('test-hash', 'client_info.json', expect.anything())
    })

    it('prefers the metadata document to a registration cached before the flag was passed', async () => {
      // Given a dynamic registration already on disk
      mockReadJsonFile.mockResolvedValue({ client_id: 'registered-earlier', redirect_uris: ['http://localhost:8080/oauth/callback'] })
      provider = providerFor(true)

      // Then the flag takes effect immediately, rather than after the old registration expires
      await expect(provider.clientInformation()).resolves.toEqual({ client_id: CLIENT_METADATA_URL })
    })

    it('registers dynamically when the server does not advertise support', async () => {
      // Given a server that says nothing about client metadata documents
      mockReadJsonFile.mockResolvedValue(undefined)
      provider = providerFor(undefined)

      // Then we fall back rather than send a client id the server will not recognise
      await expect(provider.clientInformation()).resolves.toBeUndefined()
      expect(mockReadJsonFile).toHaveBeenCalledWith('test-hash', 'client_info.json', expect.anything())
    })

    it('registers dynamically when the server advertises support as false', async () => {
      mockReadJsonFile.mockResolvedValue(undefined)
      provider = providerFor(false)

      await expect(provider.clientInformation()).resolves.toBeUndefined()
    })

    it('lets static client information win over the metadata document', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        clientMetadataUrl: CLIENT_METADATA_URL,
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          client_id_metadata_document_supported: true,
        } as AuthorizationServerMetadata,
        staticOAuthClientInfo: { client_id: 'pinned-by-the-user' } as any,
      })

      await expect(provider.clientInformation()).resolves.toEqual({ client_id: 'pinned-by-the-user' })
    })

    it('does not cache the metadata URL as if it were a registration', async () => {
      // Given the SDK reaching its own SEP-991 branch and offering the derived id back
      provider = providerFor(true)

      await provider.saveClientInformation({ client_id: CLIENT_METADATA_URL } as any)

      // Then nothing is written: client_info.json holds full registrations, and this
      // one could never be read back out of it
      expect(mockWriteJsonFile).not.toHaveBeenCalled()
    })

    it('still caches a real registration when a metadata URL is set but unused', async () => {
      provider = providerFor(false)
      const registration = { client_id: 'issued-by-the-server', redirect_uris: ['http://localhost:8080/oauth/callback'] }

      await provider.saveClientInformation(registration as any)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'client_info.json', registration)
    })
  })

  describe('the device grant', () => {
    const deviceMetadata = {
      issuer: 'https://auth.example.com',
      token_endpoint: 'https://auth.example.com/token',
      device_authorization_endpoint: 'https://auth.example.com/device',
    } as AuthorizationServerMetadata

    const deviceProvider = (authorizationServerMetadata = deviceMetadata) =>
      new NodeOAuthClientProvider({ ...defaultOptions, useDeviceCode: true, authorizationServerMetadata })

    it('registers for the grant it intends to use', () => {
      // Given DCR, which would otherwise register a client the server will not let near this flow
      expect(deviceProvider().clientMetadata.grant_types).toEqual([DEVICE_CODE_GRANT_TYPE, 'refresh_token'])
    })

    it('leaves the authorization code grant alone by default', () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      expect(provider.clientMetadata.grant_types).toEqual(['authorization_code', 'refresh_token'])
    })

    it('signs in through the device flow instead of opening a browser', async () => {
      // Given a registered client and a server offering the grant
      mockReadJsonFile.mockResolvedValue({ client_id: 'c1', redirect_uris: ['http://localhost:8080/oauth/callback'] })
      vi.mocked(authorizeWithDeviceCode).mockResolvedValue({ access_token: 'at', token_type: 'Bearer', expires_in: 3600 } as any)

      // When the SDK asks for the user to be redirected
      await deviceProvider().redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=c1'))

      // Then no browser is opened, and the tokens the flow produced are on disk for the
      // reconnect above this to find - there is no callback for a code to arrive at
      const { default: open } = await import('open')
      expect(open).not.toHaveBeenCalled()
      expect(authorizeWithDeviceCode).toHaveBeenCalledWith(
        expect.objectContaining({
          clientInformation: expect.objectContaining({ client_id: 'c1' }),
          metadata: expect.objectContaining({ device_authorization_endpoint: 'https://auth.example.com/device' }),
          scope: 'openid email profile',
        }),
      )
      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'tokens.json', expect.objectContaining({ access_token: 'at' }))
    })

    it('sends the MCP server, not the authorization server, as the device grant resource', async () => {
      // Given an authorization server on a different origin than the MCP server
      mockReadJsonFile.mockResolvedValue({ client_id: 'c1', redirect_uris: ['http://localhost:8080/oauth/callback'] })
      vi.mocked(authorizeWithDeviceCode).mockResolvedValue({ access_token: 'at', token_type: 'Bearer', expires_in: 3600 } as any)
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        useDeviceCode: true,
        authorizationServerMetadata: deviceMetadata,
        serverUrl: 'https://auth.example.com',
        resourceServerUrl: 'https://mcp.example.com/mcp',
        protectedResourceMetadata: { resource: 'https://mcp.example.com/mcp' } as any,
      })

      // selectResourceURL would otherwise compare the PRM resource against the authorization
      // server URL and throw, same as the proactive refresh path
      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=c1'))

      expect(authorizeWithDeviceCode).toHaveBeenCalledWith(expect.objectContaining({ resource: new URL('https://mcp.example.com/mcp') }))
    })

    it('refuses rather than silently opening a browser the machine may not have', async () => {
      // Given a server that does not offer the grant at all
      mockReadJsonFile.mockResolvedValue({ client_id: 'c1', redirect_uris: [] })

      await expect(
        deviceProvider({ issuer: 'https://auth.example.com' } as AuthorizationServerMetadata).redirectToAuthorization(
          new URL('https://auth.example.com/authorize'),
        ),
      ).rejects.toThrow('does not offer the device grant')

      expect(authorizeWithDeviceCode).not.toHaveBeenCalled()
    })
  })

  describe('token endpoint authentication method', () => {
    const methodFor = (token_endpoint_auth_methods_supported?: string[]) =>
      new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          ...(token_endpoint_auth_methods_supported ? { token_endpoint_auth_methods_supported } : {}),
        } as AuthorizationServerMetadata,
      }).clientMetadata.token_endpoint_auth_method

    it('registers as a public client when there is no metadata to read', () => {
      // Given a server we discovered nothing about
      provider = new NodeOAuthClientProvider(defaultOptions)

      // Then PKCE alone, which is what every server working today already gets
      expect(provider.clientMetadata.token_endpoint_auth_method).toBe('none')
    })

    it('registers as a public client when the metadata omits the list', () => {
      expect(methodFor(undefined)).toBe('none')
    })

    it('registers as a public client when the server accepts one', () => {
      // Given a server that takes public clients, we stay one rather than
      // accept a secret we have nowhere safe to keep
      expect(methodFor(['client_secret_basic', 'none'])).toBe('none')
    })

    it('takes a client secret when the server will not accept public clients', () => {
      // Given the metadata from issue #184, which offers no public-client method
      // Then registration asks for one the server will actually honour
      expect(methodFor(['client_secret_post', 'private_key_jwt'])).toBe('client_secret_post')
    })

    it('falls back to basic auth when the server does not offer post', () => {
      expect(methodFor(['client_secret_basic'])).toBe('client_secret_basic')
    })

    it('prefers post to basic when the server offers both', () => {
      expect(methodFor(['client_secret_basic', 'client_secret_post'])).toBe('client_secret_post')
    })

    it('stays a public client when it can perform none of the methods offered', () => {
      // Given a server wanting a signed assertion, which this client has no key to produce.
      // Registering as something we cannot carry out would only move the failure to the
      // token request, so we register the one way we can and let the server object.
      expect(methodFor(['private_key_jwt', 'tls_client_auth'])).toBe('none')
    })

    it('lets a user-pinned method override what the server advertises', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          token_endpoint_auth_methods_supported: ['client_secret_post'],
        } as AuthorizationServerMetadata,
        staticOAuthClientMetadata: { token_endpoint_auth_method: 'client_secret_basic' } as any,
      })

      expect(provider.clientMetadata.token_endpoint_auth_method).toBe('client_secret_basic')
    })
  })

  describe('a changed scope request', () => {
    const storedWith = (requested_scope: string | undefined) => {
      mockReadJsonFile.mockResolvedValue({
        access_token: 'at',
        refresh_token: 'rt',
        token_type: 'Bearer',
        expires_in: 3600,
        ...(requested_scope === undefined ? {} : { requested_scope }),
      })
    }

    it('signs in again when a scope is added to the configuration', async () => {
      // Given a token obtained when only read access was configured
      provider = new NodeOAuthClientProvider({ ...defaultOptions, staticOAuthClientMetadata: { scope: 'a.read a.write' } as any })
      storedWith('a.read')

      // Then it is discarded, so the next flow asks for both
      await expect(provider.tokens()).resolves.toBeUndefined()
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
    })

    it('keeps a token the server granted less scope than we asked for', async () => {
      // Given a server that granted a subset, which RFC 6749 3.3 permits
      provider = new NodeOAuthClientProvider({ ...defaultOptions, staticOAuthClientMetadata: { scope: 'a.read a.write' } as any })
      mockReadJsonFile.mockResolvedValue({
        access_token: 'at',
        refresh_token: 'rt',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'a.read',
        requested_scope: 'a.read a.write',
      })

      // Then nothing is discarded. Signing in again would return the same narrower grant, so
      // treating it as a reason to retry is a loop with nothing to end it.
      await expect(provider.tokens()).resolves.toMatchObject({ access_token: 'at' })
      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
    })

    it('keeps the sign-in when nothing describes the scope to ask for', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      storedWith('openid profile offline_access')

      await expect(provider.tokens()).resolves.toMatchObject({ access_token: 'at' })
      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
    })

    it('signs in again when a server advertises the same scopes the fallback happens to name', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        protectedResourceMetadata: { resource: 'https://example.com', scopes_supported: ['openid', 'email', 'profile'] } as any,
      })
      storedWith('openid profile offline_access')

      await expect(provider.tokens()).resolves.toBeUndefined()
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
    })

    it('reuses a token when the configuration has not changed', async () => {
      provider = new NodeOAuthClientProvider({ ...defaultOptions, staticOAuthClientMetadata: { scope: 'a.read' } as any })
      storedWith('a.read')

      await expect(provider.tokens()).resolves.toMatchObject({ access_token: 'at' })
      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
    })

    it('leaves a token stored before this was recorded alone', async () => {
      // Nobody should be signed out by upgrading
      provider = new NodeOAuthClientProvider({ ...defaultOptions, staticOAuthClientMetadata: { scope: 'a.read' } as any })
      storedWith(undefined)

      await expect(provider.tokens()).resolves.toMatchObject({ access_token: 'at' })
      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
    })
  })

  describe('token exchange loop protection', () => {
    const anAccessToken = { access_token: 'at', token_type: 'Bearer', expires_in: 3600 } as any

    /** Saves repeatedly until the brake bites, returning how many got through. */
    const saveUntilRefused = async (limit = 60) => {
      for (let attempt = 1; attempt <= limit; attempt++) {
        try {
          await provider.saveTokens({ ...anAccessToken })
        } catch {
          return attempt
        }
      }
      return undefined
    }

    it('allows the few refreshes a burst of concurrent requests can legitimately cause', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      for (let i = 0; i < 10; i++) {
        await expect(provider.saveTokens({ ...anAccessToken })).resolves.toBeUndefined()
      }
    })

    it('stops once tokens are issued faster than any token lifetime could explain', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      // A server rejecting every token it is handed makes this unbounded without the brake
      const refusedAt = await saveUntilRefused()

      expect(refusedAt).toBeDefined()
      expect(refusedAt).toBeLessThanOrEqual(25)
    })

    it('does not send the user to a browser while it is refusing to exchange', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      await saveUntilRefused()

      // Otherwise a refused refresh just becomes a full sign-in, and the storm reappears as tabs
      await expect(provider.redirectToAuthorization(new URL('https://auth.example.com/authorize'))).rejects.toThrow(/token exchanges/)
    })

    it('exchanges again once the burst has aged out', async () => {
      vi.useFakeTimers()
      try {
        vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
        provider = new NodeOAuthClientProvider(defaultOptions)
        await saveUntilRefused()

        // The window slides, so a client that stopped hammering is not punished forever
        vi.setSystemTime(new Date('2026-01-01T00:01:00Z'))

        await expect(provider.saveTokens({ ...anAccessToken })).resolves.toBeUndefined()
      } finally {
        vi.useRealTimers()
      }
    })
  })

  describe('credential invalidation', () => {
    it('should reset to default scopes after client invalidation', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'extracted custom scopes',
      }

      mockReadJsonFile.mockResolvedValueOnce(clientInfo)
      await provider.clientInformation()
      expect(provider.clientMetadata.scope).toBe('extracted custom scopes')

      await provider.invalidateCredentials('client')

      expect(provider.clientMetadata.scope).toBe('openid email profile')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'client_info.json')
    })

    it('should not delete client info when invalidating only tokens', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).not.toHaveBeenCalledWith('test-hash', 'client_info.json')
    })
  })

  // Regression tests for https://github.com/geelen/mcp-remote/issues/235:
  // concurrent mcp-remote processes for the same server used to share a single
  // code_verifier.txt file, so a second process starting mid-flow would silently
  // overwrite the first process's verifier and break its PKCE token exchange.
  describe('PKCE code verifier isolation across flows', () => {
    let mockReadTextFile: any
    let mockWriteTextFile: any

    beforeEach(() => {
      mockReadTextFile = vi.mocked(mcpAuthConfig.readTextFile)
      mockWriteTextFile = vi.mocked(mcpAuthConfig.writeTextFile)
      mockWriteTextFile.mockResolvedValue(undefined)
      mockReadTextFile.mockResolvedValue('test-verifier')
    })

    it('should save the code verifier to a filename scoped to the authorization state', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      // The SDK asks for the state first, and that is what opens the flow the verifier belongs to
      const state = provider.state()
      await provider.saveCodeVerifier('test-verifier')

      expect(mockWriteTextFile).toHaveBeenCalledWith('test-hash', `code_verifier_${state}.txt`, 'test-verifier')
      // Two processes for the same server must never target the same filename
      expect(mockWriteTextFile).not.toHaveBeenCalledWith('test-hash', 'code_verifier.txt', 'test-verifier')
    })

    it('should read the code verifier back from the same flow-scoped filename', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const state = provider.state()
      await provider.codeVerifier()

      expect(mockReadTextFile).toHaveBeenCalledWith('test-hash', `code_verifier_${state}.txt`, expect.any(String))
    })

    it('should not leave its verifier behind once the flow has produced tokens', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const state = provider.state()
      await provider.saveTokens({ access_token: 'token', token_type: 'Bearer' } as any)

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', `code_verifier_${state}.txt`)
      expect(vi.mocked(mcpAuthConfig.deleteStaleConfigFiles)).toHaveBeenCalledWith('test-hash', 'code_verifier_', expect.any(Number))
    })

    it('should read the verifier of the flow a code came from, not its own', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      // A tab opened by an instance the host has since stopped
      provider.useAuthorizationState('11111111-2222-3333-4444-555555555555')

      await provider.codeVerifier()

      expect(mockReadTextFile).toHaveBeenCalledWith(
        'test-hash',
        'code_verifier_11111111-2222-3333-4444-555555555555.txt',
        expect.any(String),
      )
    })

    it('should ignore a state it could not have issued', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const state = provider.state()
      // A crafted state would otherwise be interpolated straight into a config file path
      provider.useAuthorizationState('../../../../etc/passwd')
      await provider.codeVerifier()

      expect(mockReadTextFile).toHaveBeenCalledWith('test-hash', `code_verifier_${state}.txt`, expect.any(String))
    })

    it('should delete the flow-scoped verifier file when invalidating the verifier scope', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const state = provider.state()
      await provider.invalidateCredentials('verifier')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', `code_verifier_${state}.txt`)
    })

    it('should delete the flow-scoped verifier file when invalidating all credentials', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const state = provider.state()
      await provider.invalidateCredentials('all')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', `code_verifier_${state}.txt`)
    })
  })

  /**
   * A server that serves `initialize` unauthenticated but 401s the GET stream and `tools/call` -
   * spec-legal pre-auth discovery - puts three transport arms into `auth()` at once. Each used to
   * overwrite the previous one's verifier under a state fixed for the whole process, so the
   * exchange presented one flow's verifier against another's challenge and failed `invalid_grant`
   * every time, unrecoverably. See https://github.com/punkpeye/mcp-remote/issues/353.
   */
  describe('Feature: Concurrent demands for authorization', () => {
    /** What the SDK puts in the authorization URL for a given verifier. */
    const challengeFor = (verifier: string) => createHash('sha256').update(verifier).digest('base64url')

    const authorizeUrl = (verifier: string) => {
      const url = new URL('https://auth.example.com/authorize')
      url.searchParams.set('code_challenge', challengeFor(verifier))
      url.searchParams.set('code_challenge_method', 'S256')
      return url
    }

    /** The verifier that actually reached disk, as the exchange would later read it back. */
    const savedVerifier = () => {
      const write = vi.mocked(mcpAuthConfig.writeTextFile).mock.calls.at(-1)
      return write?.[2]
    }

    let openedUrls: string[]

    beforeEach(async () => {
      vi.mocked(mcpAuthConfig.writeTextFile).mockResolvedValue(undefined)
      const { default: open } = await import('open')
      vi.mocked(open).mockResolvedValue({} as any)
      openedUrls = []
      vi.mocked(open).mockImplementation(async (url: string) => {
        openedUrls.push(url)
        return {} as any
      })
      provider = new NodeOAuthClientProvider(defaultOptions)
    })

    it('sends the browser to the challenge whose verifier is the one on disk', async () => {
      // Given two arms entering auth() at once, each with its own PKCE pair
      const first = provider.state()
      const second = provider.state()

      // Then they are one sign-in, so the code that comes back names one verifier
      expect(second).toBe(first)

      await provider.saveCodeVerifier('verifier-from-first-arm')
      await provider.saveCodeVerifier('verifier-from-second-arm')

      // The first to land is kept: overwriting it is what broke the exchange
      expect(savedVerifier()).toBe('verifier-from-first-arm')
      expect(vi.mocked(mcpAuthConfig.writeTextFile)).toHaveBeenCalledTimes(1)

      await provider.redirectToAuthorization(authorizeUrl('verifier-from-first-arm'))
      await provider.redirectToAuthorization(authorizeUrl('verifier-from-second-arm'))

      // One browser tab, and it carries the challenge the saved verifier redeems
      expect(openedUrls).toHaveLength(1)
      expect(new URL(openedUrls[0]).searchParams.get('code_challenge')).toBe(challengeFor(savedVerifier()!))
    })

    it('does not depend on which arm reaches the verifier first', async () => {
      // Given the arms interleave the other way round - both take a state before either saves
      provider.state()
      provider.state()

      await provider.saveCodeVerifier('verifier-from-second-arm')
      await provider.saveCodeVerifier('verifier-from-first-arm')

      // Then whichever arm saved first still owns the flow, and nothing overwrote it
      expect(savedVerifier()).toBe('verifier-from-second-arm')
      expect(vi.mocked(mcpAuthConfig.writeTextFile)).toHaveBeenCalledTimes(1)

      // And the browser follows the verifier that was kept, not the arm that took a state first
      await provider.redirectToAuthorization(authorizeUrl('verifier-from-first-arm'))
      await provider.redirectToAuthorization(authorizeUrl('verifier-from-second-arm'))

      expect(openedUrls).toHaveLength(1)
      expect(new URL(openedUrls[0]).searchParams.get('code_challenge')).toBe(challengeFor(savedVerifier()!))
    })

    it('gives the next sign-in its own flow once this one has produced tokens', async () => {
      // Given a flow that completed
      const first = provider.state()
      await provider.saveCodeVerifier('first-flow-verifier')
      await provider.redirectToAuthorization(authorizeUrl('first-flow-verifier'))
      await provider.saveTokens({ access_token: 'token', token_type: 'Bearer' } as any)

      // When the server asks for a sign-in again
      const second = provider.state()
      await provider.saveCodeVerifier('second-flow-verifier')
      await provider.redirectToAuthorization(authorizeUrl('second-flow-verifier'))

      // Then it is a flow of its own, with its own state, verifier and browser tab - a finished
      // sign-in must never suppress the next one
      expect(second).not.toBe(first)
      expect(savedVerifier()).toBe('second-flow-verifier')
      expect(openedUrls).toHaveLength(2)
      expect(new URL(openedUrls[1]).searchParams.get('code_challenge')).toBe(challengeFor('second-flow-verifier'))
    })

    it('redeems a concurrent flow with the verifier the browser was sent to', async () => {
      // Given the arms raced and the callback came back naming their shared state
      const state = provider.state()
      provider.state()
      await provider.saveCodeVerifier('verifier-from-first-arm')
      await provider.saveCodeVerifier('verifier-from-second-arm')

      provider.useAuthorizationState(state)
      await provider.codeVerifier()

      // Then the exchange reads the verifier that matches the challenge in the browser URL
      expect(vi.mocked(mcpAuthConfig.readTextFile)).toHaveBeenCalledWith('test-hash', `code_verifier_${state}.txt`, expect.any(String))
    })
  })

  describe('scopes_supported parsing', () => {
    it('should use custom scopes without filtering', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email', 'profile'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'openid email profile custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use all requested scopes without filtering
      expect(clientMetadata.scope).toBe('openid email profile custom:read custom:write')
    })

    it('should use requested scopes regardless of scopes_supported', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['some', 'other', 'scopes'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use requested scopes even if not in scopes_supported
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when scopes_supported is missing', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        // No scopes_supported
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write special:scope',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write special:scope')
    })

    it('should use scopes when scopes_supported is empty', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when no metadata is provided', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes from client registration response', async () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile custom:read',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const clientMetadata = provider.clientMetadata
      // Should use all scopes from registration response
      expect(clientMetadata.scope).toBe('openid email profile custom:read')
    })

    it('should use scopes_supported when no user or client scopes provided', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use scopes_supported when nothing else is provided
      expect(clientMetadata.scope).toBe('openid email')
    })

    it('should omit scope when authorization server advertises scopes_supported: []', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      expect(provider.clientMetadata.scope).toBeUndefined()
    })

    it('should omit scope when protected resource advertises scopes_supported: []', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        protectedResourceMetadata: {
          resource: 'https://example.com',
          scopes_supported: [],
        } as any,
      })

      expect(provider.clientMetadata.scope).toBeUndefined()
    })

    it('should still fall back to defaults when protected resource omits scopes_supported', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        protectedResourceMetadata: {
          resource: 'https://example.com',
        } as any,
      })

      expect(provider.clientMetadata.scope).toBe('openid email profile')
    })

    it('should omit scope query param when scopes_supported is []', async () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.has('scope')).toBe(false)
    })

    it('should treat empty scope string as no scope and use default', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: '',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      // Empty scope should fallback to default
      expect(clientMetadata.scope).toBe('openid email profile')
    })
  })
})

// The SDK feeds a single `resource` value into the authorization, token and refresh
// requests via selectResourceURL(). These tests pin that value, because RFC 8707 §2.2
// requires the token request to carry the same resource that was authorized.
describe('NodeOAuthClientProvider - RFC 8707 resource indicator', () => {
  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://mcp.example.com/mcp',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }
  const prm: any = { resource: 'https://mcp.example.com' }
  const defaultResource = new URL('https://mcp.example.com/mcp')

  it('defers to the SDK default when no resource options are given', () => {
    const provider = new NodeOAuthClientProvider(defaultOptions)
    // Left undefined so selectResourceURL applies its Protected Resource Metadata logic
    expect(provider.validateResourceURL).toBeUndefined()
  })

  it('sends the user-supplied --resource to token requests too, not just authorize', async () => {
    const provider = new NodeOAuthClientProvider({ ...defaultOptions, authorizeResource: 'https://tenant1.example.com/' })
    const resolved = await provider.validateResourceURL!(defaultResource, prm.resource)
    // Previously this resolved to the PRM resource, so the authorize request said tenant1
    // while the token request said mcp.example.com and the server could reject the exchange.
    expect(String(resolved)).toBe('https://tenant1.example.com/')
  })

  it('omits the resource entirely when disabled', async () => {
    const provider = new NodeOAuthClientProvider({ ...defaultOptions, skipResourceParameter: true })
    expect(await provider.validateResourceURL!(defaultResource, prm.resource)).toBeUndefined()
  })

  it('lets the disable flag win over an explicit resource', async () => {
    const provider = new NodeOAuthClientProvider({
      ...defaultOptions,
      authorizeResource: 'https://tenant1.example.com/',
      skipResourceParameter: true,
    })
    expect(await provider.validateResourceURL!(defaultResource, prm.resource)).toBeUndefined()
  })

  it('no longer rewrites the resource on the authorization URL after the fact', async () => {
    const provider = new NodeOAuthClientProvider({ ...defaultOptions, authorizeResource: 'https://tenant1.example.com/' })
    const authUrl = new URL('https://auth.example.com/authorize')
    await provider.redirectToAuthorization(authUrl)
    // The SDK sets `resource` from validateResourceURL before we ever see the URL, so the
    // provider must not touch it - that post-hoc rewrite was the source of the mismatch.
    expect(authUrl.searchParams.has('resource')).toBe(false)
  })
})

describe('NodeOAuthClientProvider - proactive token refresh', () => {
  const options: OAuthProviderOptions = {
    serverUrl: 'https://example.com/mcp',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }

  const storedTokens = (overrides: Record<string, unknown> = {}) => ({
    access_token: 'stale-token',
    refresh_token: 'r1',
    token_type: 'Bearer',
    expires_in: 3600,
    ...overrides,
  })

  let mockReadJsonFile: any
  let mockWriteJsonFile: any
  let mockRefresh: any

  beforeEach(() => {
    mockReadJsonFile = vi.mocked(mcpAuthConfig.readJsonFile)
    mockWriteJsonFile = vi.mocked(mcpAuthConfig.writeJsonFile)
    mockRefresh = vi.mocked(refreshAuthorization)
    mockWriteJsonFile.mockResolvedValue(undefined)
    vi.mocked(mcpAuthConfig.deleteConfigFile).mockResolvedValue(undefined)
    vi.mocked(mcpAuthConfig.acquireConfigLease).mockResolvedValue('lease-1')
    vi.mocked(mcpAuthConfig.releaseConfigLease).mockResolvedValue(undefined)

    // Any client_info read hands back a registered client; tokens.json is per-test
    mockReadJsonFile.mockImplementation(async (_hash: string, file: string) =>
      file === 'client_info.json' ? { client_id: 'c1', client_secret: 's1', redirect_uris: [] } : undefined,
    )
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  const withStoredTokens = (tokens: Record<string, unknown>) =>
    mockReadJsonFile.mockImplementation(async (_hash: string, file: string) =>
      file === 'client_info.json' ? { client_id: 'c1', client_secret: 's1', redirect_uris: [] } : tokens,
    )

  it('Scenario: an absolute expiry is persisted alongside the token', async () => {
    const provider = new NodeOAuthClientProvider(options)
    const before = Date.now()

    await provider.saveTokens({ access_token: 'a', refresh_token: 'r', token_type: 'Bearer', expires_in: 3600 } as any)

    const [, file, written] = mockWriteJsonFile.mock.calls[0]
    expect(file).toBe('tokens.json')
    // expires_in alone is meaningless once on disk; the absolute time is what a
    // later process can actually compare against
    expect(written.expires_at).toBeGreaterThanOrEqual(before + 3600 * 1000)
  })

  it('Scenario: a token that is still valid is returned untouched', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() + 10 * 60 * 1000 }))
    const provider = new NodeOAuthClientProvider(options)

    const result = await provider.tokens()

    expect(result?.access_token).toBe('stale-token')
    expect(mockRefresh).not.toHaveBeenCalled()
  })

  it('Scenario: an expired token is refreshed before it is ever sent', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    mockRefresh.mockResolvedValue({ access_token: 'fresh-token', refresh_token: 'r2', token_type: 'Bearer', expires_in: 3600 })
    const provider = new NodeOAuthClientProvider(options)

    const result = await provider.tokens()

    // Renewed up front, rather than after the server rejects the stale token -
    // a server that answers expiry with 400 or 403 never reaches the SDK's 401 path
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    expect(mockRefresh.mock.calls[0][1].refreshToken).toBe('r1')
    expect(result?.access_token).toBe('fresh-token')
  })

  it('Scenario: proactive refresh works when the authorization server is on a different origin than the MCP server', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    mockRefresh.mockResolvedValue({ access_token: 'fresh-token', refresh_token: 'r2', token_type: 'Bearer', expires_in: 3600 })
    const provider = new NodeOAuthClientProvider({
      ...options,
      serverUrl: 'https://auth.example.com/',
      resourceServerUrl: 'https://mcp.example.com/mcp',
      protectedResourceMetadata: { resource: 'https://mcp.example.com/mcp' } as any,
    })

    const result = await provider.tokens()

    // selectResourceURL compares the PRM resource against options.serverUrl, which is the
    // authorization server here - without resourceServerUrl that mismatches and throws, so
    // this used to fall back to the stale token on every refresh
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    expect(mockRefresh.mock.calls[0][1].resource?.toString()).toBe('https://mcp.example.com/mcp')
    expect(result?.access_token).toBe('fresh-token')
  })

  const heldLease = (overrides: Record<string, unknown> = {}) => ({ pid: 4242, nonce: 'theirs', at: Date.now(), live: true, ...overrides })

  it('Scenario: an instance waits for the sibling already refreshing rather than spending the token twice', async () => {
    const expired = storedTokens({ expires_at: Date.now() - 1000 })
    const renewed = storedTokens({ access_token: 'from-sibling', refresh_token: 'r2', expires_at: Date.now() + 3_600_000 })
    mockReadJsonFile.mockResolvedValueOnce(expired).mockResolvedValue(renewed)
    vi.mocked(mcpAuthConfig.acquireConfigLease).mockResolvedValue(undefined)
    vi.mocked(mcpAuthConfig.readConfigLease).mockResolvedValue(heldLease())
    const provider = new NodeOAuthClientProvider(options)

    await expect(provider.tokens()).resolves.toMatchObject({ access_token: 'from-sibling' })
    // The whole point: one refresh_token use per host, not one per instance
    expect(mockRefresh).not.toHaveBeenCalled()
  })

  it('Scenario: a lease its owner died holding is taken over rather than waited out', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    mockRefresh.mockResolvedValue({ access_token: 'fresh-token', refresh_token: 'r2', token_type: 'Bearer', expires_in: 3600 })
    vi.mocked(mcpAuthConfig.acquireConfigLease).mockResolvedValueOnce(undefined).mockResolvedValue('lease-2')
    // An instance killed mid-refresh leaves its lease behind; nothing will ever release it
    vi.mocked(mcpAuthConfig.readConfigLease).mockResolvedValue(heldLease({ live: false }))
    const provider = new NodeOAuthClientProvider(options)

    await expect(provider.tokens()).resolves.toMatchObject({ access_token: 'fresh-token' })
    expect(mockRefresh).toHaveBeenCalledTimes(1)
  })

  it('Scenario: a sibling that finished without a token is not followed by a second attempt', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    vi.mocked(mcpAuthConfig.acquireConfigLease).mockResolvedValue(undefined)
    // The lease is released whether the refresh worked or not, so its absence says the sibling
    // has had its turn - and retrying a token it may already have spent is the storm being avoided
    vi.mocked(mcpAuthConfig.readConfigLease).mockResolvedValue(undefined)
    const provider = new NodeOAuthClientProvider(options)

    await expect(provider.tokens()).resolves.toMatchObject({ access_token: 'stale-token' })
    expect(mockRefresh).not.toHaveBeenCalled()
    expect(vi.mocked(mcpAuthConfig.acquireConfigLease)).toHaveBeenCalledTimes(1)
  })

  it('Scenario: the token redeemed is the one on disk once the lease is held', async () => {
    // A sibling rotated between this instance reading the token and winning the lease. Redeeming
    // what was read would spend a token the server has already retired.
    mockReadJsonFile
      .mockResolvedValueOnce(storedTokens({ expires_at: Date.now() - 1000 }))
      .mockResolvedValue(storedTokens({ refresh_token: 'r-rotated', expires_at: Date.now() - 1000 }))
    mockRefresh.mockResolvedValue({ access_token: 'fresh-token', refresh_token: 'r3', token_type: 'Bearer', expires_in: 3600 })
    const provider = new NodeOAuthClientProvider(options)

    await provider.tokens()

    expect(mockRefresh.mock.calls[0][1].refreshToken).toBe('r-rotated')
  })

  it('Scenario: a lease that cannot be taken at all does not fail the request', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    mockRefresh.mockResolvedValue({ access_token: 'fresh-token', refresh_token: 'r2', token_type: 'Bearer', expires_in: 3600 })
    vi.mocked(mcpAuthConfig.acquireConfigLease).mockRejectedValue(new Error('EACCES'))
    const provider = new NodeOAuthClientProvider(options)

    // tokens() runs on every outgoing request; an unwritable store is for the refresh to report
    await expect(provider.tokens()).resolves.toMatchObject({ access_token: 'fresh-token' })
    expect(vi.mocked(mcpAuthConfig.releaseConfigLease)).not.toHaveBeenCalled()
  })

  it('Scenario: concurrent requests share a single refresh', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    mockRefresh.mockImplementation(
      async () =>
        new Promise((resolve) =>
          setTimeout(() => resolve({ access_token: 'fresh-token', refresh_token: 'r2', token_type: 'Bearer', expires_in: 3600 }), 10),
        ),
    )
    const provider = new NodeOAuthClientProvider(options)

    const results = await Promise.all([provider.tokens(), provider.tokens(), provider.tokens()])

    // tokens() runs on every outgoing request. With refresh token rotation a
    // second parallel use of the same token can invalidate the whole chain.
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    expect(results.map((r) => r?.access_token)).toEqual(['fresh-token', 'fresh-token', 'fresh-token'])
  })

  it('Scenario: a failed refresh falls back to the stored token', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    mockRefresh.mockRejectedValue(new Error('authorization server unreachable'))
    const provider = new NodeOAuthClientProvider(options)

    const result = await provider.tokens()

    // The SDK's own 401 handling is still there to catch this; never hand back
    // a blank access token, which some servers reject as a malformed request
    expect(result?.access_token).toBe('stale-token')
  })

  it('Scenario: an expired token with no refresh token is left alone', async () => {
    withStoredTokens({ access_token: 'stale-token', token_type: 'Bearer', expires_in: 3600, expires_at: Date.now() - 1000 })
    const provider = new NodeOAuthClientProvider(options)

    const result = await provider.tokens()

    expect(mockRefresh).not.toHaveBeenCalled()
    expect(result?.access_token).toBe('stale-token')
  })

  describe('the ID token as the bearer credential', () => {
    /** An unsigned JWT: nothing here verifies one, it only reads `exp` to decide when to renew. */
    const idToken = (expiresAt: number, label = 'id') =>
      [
        Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
        Buffer.from(JSON.stringify({ sub: label, exp: Math.floor(expiresAt / 1000) })).toString('base64url'),
        '',
      ].join('.')

    it('Scenario: the access token is still what gets sent by default', async () => {
      // Given a server that issued both, and no flag asking for the ID token
      const token = idToken(Date.now() + 10 * 60 * 1000)
      withStoredTokens(storedTokens({ id_token: token, expires_at: Date.now() + 10 * 60 * 1000 }))

      const result = await new NodeOAuthClientProvider(options).tokens()

      expect(result?.access_token).toBe('stale-token')
    })

    it('Scenario: the ID token is presented when the server verifies identity', async () => {
      // Given a server reading claims off an ID token rather than checking scopes (issue #219)
      const token = idToken(Date.now() + 10 * 60 * 1000)
      withStoredTokens(storedTokens({ id_token: token, expires_at: Date.now() + 10 * 60 * 1000 }))

      const result = await new NodeOAuthClientProvider({ ...options, useIdToken: true }).tokens()

      // Then it is the credential on the wire, while the refresh token is untouched
      expect(result?.access_token).toBe(token)
      expect(result?.refresh_token).toBe('r1')
    })

    it('Scenario: renewal follows the ID token, not the access token beside it', async () => {
      // Given an ID token about to expire and an access token good for another ten minutes
      withStoredTokens(storedTokens({ id_token: idToken(Date.now() + 10_000, 'old'), expires_at: Date.now() + 10 * 60 * 1000 }))
      const fresh = idToken(Date.now() + 60 * 60 * 1000, 'new')
      mockRefresh.mockResolvedValue({
        access_token: 'fresh-token',
        id_token: fresh,
        refresh_token: 'r2',
        token_type: 'Bearer',
        expires_in: 3600,
      })

      const result = await new NodeOAuthClientProvider({ ...options, useIdToken: true }).tokens()

      // Then the credential is renewed before it is sent, which reading expires_in alone would miss
      expect(mockRefresh).toHaveBeenCalledTimes(1)
      expect(result?.access_token).toBe(fresh)
    })

    it('Scenario: an expired access token beside a good ID token is not worth a refresh', async () => {
      // Given the reverse: the access token has lapsed but the ID token has an hour left
      const token = idToken(Date.now() + 60 * 60 * 1000)
      withStoredTokens(storedTokens({ id_token: token, expires_at: Date.now() - 1000 }))

      const result = await new NodeOAuthClientProvider({ ...options, useIdToken: true }).tokens()

      // Then nothing is renewed: the lapsed token is not the one being sent, and spending a
      // refresh token on it risks the rotation chain for a credential nobody will see
      expect(mockRefresh).not.toHaveBeenCalled()
      expect(result?.access_token).toBe(token)
    })

    it('Scenario: an ID token whose expiry cannot be read falls back to the access token expiry', async () => {
      withStoredTokens(storedTokens({ id_token: 'not-a-jwt', expires_at: Date.now() + 10 * 60 * 1000 }))

      const result = await new NodeOAuthClientProvider({ ...options, useIdToken: true }).tokens()

      // Not refreshed on the strength of an expiry we could not read
      expect(mockRefresh).not.toHaveBeenCalled()
      expect(result?.access_token).toBe('not-a-jwt')
    })

    it('Scenario: a server that issues no ID token is reported once, not on every request', async () => {
      withStoredTokens(storedTokens({ expires_at: Date.now() + 10 * 60 * 1000 }))
      const provider = new NodeOAuthClientProvider({ ...options, useIdToken: true })
      const warnings = () => vi.mocked(log).mock.calls.filter(([message]) => String(message).includes('--use-id-token'))

      const first = await provider.tokens()
      await provider.tokens()
      await provider.tokens()

      // One clean rejection from the server beats a sign-in loop that returns the same tokens,
      // and tokens() runs on every outgoing request, so the warning cannot repeat
      expect(first?.access_token).toBe('stale-token')
      expect(warnings()).toHaveLength(1)
    })
  })
})

describe('NodeOAuthClientProvider - Extra authorization parameters', () => {
  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://example.com',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }

  beforeEach(() => {
    vi.mocked(mcpAuthConfig.readJsonFile).mockResolvedValue(undefined)
    vi.mocked(mcpAuthConfig.writeJsonFile).mockResolvedValue(undefined)
    vi.mocked(mcpAuthConfig.deleteConfigFile).mockResolvedValue(undefined)
    vi.mocked(mcpAuthConfig.acquireConfigLease).mockResolvedValue('lease-1')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  it('should put the requested parameters on the authorization URL', async () => {
    // Given the parameters Google needs to part with a refresh token
    const provider = new NodeOAuthClientProvider({
      ...defaultOptions,
      authorizeParams: { access_type: 'offline', prompt: 'consent' },
    })

    // When the user is sent to authorize
    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth')
    await provider.redirectToAuthorization(authUrl)

    // Then the server sees them
    expect(authUrl.searchParams.get('access_type')).toBe('offline')
    expect(authUrl.searchParams.get('prompt')).toBe('consent')
  })

  it('should let a requested parameter override one this client chose', async () => {
    // Given a scope this client would otherwise decide for itself
    const provider = new NodeOAuthClientProvider({
      ...defaultOptions,
      staticOAuthClientMetadata: { scope: 'openid email' } as any,
      authorizeParams: { scope: 'openid' },
    })

    const authUrl = new URL('https://auth.example.com/authorize')
    await provider.redirectToAuthorization(authUrl)

    // Then the explicit request wins, because that is what the escape hatch is for
    expect(authUrl.searchParams.get('scope')).toBe('openid')
  })

  it('should add nothing of its own when none are supplied', async () => {
    // Given a provider configured exactly as before the flag existed
    const provider = new NodeOAuthClientProvider({ ...defaultOptions })

    const authUrl = new URL('https://auth.example.com/authorize?response_type=code')
    await provider.redirectToAuthorization(authUrl)

    // Then the URL carries only what this client already decided for itself - `scope` is
    // applyScope's doing, not the new flag's
    expect([...authUrl.searchParams.keys()].sort()).toEqual(['response_type', 'scope'])
  })
})
