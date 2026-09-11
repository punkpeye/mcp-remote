import { z } from 'zod'
import { OAuthClientInformationFullSchema, OAuthTokensSchema } from '@modelcontextprotocol/core'
import { OAuthError, OAuthErrorCode, refreshAuthorization, selectClientAuthMethod, selectResourceURL } from '@modelcontextprotocol/client'
import type {
  OAuthClientInformation,
  OAuthClientInformationFull,
  OAuthClientInformationMixed,
  OAuthClientProvider,
  OAuthTokens,
} from '@modelcontextprotocol/client'
import { type OAuthProviderOptions, type StaticOAuthClientInformationFull, type StaticOAuthClientMetadata } from './types'
import {
  readJsonFile,
  writeJsonFile,
  readTextFile,
  writeTextFile,
  deleteConfigFile,
  deleteStaleConfigFiles,
  acquireConfigLease,
  readConfigLease,
  releaseConfigLease,
} from './mcp-auth-config'
import { openBrowser } from './open-browser'
import { authorizeWithClientCredentials } from './client-credentials'
import { log, debugLog, buildRedirectUrl, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { createHash, randomUUID } from 'node:crypto'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import { getAuthorizationServerUrl, type ProtectedResourceMetadata } from './protected-resource-metadata'
import {
  applyClientAuthentication,
  authorizeWithDeviceCode,
  supportsDeviceAuthorization,
  DEVICE_CODE_GRANT_TYPE,
} from './device-authorization'

/**
 * The OAuth token response only carries the relative `expires_in`, which is
 * useless once persisted to disk. We extend the SDK token schema with an
 * absolute `expires_at` timestamp so later reads can detect imminent expiry
 * and refresh proactively. The base schema uses `.strip()`, which would
 * otherwise drop `expires_at` on read, so we parse and serialize tokens with
 * this extended schema instead.
 */
type OAuthTokensWithExpiresAt = OAuthTokens & {
  expires_at?: number
  /** The scope this client asked for when the token was obtained. See {@link scopeRequestChanged}. */
  requested_scope?: string
}

/**
 * The surface this package asks of the stored-token schema.
 *
 * Annotated rather than inferred because the declaration build cannot name an inferred zod type
 * without reaching into zod's own internal paths and refuses to emit one (TS2742) - and naming the
 * zod type itself is what sends that build out of memory.
 */
type TokenStoreSchema = {
  parse(value: unknown): OAuthTokensWithExpiresAt
  parseAsync(value: unknown): Promise<OAuthTokensWithExpiresAt>
}

export const OAuthTokensWithExpiresAtSchema: TokenStoreSchema = OAuthTokensSchema.extend({
  expires_at: z.coerce.number().optional(),
  requested_scope: z.string().optional(),
})

const FALLBACK_SCOPE = 'openid email profile'

/** The shape of the state we issue, and the only shape accepted into a config filename. */
const ISSUED_STATE = /^[A-Za-z0-9-]{1,64}$/

const CODE_VERIFIER_PREFIX = 'code_verifier_'

/**
 * How many access tokens may be issued inside {@link TOKEN_STORM_WINDOW_MS} before this client
 * stops going back for more.
 *
 * Set well above any legitimate cadence. A token lives minutes at least, and the handful of
 * refreshes a burst of concurrent requests can trigger is nowhere near this. Reaching it means
 * something is exchanging tokens in a loop rather than because one expired.
 */
const TOKEN_STORM_LIMIT = 20
const TOKEN_STORM_WINDOW_MS = 30_000

/**
 * How many browser sign-ins may be started inside {@link TOKEN_STORM_WINDOW_MS} before this client
 * stops asking for another.
 *
 * Counted separately from the token brake above, and for the case that one cannot see: a loop where
 * the sign-in never completes writes no tokens at all, so nothing accumulates for that brake to
 * catch, and the user watches tab after tab open instead (issue #352). Low, because a sign-in is a
 * human action - even a handful in half a minute is already a loop, not a person.
 */
const AUTHORIZATION_STORM_LIMIT = 5

/** Treat a token about to expire as expired, rather than sending one that will 401 in transit. */
const TOKEN_EXPIRY_MARGIN_MS = 60_000

/** The lease that keeps a rotating refresh token to one use per host. See {@link refreshOncePerHost}. */
const REFRESH_LEASE_FILE = 'refresh_in_progress.json'

/**
 * How long an instance may hold the refresh lease.
 *
 * Only ever reached by an instance that is alive and stuck, since one that died is spotted by pid
 * and its lease taken at once. So this is sized for the slowest token request worth waiting on
 * rather than for how quickly an abandoned lease should be noticed.
 */
const REFRESH_LEASE_MS = 30_000
const REFRESH_POLL_MS = 200

/** Stands in for a lease when the store cannot be written at all. See {@link takeRefreshLease}. */
const UNCOORDINATED = ''

/** How long a flow may still be in progress, and its verifier still needed. */
const ABANDONED_FLOW_AGE_MS = 10 * 60 * 1000

/**
 * How long concurrent demands for authorization count as one sign-in rather than several.
 *
 * A server that answers some requests unauthenticated but 401s others - spec-legal, and what
 * pre-auth tool discovery looks like - makes several transport arms enter `auth()` at once: the
 * standalone GET stream, the fallback probe's stream, and the request that was actually refused.
 *
 * It only has to span how far apart those arms reach `state()`, which is the width of one connect
 * burst - milliseconds once discovery is memoized, seconds at worst if each arm is still waiting
 * on its own registration round trip. Deliberately kept well inside the default `--auth-timeout`
 * of 30s, so an abandoned flow always stops holding the window before the sign-in it belongs to
 * times out, rather than after. A finished flow closes it sooner still (see {@link saveTokens}).
 */
const CONCURRENT_FLOW_WINDOW_MS = 10_000

/**
 * The S256 challenge the SDK derives from a verifier.
 *
 * Recomputed here so a redirect can be matched back to the flow that produced it: the
 * authorization URL carries the challenge, and that is the only thing linking it to one of
 * several concurrent flows. See {@link NodeOAuthClientProvider.ownsPendingFlow}.
 */
function codeChallengeFor(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier).digest('base64url')
}

/**
 * The token endpoint authentication methods this client can actually perform, best first.
 * See {@link NodeOAuthClientProvider.getTokenEndpointAuthMethod}.
 */
const TOKEN_ENDPOINT_AUTH_METHOD_PREFERENCE = ['none', 'client_secret_post', 'client_secret_basic']

type ClientRegistrationSource = 'cached-dynamic' | 'fresh-dynamic' | 'static' | 'client-id-metadata-document' | undefined

/**
 * Reads the `exp` claim off a JWT, as a millisecond timestamp.
 *
 * Deliberately no signature check: this decides when to renew a credential we already hold, not
 * whether to trust one that arrived. Verifying is the resource server's job.
 */
function jwtExpiresAt(token: string): number | undefined {
  const payload = token.split('.')[1]
  if (!payload) return undefined

  try {
    const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
    return typeof exp === 'number' ? exp * 1000 : undefined
  } catch {
    return undefined
  }
}

function staleClientRegistrationError(value: unknown): OAuthError | undefined {
  if (!value || typeof value !== 'object') {
    return undefined
  }

  const response = value as Record<string, unknown>
  const message =
    typeof response.error_description === 'string' ? response.error_description : 'Cached OAuth client registration is no longer valid'
  if (response.error === OAuthErrorCode.InvalidClient) {
    return new OAuthError(OAuthErrorCode.InvalidClient, message)
  }
  if (response.error === OAuthErrorCode.UnauthorizedClient) {
    return new OAuthError(OAuthErrorCode.UnauthorizedClient, message)
  }
  return undefined
}

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string
  private softwareId: string
  private softwareVersion: string
  private staticOAuthClientMetadata: StaticOAuthClientMetadata
  private staticOAuthClientInfo: StaticOAuthClientInformationFull
  /**
   * URL of a Client ID Metadata Document, which SEP-991 lets a server accept in place of a
   * registered client id. Read by the SDK, hence a public field rather than a private one.
   */
  clientMetadataUrl?: string
  private useIdToken: boolean
  private useDeviceCode: boolean
  private useClientCredentials: boolean
  /** So a server that never issues an ID token is reported once, not on every outgoing request. */
  private warnedAboutMissingIdToken = false
  private authorizeResource: string | undefined
  private authorizeParams: Record<string, string>
  private skipResourceParameter: boolean
  /**
   * Overrides how the SDK picks the RFC 8707 `resource` indicator. Only defined when we have
   * an opinion; otherwise the SDK derives it from Protected Resource Metadata as usual.
   */
  validateResourceURL?: (defaultResource: URL, discoveredResource?: string) => Promise<URL | undefined>
  private _state: string
  private _clientInfo: OAuthClientInformationFull | undefined
  private clientRegistrationSource: ClientRegistrationSource
  private incomingState: string | undefined
  private authorizationServerMetadata: AuthorizationServerMetadata | undefined
  private protectedResourceMetadata: ProtectedResourceMetadata | undefined
  private wwwAuthenticateScope: string | undefined
  /** When tokens were last written, for spotting an exchange loop. See {@link TOKEN_STORM_LIMIT}. */
  private recentTokenWrites: number[] = []
  /** When sign-ins were last started, for spotting a loop that never gets as far as a token. */
  private recentAuthorizations: number[] = []
  /** In-flight proactive refresh, so concurrent requests share one refresh_token use */
  private refreshInFlight: Promise<OAuthTokensWithExpiresAt | undefined> | null = null
  /**
   * The sign-in being started, so concurrent arms join it rather than race it.
   *
   * `challenge` is set by whichever arm saved its verifier first, and is what identifies that
   * arm's redirect among the several that follow. See {@link CONCURRENT_FLOW_WINDOW_MS}.
   */
  private pendingFlow: { state: string; startedAt: number; challenge?: string } | null = null

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = options.serverUrlHash
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    this.clientMetadataUrl = options.clientMetadataUrl
    this.useIdToken = options.useIdToken ?? false
    this.useDeviceCode = options.useDeviceCode ?? false
    this.useClientCredentials = options.useClientCredentials ?? false
    const trimmedAuthorizeResource = options.authorizeResource?.trim()
    this.authorizeResource = trimmedAuthorizeResource ? trimmedAuthorizeResource : undefined
    this.skipResourceParameter = options.skipResourceParameter ?? false
    this.authorizeParams = options.authorizeParams ?? {}
    this._state = randomUUID()
    this._clientInfo = undefined
    this.clientRegistrationSource = undefined
    this.authorizationServerMetadata = options.authorizationServerMetadata
    this.protectedResourceMetadata = options.protectedResourceMetadata
    this.wwwAuthenticateScope = options.wwwAuthenticateScope

    // The SDK feeds one `resource` value into the authorization, token and refresh requests
    // (selectResourceURL -> startAuthorization / fetchToken / refreshAuthorization). Deciding
    // it here keeps those three in agreement, which RFC 8707 §2.2 requires - previously the
    // authorize URL was rewritten after the fact, so it could disagree with the token request.
    if (this.skipResourceParameter) {
      this.validateResourceURL = async () => {
        debugLog('Resource parameter disabled; omitting it from authorization and token requests')
        return undefined
      }
    } else if (this.authorizeResource) {
      const resourceUrl = new URL(this.authorizeResource)
      this.validateResourceURL = async () => resourceUrl
    }
    // Otherwise left undefined so the SDK applies its default resource selection.
  }

  setCallbackPort(port: number): void {
    this.options.callbackPort = port
  }

  get redirectUrl(): string {
    return buildRedirectUrl(this.options.host, this.options.callbackPort, this.callbackPath)
  }

  /**
   * The MCP server URL, for the RFC 8707 resource indicator. `options.serverUrl` holds the
   * authorization server URL by the time it reaches this class (see proxy.ts/client.ts), which
   * only coincides with the resource server when the two share an origin.
   */
  private get resourceServerUrl(): string {
    return this.options.resourceServerUrl ?? this.options.serverUrl
  }

  get clientMetadata() {
    const effectiveScope = this.getEffectiveScope()
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: this.getTokenEndpointAuthMethod(),
      grant_types: this.grantTypes(),
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
      ...(effectiveScope ? { scope: effectiveScope } : {}),
    }
  }

  /**
   * The `state` this authorization will carry.
   *
   * Called once per flow, and the first provider method a new flow reaches, so it is where a
   * flow is recognised as new. Concurrent arms are handed the state of the flow already being
   * started: only one of them can be redeemed, and sharing the state means the code that comes
   * back names the verifier that flow actually saved.
   *
   * A new flow supersedes any code received for an earlier one, so the state a callback last
   * reported is dropped here - otherwise {@link flowState} would keep reading for a verifier this
   * flow never wrote (and {@link saveTokens} has since deleted).
   */
  state(): string {
    const pending = this.pendingFlow
    if (pending && Date.now() - pending.startedAt < CONCURRENT_FLOW_WINDOW_MS) {
      debugLog('Joining the sign-in already being started', { state: pending.state })
      return pending.state
    }

    this._state = randomUUID()
    this.incomingState = undefined
    this.pendingFlow = { state: this._state, startedAt: Date.now() }
    return this._state
  }

  /**
   * Gets the authorization server metadata, fetching it if not already available
   * @returns The authorization server metadata, or undefined if unavailable
   */
  async getAuthorizationServerMetadata(): Promise<AuthorizationServerMetadata | undefined> {
    // Already have metadata? Return it
    debugLog(`authorizationServerMetadata: ${JSON.stringify(this.authorizationServerMetadata)}`)
    if (this.authorizationServerMetadata) {
      return this.authorizationServerMetadata
    }

    // Fetch metadata and cache in memory for this session
    try {
      this.authorizationServerMetadata = await fetchAuthorizationServerMetadata(this.options.serverUrl)
      if (this.authorizationServerMetadata?.scopes_supported) {
        debugLog('Authorization server supports scopes', {
          scopes_supported: this.authorizationServerMetadata.scopes_supported,
        })
      }
      return this.authorizationServerMetadata
    } catch (error) {
      debugLog('Failed to fetch authorization server metadata', error)
      return undefined
    }
  }

  /**
   * Picks how this client will authenticate at the token endpoint, from what the server offers.
   *
   * `none` comes first because that is what this client honestly is: a public client on someone's
   * laptop, holding no secret worth the name and relying on PKCE. Registering as anything else,
   * only to be handed a secret that npx writes to disk, buys nothing.
   *
   * But an authorization server that leaves `none` out of `token_endpoint_auth_methods_supported`
   * has said it will not accept public clients, and registering as one anyway produced a client
   * whose token requests it then refused (see issue #184). So when `none` is not on offer we take
   * the best of the secret-based methods we can actually perform and let dynamic registration hand
   * us the secret; the SDK reads the method back off the registration and sends it that way.
   *
   * `private_key_jwt` and its relatives are left out deliberately - they need a key pair and a
   * signed assertion, neither of which this client has any way to produce.
   *
   * With no metadata to read we stay on `none`, which is what every server working today already
   * gets. RFC 8414's `client_secret_basic` default describes servers that publish metadata; one
   * that publishes none has told us nothing to act on.
   */
  private getTokenEndpointAuthMethod(): string {
    const supported = this.authorizationServerMetadata?.token_endpoint_auth_methods_supported
    if (!Array.isArray(supported) || supported.length === 0) {
      return 'none'
    }

    const method = TOKEN_ENDPOINT_AUTH_METHOD_PREFERENCE.find((candidate) => supported.includes(candidate))
    if (!method) {
      debugLog('Authorization server advertises no token endpoint auth method this client can perform', {
        token_endpoint_auth_methods_supported: supported,
      })
      return 'none'
    }

    if (method !== 'none') {
      debugLog('Registering with the token endpoint auth method the authorization server advertises', {
        token_endpoint_auth_method: method,
        token_endpoint_auth_methods_supported: supported,
      })
    }
    return method
  }

  private getEffectiveScope(): string {
    return this.requestedScope() ?? FALLBACK_SCOPE
  }

  private requestedScope(): string | undefined {
    // Priority 1: User-provided scope from staticOAuthClientMetadata (highest priority)
    if (this.staticOAuthClientMetadata?.scope && this.staticOAuthClientMetadata.scope.trim().length > 0) {
      debugLog('Using scope from staticOAuthClientMetadata', { scope: this.staticOAuthClientMetadata.scope })
      return this.staticOAuthClientMetadata.scope
    }

    // Priority 2: Scope from WWW-Authenticate header (per MCP spec)
    if (this.wwwAuthenticateScope && this.wwwAuthenticateScope.trim().length > 0) {
      debugLog('Using scope from WWW-Authenticate header', { scope: this.wwwAuthenticateScope })
      return this.wwwAuthenticateScope
    }

    // Priority 3: Scopes from Protected Resource Metadata (RFC 9728)
    const resourceScopes = this.protectedResourceMetadata?.scopes_supported
    if (resourceScopes !== undefined) {
      if (resourceScopes.length === 0) {
        debugLog('Protected resource advertises no scopes (scopes_supported: []), omitting scope')
        return ''
      }
      const scope = resourceScopes.join(' ')
      debugLog('Using scopes from Protected Resource Metadata', {
        scopes_supported: resourceScopes,
        scope,
      })
      return scope
    }

    // Priority 4: Scope from client registration response
    if (this._clientInfo?.scope && this._clientInfo.scope.trim().length > 0) {
      debugLog('Using scope from client registration response', { scope: this._clientInfo.scope })
      return this._clientInfo.scope
    }

    // Priority 5: Use authorization server's supported scopes if advertised
    const authScopes = this.authorizationServerMetadata?.scopes_supported
    if (authScopes !== undefined) {
      if (authScopes.length === 0) {
        debugLog('Authorization server advertises no scopes (scopes_supported: []), omitting scope')
        return ''
      }
      const scope = authScopes.join(' ')
      debugLog('Using scopes from Authorization Server Metadata', {
        scopes_supported: authScopes,
        scope,
      })
      return scope
    }

    debugLog('No source describes the scope to request')
    return undefined
  }

  /**
   * Client authentication for every token request the SDK or this provider sends (the SDK's
   * `executeTokenRequest`). Once a provider supplies this hook the SDK skips its own client
   * authentication, so the hook reproduces that first, then adds the one parameter the SDK
   * leaves out: `scope` on a `refresh_token` grant.
   *
   * RFC 6749 section 6 makes `scope` optional on refresh and the SDK omits it. Microsoft Entra ID
   * reads a scopeless refresh from an app whose client id is also the resource as "requesting a
   * token for itself" and answers `AADSTS90009`, so the session dies at every access-token expiry
   * (modelcontextprotocol/typescript-sdk#2718, anthropics/claude-ai-mcp#840). Repeating the scope
   * the grant carries turns that 400 into a 200, and names nothing the original grant did not, so
   * every other server accepts it too. Authorization-code exchanges are left exactly as they were.
   *
   * An arrow property rather than a method: the SDK passes `provider.addClientAuthentication`
   * around unbound (see its `auth()`), so `this` has to travel with it.
   */
  addClientAuthentication: NonNullable<OAuthClientProvider['addClientAuthentication']> = async (headers, params, _url, metadata) => {
    const clientInformation = await this.clientInformation()
    if (clientInformation) {
      const authMethod = selectClientAuthMethod(clientInformation, metadata?.token_endpoint_auth_methods_supported ?? [])
      applyClientAuthentication(authMethod, clientInformation, headers, params)
    }
    if (params.get('grant_type') === 'refresh_token' && !params.has('scope')) {
      const scope = await this.scopeToRepeatOnRefresh()
      // A server that advertises `scopes_supported: []` is asking for no scope at all, and `scope=`
      // is malformed rather than empty, so the parameter stays off the request entirely.
      if (scope) {
        params.set('scope', scope)
        debugLog('Added the requested scope to the refresh_token grant', { scope })
      }
    }
  }

  /**
   * The scope to repeat on a refresh: what the authorization server actually granted, when it said
   * so in the token response, and otherwise what this client asked for.
   *
   * RFC 6749 section 6 forbids a refresh from naming a scope the resource owner never granted, so
   * echoing the request back at a server that downscoped the authorization earns `invalid_scope` -
   * the refresh this exists to fix, broken a different way. The grant is the safe thing to repeat.
   */
  private async scopeToRepeatOnRefresh(): Promise<string> {
    const stored = await readJsonFile<OAuthTokensWithExpiresAt>(this.serverUrlHash, 'tokens.json', OAuthTokensWithExpiresAtSchema)
    return stored?.scope ?? this.getEffectiveScope()
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    debugLog('Reading client info')
    if (this.staticOAuthClientInfo) {
      debugLog('Returning static client info')
      this._clientInfo = this.staticOAuthClientInfo
      this.clientRegistrationSource = 'static'
      return this.staticOAuthClientInfo
    }

    const clientIdMetadataDocument = await this.clientIdMetadataDocument()
    if (clientIdMetadataDocument) {
      this.clientRegistrationSource = 'client-id-metadata-document'
      return clientIdMetadataDocument
    }

    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )

    if (clientInfo) {
      this._clientInfo = clientInfo
      if (this.clientRegistrationSource !== 'fresh-dynamic') {
        this.clientRegistrationSource = 'cached-dynamic'
      }
    }

    debugLog('Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * The client id to use when the authorization server accepts a Client ID Metadata Document.
   *
   * SEP-991 lets a client be identified by an HTTPS URL that serves its own metadata, removing the
   * need to register at all. That helps against servers with no dynamic registration, and against
   * those that hand out a fresh client on every run.
   *
   * The SDK has this branch too, but only reaches it when nothing is cached. Deciding it here
   * means a client that already registered dynamically switches over as soon as the flag is
   * passed, instead of quietly carrying on with the old registration.
   */
  private async clientIdMetadataDocument(): Promise<OAuthClientInformation | undefined> {
    if (!this.clientMetadataUrl) {
      return undefined
    }

    const metadata = await this.getAuthorizationServerMetadata()
    if (metadata?.client_id_metadata_document_supported !== true) {
      debugLog('Authorization server does not accept a client metadata document; registering instead', {
        clientMetadataUrl: this.clientMetadataUrl,
      })
      return undefined
    }

    debugLog('Identifying this client by its metadata document', { client_id: this.clientMetadataUrl })
    return { client_id: this.clientMetadataUrl }
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    // A client id that is a metadata document URL is not a registration. It came from the command
    // line and is reproduced from there on every run, so caching it could only ever store the same
    // value or a stale one - and store it in a file this client cannot read back, since
    // client_info.json is parsed as a full registration and that shape has only a client_id. The
    // SDK offers it here because its own SEP-991 branch saves whatever it derives.
    if (this.clientMetadataUrl && clientInformation.client_id === this.clientMetadataUrl) {
      debugLog('Not caching a client id that came from a client metadata document')
      this.clientRegistrationSource = 'client-id-metadata-document'
      return
    }

    // Saving the client we just read back is not a registration. The SDK re-saves a cached client
    // to stamp it with the issuer that vouched for it (SEP-2352), and treating that as a fresh
    // registration would retire the preflight in {@link preflightCachedDynamicClientRegistration} -
    // leaving a stale cached client to fail the sign-in it exists to recover from.
    const isRestampOfCachedClient =
      this.clientRegistrationSource === 'cached-dynamic' && clientInformation.client_id === this._clientInfo?.client_id

    debugLog('Saving client info', { client_id: clientInformation.client_id, restamp: isRestampOfCachedClient })
    this._clientInfo = clientInformation
    if (!isRestampOfCachedClient) {
      this.clientRegistrationSource = 'fresh-dynamic'
    }
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    debugLog('Reading OAuth tokens')
    debugLog('Token request stack trace:', new Error().stack)

    const tokens = await readJsonFile<OAuthTokensWithExpiresAt>(this.serverUrlHash, 'tokens.json', OAuthTokensWithExpiresAtSchema)

    if (tokens && this.scopeRequestChanged(tokens)) {
      log('The scopes this client asks for have changed since it signed in; signing in again')
      debugLog('Discarding a token obtained for a different scope request', {
        obtainedFor: tokens.requested_scope,
        nowRequesting: this.getEffectiveScope(),
      })
      await this.invalidateCredentials('tokens')
      return undefined
    }

    if (tokens) {
      const timeLeft = tokens.expires_in || 0

      // Alert if expires_in is invalid
      if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
        debugLog('⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', {
          expiresIn: tokens.expires_in,
          tokenObject: JSON.stringify(tokens),
          stack: new Error('Invalid expires_in value').stack,
        })
      }

      // Use the persisted absolute expiry timestamp to detect imminent expiry,
      // refreshing ~60s early to avoid sending a token that is about to 401.
      const expiresAt = this.bearerExpiresAt(tokens)
      const isExpired = expiresAt ? Date.now() >= expiresAt - TOKEN_EXPIRY_MARGIN_MS : false

      debugLog('Token result:', {
        found: true,
        hasAccessToken: !!tokens.access_token,
        hasIdToken: !!tokens.id_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : 'unknown',
        isExpired,
      })

      // Renew before the token is sent rather than after the server rejects it.
      // Waiting for a 401 assumes the server answers expiry with exactly 401 -
      // one that replies 400 or 403 instead never reaches the SDK's refresh path
      // and the connection just fails (see issue #273).
      if (isExpired && tokens.refresh_token) {
        const refreshed = await this.refreshTokens(tokens.refresh_token)
        if (refreshed) {
          return this.asBearerTokens(refreshed)
        }
        // Refresh failed: hand back what we have and let the SDK's own 401
        // handling take it from here, exactly as it did before.
        log('Proactive token refresh failed, falling back to the stored token')
      }
    } else {
      debugLog('Token result: Not found')
    }

    return this.asBearerTokens(tokens)
  }

  /**
   * The token to present as the Bearer credential.
   *
   * An access token says what the caller may do; an ID token says who they are. A server that
   * verifies identity against an OIDC JWKS endpoint and reads claims like `sub` and `email` wants
   * the second and rejects the first outright - AWS Cognito in front of Bedrock AgentCore being
   * the deployment this was reported for (issue #219).
   *
   * Only the credential presented is swapped. The refresh token, and everything the SDK does with
   * it, is left alone, so renewal still happens the way the authorization server expects.
   */
  private asBearerTokens<T extends OAuthTokens>(tokens: T | undefined): T | undefined {
    if (!tokens || !this.useIdToken) {
      return tokens
    }

    if (!tokens.id_token) {
      // Sending the access token instead will almost certainly be refused - a server asked for an
      // ID token because it will not take the other one - but it fails once, with the server's own
      // message, rather than looping through a sign-in that returns the same tokens again.
      if (!this.warnedAboutMissingIdToken) {
        this.warnedAboutMissingIdToken = true
        log(
          'Warning: --use-id-token was passed but the authorization server issued no ID token, so the access token ' +
            'is being sent instead. An ID token is only returned when `openid` is among the requested scopes.',
        )
      }
      return tokens
    }

    debugLog('Presenting the ID token as the bearer credential')
    return { ...tokens, access_token: tokens.id_token }
  }

  /**
   * When the credential this client actually sends stops being accepted.
   *
   * `expires_in` describes the access token, which under `--use-id-token` is not what goes on the
   * wire. An ID token is issued alongside it with a lifetime of its own, so reading `exp` off the
   * JWT is what keeps the proactive refresh honest about the credential in use.
   */
  private bearerExpiresAt(tokens: OAuthTokensWithExpiresAt): number | undefined {
    if (!this.useIdToken || !tokens.id_token) {
      return tokens.expires_at
    }
    return jwtExpiresAt(tokens.id_token) ?? tokens.expires_at
  }

  /**
   * Whether this run is asking for something different from what the stored token was obtained for.
   *
   * Compares request against request, deliberately, not against what the server granted. An
   * authorization server may grant *less* than it was asked for (RFC 6749 3.3), and treating that
   * as a reason to sign in again is a loop with nothing to break it: the next sign-in returns the
   * same narrower grant, which is rejected the same way. Comparing the two requests only fires
   * when the configuration actually changed - a scope added to `--static-oauth-client-metadata`,
   * say - and then only once, because the new token records the new request.
   *
   * A token stored before this was recorded has no request to compare, and is left alone.
   *
   * @param tokens The tokens read from disk
   * @returns True if a fresh authorization is needed to cover what is being asked for now
   */
  private scopeRequestChanged(tokens: OAuthTokensWithExpiresAt): boolean {
    if (tokens.requested_scope === undefined) return false
    const requested = this.requestedScope()
    if (requested === undefined) return false
    return tokens.requested_scope !== requested
  }

  /**
   * Exchanges a refresh token for a new access token, reusing the same authorization
   * server, client credentials and RFC 8707 resource indicator the SDK would have
   * picked, so the refresh request agrees with the authorization that produced it.
   *
   * Concurrent callers share one attempt: `tokens()` runs on every outgoing request,
   * and with refresh token rotation a second, parallel use of the same token can
   * invalidate the whole chain rather than merely wasting a round trip.
   *
   * @param refreshToken The refresh token to redeem
   * @returns The refreshed tokens, or undefined if the refresh could not be completed
   */
  private async refreshTokens(refreshToken: string): Promise<OAuthTokensWithExpiresAt | undefined> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.refreshOncePerHost(refreshToken).finally(() => {
        this.refreshInFlight = null
      })
    }
    return this.refreshInFlight
  }

  /**
   * Redeems the refresh token, or waits for whichever instance is already redeeming it.
   *
   * A host runs several instances against one server and they share a token store, so a refresh
   * token rotated by one of them is dead in the hands of the rest. {@link refreshInFlight} holds
   * this instance to a single use; nothing held the instances to a single use between them, and a
   * server that rotates without a grace period answers the second use by revoking the chain - a
   * browser sign-in in return for a burst of requests that were all legitimate.
   *
   * The callback port that arbitrates a sign-in is no help here. It is held only while a flow is
   * running, and a refresh happens without one, so there is no existing mutex to reuse and the
   * lease has to stand in for one. Losing the race is not fatal: the loser reads the token the
   * winner wrote, and failing that returns undefined into the path that existed before any of this.
   *
   * @param refreshToken The refresh token this instance set out to redeem
   * @returns The refreshed tokens, or undefined if the refresh could not be completed
   */
  private async refreshOncePerHost(refreshToken: string): Promise<OAuthTokensWithExpiresAt | undefined> {
    let lease = await this.takeRefreshLease()

    if (lease === undefined) {
      const sibling = await this.awaitRefreshBySibling()
      if (sibling.tokens) {
        debugLog('Another instance refreshed the token')
        return sibling.tokens
      }
      // A sibling that released its lease has already had its turn, and a second attempt at a
      // token it may have spent is the storm this exists to stop. Only work it never got to is
      // this instance's to pick up.
      if (!sibling.abandoned) return undefined

      lease = await this.takeRefreshLease()
      if (lease === undefined) return undefined
    }

    try {
      // A sibling may have rotated the token while this instance was reading it, or waiting for
      // the lease, so redeem whatever is on disk now rather than what the caller set out with.
      const stored = await readJsonFile<OAuthTokensWithExpiresAt>(this.serverUrlHash, 'tokens.json', OAuthTokensWithExpiresAtSchema)
      return await this.doRefreshTokens(stored?.refresh_token ?? refreshToken)
    } finally {
      if (lease !== UNCOORDINATED) await releaseConfigLease(this.serverUrlHash, REFRESH_LEASE_FILE, lease)
    }
  }

  /**
   * Takes the refresh lease.
   *
   * A store this instance cannot write is the refresh's own problem to report - it fails, says so,
   * and hands back undefined the way it always did. Failing here instead would turn that into an
   * exception out of `tokens()`, which is on the path of every outgoing request.
   *
   * @returns The lease, undefined if a sibling holds it, or {@link UNCOORDINATED} if no lease can be taken at all
   */
  private async takeRefreshLease(): Promise<string | undefined> {
    try {
      return await acquireConfigLease(this.serverUrlHash, REFRESH_LEASE_FILE, REFRESH_LEASE_MS)
    } catch (error) {
      debugLog('Could not take the refresh lease; refreshing without coordinating', error)
      return UNCOORDINATED
    }
  }

  /**
   * Waits on the instance holding the refresh lease, until it has something to show for it.
   *
   * Bounded by the lease rather than by a clock of its own: an owner that died is spotted within a
   * poll, and one that is alive but stuck runs out its {@link REFRESH_LEASE_MS} and is treated the
   * same. Reading the token before the lease matters, because the winner writes the token first
   * and only then lets go of the lease.
   *
   * @returns The token a sibling wrote, or whether it died still owing one
   */
  private async awaitRefreshBySibling(): Promise<{ tokens?: OAuthTokensWithExpiresAt; abandoned?: boolean }> {
    debugLog('Waiting for the instance already refreshing this token')

    for (;;) {
      await new Promise((resolve) => setTimeout(resolve, REFRESH_POLL_MS))

      const stored = await readJsonFile<OAuthTokensWithExpiresAt>(this.serverUrlHash, 'tokens.json', OAuthTokensWithExpiresAtSchema)
      if (stored?.expires_at !== undefined && Date.now() < stored.expires_at - TOKEN_EXPIRY_MARGIN_MS) return { tokens: stored }

      const holder = await readConfigLease(this.serverUrlHash, REFRESH_LEASE_FILE, REFRESH_LEASE_MS)
      if (!holder) return {}
      if (!holder.live) return { abandoned: true }
    }
  }

  private async doRefreshTokens(refreshToken: string): Promise<OAuthTokensWithExpiresAt | undefined> {
    try {
      const clientInformation = await this.clientInformation()
      if (!clientInformation) {
        debugLog('No client information available, cannot refresh proactively')
        return undefined
      }

      const metadata = await this.getAuthorizationServerMetadata()
      const authorizationServerUrl =
        (this.protectedResourceMetadata ? getAuthorizationServerUrl(this.protectedResourceMetadata) : undefined) ??
        new URL('/', this.options.serverUrl).toString()
      const resource = await selectResourceURL(new URL(this.resourceServerUrl), this, this.protectedResourceMetadata)

      debugLog('Refreshing access token before it expires', { authorizationServerUrl, resource: resource?.toString() })

      // The SDK types metadata as the full OIDC discovery document, while ours is
      // the RFC 8414 subset. Only these two fields reach the token request
      // (executeTokenRequest), so narrow to them rather than cast the whole object.
      const tokenRequestMetadata = metadata
        ? ({
            token_endpoint: metadata.token_endpoint,
            token_endpoint_auth_methods_supported: metadata.token_endpoint_auth_methods_supported,
          } as Parameters<typeof refreshAuthorization>[1]['metadata'])
        : undefined

      const refreshed = await refreshAuthorization(authorizationServerUrl, {
        metadata: tokenRequestMetadata,
        clientInformation,
        refreshToken,
        resource,
        addClientAuthentication: this.addClientAuthentication,
      })

      // Goes through saveTokens so the new expiry is persisted the same way
      await this.saveTokens(refreshed)
      log('Refreshed the access token before it expired')

      return OAuthTokensWithExpiresAtSchema.parse({
        ...refreshed,
        expires_at: refreshed.expires_in ? Date.now() + refreshed.expires_in * 1000 : undefined,
      })
    } catch (error) {
      debugLog('Proactive token refresh failed', error)
      return undefined
    }
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  /**
   * Stops this client taking part in a token exchange loop.
   *
   * An authorization server that keeps honouring a refresh token, for a resource server that keeps
   * rejecting the access tokens it returns, is a loop with nothing to end it: every rejection looks
   * to the SDK like a token worth refreshing. The SDK breaks that cycle for the request path, but
   * not for the standalone SSE stream, whose 401 handler re-enters authorization and reopens the
   * stream with no circuit breaker and no backoff - measured at several hundred exchanges a second,
   * indefinitely, which is what gets people rate-limited by their own identity provider.
   *
   * Every one of those exchanges ends here, so this is the one place the loop can be seen from and
   * the one place it can be stopped. Throwing fails the authorization that asked for the write,
   * which is what unwinds the stream's retry.
   *
   * The window is a sliding one, so a client that stops hammering is trusted again shortly after.
   */
  private inTokenStorm(): boolean {
    const now = Date.now()
    this.recentTokenWrites = this.recentTokenWrites.filter((at) => now - at < TOKEN_STORM_WINDOW_MS)
    return this.recentTokenWrites.length >= TOKEN_STORM_LIMIT
  }

  /** The error both halves of the brake raise, so the cause reads the same wherever it surfaces. */
  private tokenStormError(): Error {
    const seconds = TOKEN_STORM_WINDOW_MS / 1000
    log(
      `Stopping: ${TOKEN_STORM_LIMIT} access tokens were issued in the last ${seconds}s and the MCP server ` +
        `rejected them all. Asking for another would only repeat the exchange.`,
    )
    debugLog('Token exchange loop detected', { writes: this.recentTokenWrites.length, windowMs: TOKEN_STORM_WINDOW_MS })
    return new Error(
      `Stopped after ${TOKEN_STORM_LIMIT} token exchanges in ${seconds}s. The tokens being issued are not accepted ` +
        `by the MCP server - check that its audience and scopes match, or sign in again.`,
    )
  }

  private guardAgainstTokenStorm(): void {
    if (this.inTokenStorm()) throw this.tokenStormError()
    this.recentTokenWrites.push(Date.now())
  }

  /**
   * Stops a reconnect loop from opening a browser tab per turn.
   *
   * The token brake cannot see this one: a loop that fails before any token is issued leaves
   * {@link recentTokenWrites} empty, so the only thing that accumulates is tabs.
   */
  private guardAgainstAuthorizationStorm(): void {
    const now = Date.now()
    this.recentAuthorizations = this.recentAuthorizations.filter((at) => now - at < TOKEN_STORM_WINDOW_MS)

    if (this.recentAuthorizations.length >= AUTHORIZATION_STORM_LIMIT) {
      const seconds = TOKEN_STORM_WINDOW_MS / 1000
      log(`Stopping: ${AUTHORIZATION_STORM_LIMIT} sign-ins were started in the last ${seconds}s and none of them completed.`)
      debugLog('Authorization loop detected', { starts: this.recentAuthorizations.length, windowMs: TOKEN_STORM_WINDOW_MS })
      throw new Error(
        `Stopped after ${AUTHORIZATION_STORM_LIMIT} sign-ins in ${seconds}s, none of which completed. Opening another ` +
          `browser tab would only repeat it - check that the server accepts the tokens this client is being issued.`,
      )
    }

    this.recentAuthorizations.push(now)
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    this.guardAgainstTokenStorm()

    const timeLeft = tokens.expires_in || 0

    // Alert if expires_in is invalid
    if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
      debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
        expiresIn: tokens.expires_in,
        tokenObject: JSON.stringify(tokens),
        stack: new Error('Invalid expires_in value').stack,
      })
    }

    debugLog('Saving tokens', {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: `${timeLeft} seconds`,
      expiresInValue: tokens.expires_in,
    })

    // Persist an absolute expiry timestamp alongside the token so that future
    // reads can detect imminent expiry and refresh proactively (the spec only
    // provides the relative `expires_in`, which is meaningless once stored).
    const tokensToSave: OAuthTokensWithExpiresAt = {
      ...tokens,
      expires_at: tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined,
      requested_scope: this.getEffectiveScope(),
    }

    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokensToSave)

    // The flow is over, and its verifier is named after a state nothing will use again
    await deleteConfigFile(this.serverUrlHash, this.codeVerifierFile(this.flowState))
    await deleteStaleConfigFiles(this.serverUrlHash, CODE_VERIFIER_PREFIX, ABANDONED_FLOW_AGE_MS)

    // Closes the window early, so the next 401 opens a browser instead of joining a flow that has
    // already finished
    this.pendingFlow = null
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // A refused refresh sends the SDK down the full authorization path, so without this the brake
    // would turn an exchange loop into a browser-tab loop - the same storm, more visible.
    if (this.inTokenStorm()) throw this.tokenStormError()

    // Every concurrent arm arrives here with its own challenge, but only the one whose verifier
    // was kept can be redeemed. Sending the user to any of the others produces a code nothing can
    // exchange - and a browser tab per arm. The rest simply fail as ordinary 401s, and retry once
    // this flow has put tokens on disk.
    if (!this.ownsPendingFlow(authorizationUrl)) {
      log('A sign-in for this server is already under way; not starting another')
      debugLog('Suppressed a concurrent authorization redirect', { state: this.pendingFlow?.state })
      return
    }

    // The device grant needs no browser here and no URL to send one to, so the SDK's whole
    // redirect is replaced rather than followed. It returns once tokens are on disk, which is
    // what the reconnect above this then finds.
    if (this.useDeviceCode) {
      await this.authorizeWithDeviceCode()
      return
    }

    // Nobody is being asked for consent here, so there is no URL to send anyone to. Like the device
    // grant above, the whole redirect is replaced: this returns once tokens are on disk, which is
    // what the reconnect above this then finds.
    if (this.useClientCredentials) {
      await this.authorizeWithClientCredentials()
      return
    }

    // Optionally fetch metadata for debugging/informational purposes (non-blocking)
    this.getAuthorizationServerMetadata().catch(() => {
      // Ignore errors, metadata is optional
    })

    this.applyScope(authorizationUrl)
    this.applyAuthorizeParams(authorizationUrl)

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    await this.preflightCachedDynamicClientRegistration(authorizationUrl)

    this.guardAgainstAuthorizationStorm()

    if (await openBrowser(sanitizeUrl(authorizationUrl.toString()))) {
      log('Browser opened automatically.')
    } else {
      log('Could not open a browser automatically. Please copy and paste the URL above into your browser.')
    }
  }

  /**
   * Signs in with the device grant, and leaves the tokens where the next attempt will find them.
   *
   * Runs to completion here rather than handing anything back, because there is nothing to hand
   * back: no code arrives at a callback port, so the only trace of a finished sign-in is the
   * tokens on disk.
   */
  private async authorizeWithDeviceCode(): Promise<void> {
    const metadata = await this.getAuthorizationServerMetadata()
    if (!supportsDeviceAuthorization(metadata)) {
      throw new Error(
        '--device-code was passed but the authorization server does not offer the device grant. ' +
          'Remove the flag to sign in through a browser instead.',
      )
    }

    const clientInformation = await this.clientInformation()
    if (!clientInformation) {
      throw new Error('No OAuth client is registered, so there is nothing to authorize')
    }

    const scope = this.getEffectiveScope()
    const tokens = await authorizeWithDeviceCode({
      metadata: metadata!,
      clientInformation,
      scope: scope || undefined,
      resource: await this.deviceAuthorizationResource(),
    })

    await this.saveTokens(tokens)
  }

  /**
   * The RFC 8707 resource indicator to send with a device authorization, matching what the SDK
   * would put on an authorization code flow so the two cannot disagree about what the token is for.
   */
  /**
   * The grants to register for.
   *
   * `client_credentials` is listed alone: it has no user to come back as a refresh, and asking for
   * `authorization_code` alongside it would register a redirect-based client this flow never uses.
   */
  private grantTypes(): string[] {
    if (this.useClientCredentials) return ['client_credentials']
    if (this.useDeviceCode) return [DEVICE_CODE_GRANT_TYPE, 'refresh_token']
    return ['authorization_code', 'refresh_token']
  }

  /**
   * Signs in as the software itself, and leaves the token where the next attempt will find it.
   *
   * Runs to completion here for the same reason the device grant does: nothing arrives at a
   * callback port, so the only trace of a finished sign-in is the token on disk.
   */
  private async authorizeWithClientCredentials(): Promise<void> {
    const metadata = await this.getAuthorizationServerMetadata()
    if (!metadata) {
      throw new Error('Could not discover the authorization server metadata, so there is no token endpoint to ask')
    }

    const clientInformation = await this.clientInformation()
    if (!clientInformation) {
      throw new Error('No OAuth client credentials were supplied; pass them with --static-oauth-client-info')
    }

    const scope = this.getEffectiveScope()
    const tokens = await authorizeWithClientCredentials({
      metadata,
      clientInformation,
      scope: scope || undefined,
      resource: await this.deviceAuthorizationResource(),
    })

    await this.saveTokens(tokens)
  }

  private async deviceAuthorizationResource(): Promise<URL | undefined> {
    return selectResourceURL(new URL(this.resourceServerUrl), this, this.protectedResourceMetadata)
  }

  private async preflightCachedDynamicClientRegistration(authorizationUrl: URL): Promise<void> {
    if (this.clientRegistrationSource !== 'cached-dynamic') {
      return
    }

    let response: Response
    try {
      response = await fetch(authorizationUrl.toString(), {
        redirect: 'manual',
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5_000),
      })
    } catch (error) {
      debugLog('Authorization preflight failed; continuing to browser authorization', error)
      return
    }

    if (response.status !== 400 && response.status !== 401) {
      return
    }

    let errorResponse: unknown
    try {
      errorResponse = await response.json()
    } catch (error) {
      debugLog('Authorization preflight returned invalid JSON; continuing to browser authorization', error)
      return
    }

    const registrationError = staleClientRegistrationError(errorResponse)
    if (!registrationError) {
      return
    }

    throw registrationError
  }

  /**
   * Decides which scope the authorization request asks for.
   *
   * The SDK has already put one on the URL, picked - in its order - from a scope it parsed out of a
   * live `WWW-Authenticate` challenge, the protected resource's `scopes_supported`, or the `scope`
   * in our own client metadata. The last two originate here, and this client's priority order for
   * them is not the SDK's, so they are replaced with what `getEffectiveScope` decided.
   *
   * A challenge scope does not originate here, and replacing it defeated the one thing it is for: a
   * 403 `insufficient_scope` names the scopes the call actually needed, the SDK re-runs
   * authorization asking for them, and overwriting them here re-requested exactly the scope that
   * had just been refused - so it was refused again and the SDK gave up with "Server returned 403
   * after trying upscoping" (see https://github.com/geelen/mcp-remote/issues/134).
   *
   * A scope the user pinned with `--static-oauth-client-metadata` still wins over both. They set it
   * because the scopes the server advertises do not work for them, and a challenge is the server
   * advertising them again.
   *
   * @param authorizationUrl The authorization URL to set the scope on, modified in place
   */
  /**
   * Adds the caller's own parameters to the authorization URL.
   *
   * Applied after everything this client decides for itself, so an explicitly requested value wins
   * - the flag exists precisely for servers whose requirements this client does not model. The
   * parameters the flow derives per request are refused at parse time instead.
   *
   * @param authorizationUrl The authorization URL to add parameters to, modified in place
   */
  private applyAuthorizeParams(authorizationUrl: URL): void {
    for (const [key, value] of Object.entries(this.authorizeParams)) {
      authorizationUrl.searchParams.set(key, value)
    }

    if (Object.keys(this.authorizeParams).length > 0) {
      debugLog('Added extra parameters to authorization URL', { keys: Object.keys(this.authorizeParams) })
    }
  }

  private applyScope(authorizationUrl: URL): void {
    const effectiveScope = this.getEffectiveScope()
    const requestedScope = authorizationUrl.searchParams.get('scope')
    const pinnedByUser = !!this.staticOAuthClientMetadata?.scope?.trim()
    const couldBeOurs = [effectiveScope, this.protectedResourceMetadata?.scopes_supported?.join(' ')]

    if (!pinnedByUser && requestedScope && !couldBeOurs.includes(requestedScope)) {
      log(`Authorizing with the scope the server asked for: ${requestedScope}`)
      debugLog('Keeping a scope this client did not supply', { scope: requestedScope, effectiveScope })
      return
    }

    if (effectiveScope) {
      authorizationUrl.searchParams.set('scope', effectiveScope)
      debugLog('Added scope parameter to authorization URL', { scopes: effectiveScope })
    } else {
      debugLog('Omitting scope parameter from authorization URL (no effective scope)')
    }
  }

  /**
   * Saves the PKCE code verifier
   *
   * The filename is scoped to this flow's authorization state rather than to the process, so a
   * code can still be redeemed by an instance that took the callback port over from the one that
   * started the flow. See https://github.com/geelen/mcp-remote/issues/235.
   *
   * Concurrent arms each generate their own PKCE pair, but only one challenge can be the one the
   * browser is sent to, and only the verifier matching it can be redeemed. The first to land wins
   * and later ones are dropped: overwriting meant the exchange presented one flow's verifier
   * against another's challenge, which every authorization server correctly rejects as
   * `invalid_grant` (see https://github.com/punkpeye/mcp-remote/issues/353).
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    const flow = this.pendingFlow
    if (flow?.challenge !== undefined) {
      debugLog('Keeping the code verifier already saved for this sign-in', { state: flow.state })
      return
    }

    debugLog('Saving code verifier')
    await writeTextFile(this.serverUrlHash, this.codeVerifierFile(flow?.state ?? this._state), codeVerifier)
    if (flow) flow.challenge = codeChallengeFor(codeVerifier)
  }

  /**
   * Records the state a code came back with, so the flow that produced it decides which verifier
   * redeems it
   * @param state The state from the callback
   */
  useAuthorizationState(state: string): void {
    if (!ISSUED_STATE.test(state)) {
      log('Ignoring an authorization state this client could not have issued')
      debugLog('Rejected authorization state', { state })
      return
    }
    this.incomingState = state
  }

  /** The flow this instance is redeeming for: another instance's when a code names it. */
  private get flowState(): string {
    return this.incomingState ?? this._state
  }

  /**
   * Whether this redirect belongs to the flow whose verifier is the one on disk.
   *
   * The challenge in the authorization URL is the only thing tying a redirect back to the
   * verifier that produced it, since the SDK hands neither call a flow of its own to name.
   * Unrecognised flows are allowed through: suppressing a sign-in that turns out to be the only
   * one costs the user their connection, while an extra tab merely annoys.
   */
  private ownsPendingFlow(authorizationUrl: URL): boolean {
    const challenge = this.pendingFlow?.challenge
    if (challenge === undefined) return true
    return authorizationUrl.searchParams.get('code_challenge') === challenge
  }

  private codeVerifierFile(state: string): string {
    return `${CODE_VERIFIER_PREFIX}${state}.txt`
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    debugLog('Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, this.codeVerifierFile(this.flowState), 'No code verifier saved for session')
    debugLog('Code verifier found:', !!verifier)
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    debugLog(`Invalidating credentials: ${scope}`)

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, this.codeVerifierFile(this.flowState)),
        ])
        this._clientInfo = undefined
        this.clientRegistrationSource = undefined
        this.pendingFlow = null
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        this._clientInfo = undefined
        this.clientRegistrationSource = undefined
        debugLog('Client information invalidated')
        break

      case 'tokens':
        await deleteConfigFile(this.serverUrlHash, 'tokens.json')
        debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, this.codeVerifierFile(this.flowState))
        this.pendingFlow = null
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }
}
