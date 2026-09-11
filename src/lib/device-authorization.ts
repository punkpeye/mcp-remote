import { OAuthTokensSchema } from '@modelcontextprotocol/core'
import { selectClientAuthMethod } from '@modelcontextprotocol/client'
import type { OAuthClientInformationMixed, OAuthTokens } from '@modelcontextprotocol/client'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'
import { log, debugLog } from './utils'

/** RFC 8628. The grant this module exchanges, and the one a server has to advertise to offer it. */
export const DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'

/** RFC 8628 3.5: how often to poll when the server expresses no preference. */
const DEFAULT_POLL_INTERVAL_SECONDS = 5

/** RFC 8628 3.5: what a `slow_down` adds to the interval, every time one arrives. */
const SLOW_DOWN_INCREMENT_SECONDS = 5

/** How long to keep polling when the server does not say when the code lapses. */
const DEFAULT_EXPIRY_SECONDS = 30 * 60

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

interface DeviceAuthorizationResponse {
  device_code: string
  user_code: string
  verification_uri: string
  /** The same URL with the code already in it, for a device that can show a link or a QR code. */
  verification_uri_complete?: string
  expires_in?: number
  interval?: number
}

export interface DeviceAuthorizationRequest {
  metadata: AuthorizationServerMetadata
  clientInformation: OAuthClientInformationMixed
  scope?: string
  /** RFC 8707 resource indicator, kept the same across both requests as the spec requires. */
  resource?: URL
}

/**
 * Whether this authorization server offers the device grant.
 *
 * The endpoint is what makes it usable, so that is the part we insist on. `grant_types_supported`
 * is only consulted when the server publishes it: plenty of servers offer the endpoint and list
 * nothing, and refusing those would rule out working deployments for a missing advertisement.
 */
export function supportsDeviceAuthorization(metadata: AuthorizationServerMetadata | undefined): boolean {
  if (!metadata?.device_authorization_endpoint) return false

  const grants = metadata.grant_types_supported
  return !Array.isArray(grants) || grants.includes(DEVICE_CODE_GRANT_TYPE)
}

/**
 * Signs in without a browser on this machine, per RFC 8628.
 *
 * The authorization code flow needs a browser and a loopback port to redirect back to, which is
 * exactly what a cron job, an SSH session or a container does not have. The device grant moves the
 * browser to whatever machine the person is actually sitting at: this prints a short code, they
 * enter it wherever they are, and this polls until the server says they did (see issue #228).
 *
 * Resolves with the tokens once approved. The refresh token that comes back is what makes later
 * runs non-interactive, so this should happen once, not once a night.
 */
export async function authorizeWithDeviceCode({
  metadata,
  clientInformation,
  scope,
  resource,
}: DeviceAuthorizationRequest): Promise<OAuthTokens> {
  const deviceAuthorizationEndpoint = metadata.device_authorization_endpoint
  if (typeof deviceAuthorizationEndpoint !== 'string') {
    throw new Error('The authorization server does not offer a device authorization endpoint')
  }
  if (!metadata.token_endpoint) {
    throw new Error('The authorization server metadata has no token endpoint')
  }

  const authMethod = selectClientAuthMethod(clientInformation, metadata.token_endpoint_auth_methods_supported ?? [])

  const authorization = await requestDeviceAuthorization(deviceAuthorizationEndpoint, {
    clientInformation,
    authMethod,
    scope,
    resource,
  })

  // Goes to stderr like everything else here, which MCP clients capture into their own logs. In a
  // headless run that log is the only place anyone can read this, so it is deliberately loud.
  log('')
  log('To authorize this client, visit:')
  log(`  ${authorization.verification_uri_complete ?? authorization.verification_uri}`)
  if (!authorization.verification_uri_complete) {
    log('')
    log(`And enter the code: ${authorization.user_code}`)
  }
  log('')
  log('Waiting for approval...')

  return pollForTokens(metadata.token_endpoint, {
    authorization,
    clientInformation,
    authMethod,
    resource,
  })
}

async function requestDeviceAuthorization(
  endpoint: string,
  options: {
    clientInformation: OAuthClientInformationMixed
    authMethod: string
    scope?: string
    resource?: URL
  },
): Promise<DeviceAuthorizationResponse> {
  const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' })
  const params = new URLSearchParams()
  applyClientAuthentication(options.authMethod, options.clientInformation, headers, params)
  if (options.scope) params.set('scope', options.scope)
  if (options.resource) params.set('resource', options.resource.href)

  debugLog('Requesting device authorization', { endpoint, scope: options.scope })

  const response = await fetch(endpoint, { method: 'POST', headers, body: params })
  if (!response.ok) {
    throw new Error(`Device authorization request failed (HTTP ${response.status}): ${await errorDetail(response)}`)
  }

  const authorization = (await response.json()) as DeviceAuthorizationResponse
  if (!authorization?.device_code || !authorization.user_code || !authorization.verification_uri) {
    throw new Error('The authorization server returned an incomplete device authorization response')
  }

  debugLog('Device authorization issued', {
    verification_uri: authorization.verification_uri,
    expires_in: authorization.expires_in,
    interval: authorization.interval,
  })

  return authorization
}

async function pollForTokens(
  tokenEndpoint: string,
  options: {
    authorization: DeviceAuthorizationResponse
    clientInformation: OAuthClientInformationMixed
    authMethod: string
    resource?: URL
  },
): Promise<OAuthTokens> {
  const { authorization } = options
  let intervalSeconds = authorization.interval ?? DEFAULT_POLL_INTERVAL_SECONDS
  const deadline = Date.now() + (authorization.expires_in ?? DEFAULT_EXPIRY_SECONDS) * 1000

  while (Date.now() < deadline) {
    await delay(intervalSeconds * 1000)

    const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' })
    const params = new URLSearchParams({ grant_type: DEVICE_CODE_GRANT_TYPE, device_code: authorization.device_code })
    applyClientAuthentication(options.authMethod, options.clientInformation, headers, params)
    if (options.resource) params.set('resource', options.resource.href)

    const response = await fetch(tokenEndpoint, { method: 'POST', headers, body: params })
    if (response.ok) {
      log('Authorized.')
      return OAuthTokensSchema.parse(await response.json())
    }

    // Everything below is an error response carrying a reason to keep going, or to stop
    const body = (await response.json().catch(() => undefined)) as { error?: string; error_description?: string } | undefined

    switch (body?.error) {
      case 'authorization_pending':
        // Nobody has entered the code yet, which is the normal state of this loop
        continue
      case 'slow_down':
        // RFC 8628 3.5: back off permanently, not just for this attempt
        intervalSeconds += SLOW_DOWN_INCREMENT_SECONDS
        debugLog('Device token endpoint asked us to slow down', { intervalSeconds })
        continue
      case 'access_denied':
        throw new Error('Authorization was denied')
      case 'expired_token':
        throw new Error('The device code expired before it was approved')
      default:
        throw new Error(
          `Device token request failed (HTTP ${response.status}): ${body?.error_description ?? body?.error ?? 'unknown error'}`,
        )
    }
  }

  throw new Error('The device code expired before it was approved')
}

/**
 * The SDK picks the client authentication method but does not export applying it, so this mirrors
 * `applyClientAuthentication` from `@modelcontextprotocol/sdk/client/auth.js` for our own requests.
 */
export function applyClientAuthentication(
  method: string,
  clientInformation: OAuthClientInformationMixed,
  headers: Headers,
  params: URLSearchParams,
): void {
  const { client_id, client_secret } = clientInformation

  if (method === 'client_secret_basic') {
    if (!client_secret) throw new Error('client_secret_basic authentication requires a client_secret')
    headers.set('Authorization', `Basic ${Buffer.from(`${client_id}:${client_secret}`).toString('base64')}`)
    return
  }

  if (method === 'client_secret_post') {
    params.set('client_id', client_id)
    if (client_secret) params.set('client_secret', client_secret)
    return
  }

  if (method !== 'none') {
    // The SDK throws here rather than guessing, and so does this: falling through would send the
    // client id alone and silently drop a secret the caller supplied, leaving a bare 401 as the
    // only sign that the credential never went anywhere.
    throw new Error(`Unsupported client authentication method: ${method}`)
  }

  params.set('client_id', client_id)
}

async function errorDetail(response: Response): Promise<string> {
  try {
    const text = await response.text()
    return text.slice(0, 500) || response.statusText
  } catch {
    return response.statusText
  }
}
