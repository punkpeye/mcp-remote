import { OAuthTokensSchema } from '@modelcontextprotocol/core'
import { selectClientAuthMethod } from '@modelcontextprotocol/client'
import type { OAuthClientInformationMixed, OAuthTokens } from '@modelcontextprotocol/client'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'
import { applyClientAuthentication } from './device-authorization'
import { log, debugLog } from './utils'

/**
 * Signing in as the software itself, per RFC 6749 section 4.4.
 *
 * There is no user in this grant and no consent to collect: the client presents its own credentials
 * and is handed a token for itself. That suits the servers people actually run into here - an
 * internal one behind a machine-to-machine client, reached by a CLI on a schedule - where the
 * authorization code flow's browser and loopback port are not missing by accident but by design,
 * and where the device grant's "go and approve this somewhere" is equally beside the point
 * (see https://github.com/punkpeye/mcp-remote/issues/350).
 *
 * No refresh token comes back, and none is wanted: the credentials are the durable thing, so a
 * token that has expired is replaced by asking for another exactly the way this one was obtained.
 */
export async function authorizeWithClientCredentials({
  metadata,
  clientInformation,
  scope,
  resource,
}: {
  metadata: AuthorizationServerMetadata
  clientInformation: OAuthClientInformationMixed
  scope?: string
  resource?: URL
}): Promise<OAuthTokens> {
  const tokenEndpoint = metadata.token_endpoint
  if (typeof tokenEndpoint !== 'string') {
    throw new Error('The authorization server metadata has no token endpoint')
  }

  if (!clientInformation.client_secret) {
    throw new Error(
      'The client_credentials grant needs a client secret. Supply one with --static-oauth-client-info, ' +
        'which accepts `@path/to/file.json` and `${ENV_VAR}` placeholders so the secret need not sit in the command line.',
    )
  }

  const authMethod = selectClientAuthMethod(clientInformation, metadata.token_endpoint_auth_methods_supported ?? [])

  const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' })
  const params = new URLSearchParams({ grant_type: 'client_credentials' })
  applyClientAuthentication(authMethod, clientInformation, headers, params)
  if (scope) params.set('scope', scope)
  // RFC 8707: name the MCP server this token is for, so an authorization server that issues
  // audience-bound tokens issues one this server will accept
  if (resource) params.set('resource', resource.href)

  debugLog('Requesting a token with the client_credentials grant', { tokenEndpoint, authMethod, scope, resource: resource?.href })

  const response = await fetch(tokenEndpoint, { method: 'POST', headers, body: params })

  if (!response.ok) {
    const body = (await response.json().catch(() => undefined)) as { error?: string; error_description?: string } | undefined
    throw new Error(
      `The client_credentials token request failed (HTTP ${response.status}): ${body?.error_description ?? body?.error ?? 'unknown error'}`,
    )
  }

  const tokens = OAuthTokensSchema.parse(await response.json())
  log('Signed in with the client_credentials grant')
  return tokens
}
