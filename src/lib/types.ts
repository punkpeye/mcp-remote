import { EventEmitter } from 'events'
import type { OAuthClientInformationFull, OAuthClientMetadata } from '@modelcontextprotocol/client'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'
import type { ProtectedResourceMetadata } from './protected-resource-metadata'

/**
 * Options for creating an OAuth client provider
 */
export interface OAuthProviderOptions {
  /** Server URL to connect to */
  serverUrl: string
  /** The actual MCP server URL, for the RFC 8707 resource indicator. Defaults to `serverUrl`, which is the authorization server once discovery has run. */
  resourceServerUrl?: string
  /** Port for the OAuth callback server */
  callbackPort: number
  /** Desired hostname for the OAuth callback server */
  host: string
  /** Path for the OAuth callback endpoint */
  callbackPath?: string
  /** Directory to store OAuth credentials */
  configDir?: string
  /** Client name to use for OAuth registration */
  clientName?: string
  /** Client URI to use for OAuth registration */
  clientUri?: string
  /** Software ID to use for OAuth registration */
  softwareId?: string
  /** Software version to use for OAuth registration */
  softwareVersion?: string
  /** Static OAuth client metadata to override default OAuth client metadata */
  staticOAuthClientMetadata?: StaticOAuthClientMetadata
  /** Static OAuth client information to use instead of OAuth registration */
  staticOAuthClientInfo?: StaticOAuthClientInformationFull
  /** URL of a Client ID Metadata Document (SEP-991), used as the client_id instead of registering */
  clientMetadataUrl?: string
  /** Present the OIDC ID token as the Bearer credential instead of the access token */
  useIdToken?: boolean
  /** Sign in with the OAuth device grant (RFC 8628) rather than a browser on this machine */
  useDeviceCode?: boolean
  /** Sign in as the software itself with the RFC 6749 `client_credentials` grant */
  useClientCredentials?: boolean
  /** Resource parameter to send to the authorization server */
  authorizeResource?: string
  /** Omit the RFC 8707 resource parameter entirely (some servers reject it, e.g. Entra ID v2) */
  skipResourceParameter?: boolean
  /** Extra query parameters to add to the authorization URL, for servers that require their own */
  authorizeParams?: Record<string, string>
  /** Pre-calculated server URL hash for cache isolation */
  serverUrlHash: string
  /** Authorization server metadata (optional, fetched if not provided) */
  authorizationServerMetadata?: AuthorizationServerMetadata
  /** Protected resource metadata (optional, discovered from 401 response) */
  protectedResourceMetadata?: ProtectedResourceMetadata
  /** Scope extracted from WWW-Authenticate header */
  wwwAuthenticateScope?: string
}

/**
 * OAuth callback server setup options
 */
export interface OAuthCallbackServerOptions {
  /** Port for the callback server */
  port: number
  /** Path for the callback endpoint */
  path: string
  /** Event emitter to signal when auth code is received */
  events: EventEmitter
  /** Timeout in milliseconds for the auth callback server's long poll */
  authTimeoutMs?: number
  /** Identifies which server this callback server belongs to, for the identity probe */
  serverUrlHash: string
}

/** An authorization code, with the state identifying the flow it belongs to. */
export type AuthCodeResult = {
  code: string
  state?: string
}

/*
 * How often, if ever, to ping the remote server so an idle connection is not reaped
 */
export interface KeepAliveConfig {
  enabled: boolean
  intervalMs: number
}

// optional tatic OAuth client information
export type StaticOAuthClientMetadata = OAuthClientMetadata | null | undefined
export type StaticOAuthClientInformationFull = OAuthClientInformationFull | null | undefined
