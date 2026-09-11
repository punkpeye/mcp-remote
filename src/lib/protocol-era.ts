import { DiscoverResultSchema } from '@modelcontextprotocol/core'
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  LATEST_PROTOCOL_VERSION,
  PROTOCOL_VERSION_META_KEY,
  SERVER_INFO_META_KEY,
  SUPPORTED_PROTOCOL_VERSIONS,
} from '@modelcontextprotocol/client'

/**
 * Bridging a `2025-11-25`-era local client to a `2026-07-28` remote server.
 *
 * The 2026-07-28 revision retired the `initialize` handshake and the session behind it: a request
 * now carries its own protocol version, client identity and capabilities in `_meta`, and a server
 * advertises itself through `server/discover` rather than answering a handshake. The spec's own
 * compatibility matrix puts a legacy client against a modern server in the one cell that simply
 * fails - "legacy clients have no fall-forward mechanism" - and names the fix: a *dual-era client*,
 * which is what this proxy becomes when the bridge is on.
 *
 * mcp-remote is the only thing in the chain that can be dual-era. The local client is whatever the
 * user's desktop host ships, and the remote server has already moved on; between them sits a proxy
 * that reads every message anyway. So the handshake is answered here, from a `server/discover`
 * result, and every request the client sends afterwards is stamped with the metadata the modern
 * server requires. Neither end has to know.
 */

/** The first protocol revision that carries its version per request instead of negotiating one. */
const FIRST_MODERN_PROTOCOL_VERSION = '2026-07-28'

/** The modern revisions this proxy can translate to, newest first. */
const SUPPORTED_MODERN_VERSIONS = [FIRST_MODERN_PROTOCOL_VERSION]

/**
 * How hard to look for a modern server.
 *
 * `legacy` is the default and the behaviour every release before this one had: the client's
 * `initialize` goes straight to the server and nothing probes anything. `auto` spends one
 * `server/discover` round trip on the first handshake and bridges only if it finds a modern server.
 */
export type ProtocolMode = 'legacy' | 'auto'

/** What the local client said about itself, replayed into the `_meta` of every modern request. */
export type LegacyClientIdentity = {
  protocolVersion?: string
  capabilities?: Record<string, unknown>
  clientInfo?: { name?: string; version?: string }
}

type DiscoverResult = {
  supportedVersions: string[]
  capabilities: Record<string, unknown>
  instructions?: string
  _meta?: Record<string, unknown>
}

/** What the probe concluded, and everything the bridge needs if the answer was "modern". */
export type EraVerdict =
  | { era: 'legacy'; reason: string }
  | { era: 'modern'; version: string; discover: DiscoverResult }
  | { era: 'incompatible'; reason: string }

/**
 * Error codes the 2026-07-28 revision reserves for itself.
 *
 * Their job here is not to be handled individually but to be *recognised*: the spec makes a modern
 * error the proof that a modern server answered, so anything outside this set - a `-32601` for an
 * unknown method, an HTTP-level failure, a parse error - is a legacy server saying it has never
 * heard of `server/discover`.
 */
const MODERN_ERROR_CODES = new Set([
  -32020, // HeaderMismatch
  -32021, // MissingRequiredClientCapability
  -32022, // UnsupportedProtocolVersion
])

/** The `server/discover` request, carrying the same `_meta` every other modern request will. */
export function discoverRequest(id: string, identity: LegacyClientIdentity, version = FIRST_MODERN_PROTOCOL_VERSION) {
  return stampModernMeta({ jsonrpc: '2.0' as const, id, method: 'server/discover', params: {} }, identity, version)
}

/**
 * Reads the probe's answer as evidence of which era the server belongs to.
 *
 * @param message The response to the `server/discover` request
 * @returns Which era answered, and the version to speak if it was modern
 */
export function readEraFromDiscoverResponse(message: { result?: unknown; error?: { code?: number; data?: unknown } }): EraVerdict {
  if (message.error) {
    const { code } = message.error
    if (code !== undefined && MODERN_ERROR_CODES.has(code)) {
      // A modern server that will not speak any revision we know. Falling back to `initialize`
      // would be worse than failing: it cannot work, and it would hide why.
      const supported = (message.error.data as { supported?: string[] } | undefined)?.supported
      const version = supported && chooseModernVersion(supported)
      if (!version) {
        return {
          era: 'incompatible',
          reason: `the server is on the 2026-07-28 era but offers no revision this proxy speaks${
            supported ? ` (it offers ${supported.join(', ')})` : ''
          }`,
        }
      }
      return { era: 'incompatible', reason: `the server asked for protocol version ${version}, which the probe already offered` }
    }
    return { era: 'legacy', reason: `the server answered server/discover with error ${code}` }
  }

  const parsed = DiscoverResultSchema.safeParse(message.result)
  if (!parsed.success) {
    return { era: 'legacy', reason: 'the server answered server/discover with something that is not a DiscoverResult' }
  }

  const discover = parsed.data as DiscoverResult
  const version = chooseModernVersion(discover.supportedVersions)
  if (!version) {
    return {
      era: 'incompatible',
      reason: `the server offers ${discover.supportedVersions.join(', ')}, and this proxy speaks ${SUPPORTED_MODERN_VERSIONS.join(', ')}`,
    }
  }

  return { era: 'modern', version, discover }
}

/** The newest revision both sides know, or undefined if there is no overlap. */
function chooseModernVersion(supportedVersions: string[]): string | undefined {
  return SUPPORTED_MODERN_VERSIONS.find((candidate) => supportedVersions.includes(candidate))
}

/**
 * Builds the `InitializeResult` the local client is waiting for out of what `server/discover` said.
 *
 * The client asked a question the server no longer answers, so this proxy answers it instead. The
 * version reported back is the client's own, not the remote server's: the two ends are in different
 * eras by definition here, and telling a 2025-era client about a 2026 revision would only invite it
 * to speak one this proxy would then have to translate back.
 *
 * @param discover What the remote server advertised
 * @param identity What the local client said in its `initialize`
 * @returns The result to answer the client's `initialize` with
 */
export function synthesizeInitializeResult(discover: DiscoverResult, identity: LegacyClientIdentity) {
  const requested = identity.protocolVersion
  const protocolVersion = requested && SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : LATEST_PROTOCOL_VERSION

  const advertised = discover._meta?.[SERVER_INFO_META_KEY] as { name?: string; version?: string } | undefined
  const serverInfo = advertised?.name ? advertised : { name: 'remote MCP server', version: FIRST_MODERN_PROTOCOL_VERSION }

  return {
    protocolVersion,
    capabilities: discover.capabilities ?? {},
    serverInfo,
    ...(discover.instructions ? { instructions: discover.instructions } : {}),
  }
}

/**
 * Adds the per-request metadata a 2026-07-28 server requires, leaving anything already there alone.
 *
 * `protocolVersion` and `clientCapabilities` are both mandatory on every request - a server must
 * reject a request missing either with `-32602` - and `clientInfo` is a SHOULD. The version here has
 * to agree with the `MCP-Protocol-Version` header the transport sends, or the server answers
 * `-32020`, which is the failure that opened this whole thread.
 *
 * @param message The request on its way to the remote server
 * @param identity What the local client said in its `initialize`
 * @param version The revision being spoken to the remote server
 * @returns The same request with its `_meta` filled in
 */
export function stampModernMeta<T extends { params?: any }>(
  message: T,
  identity: LegacyClientIdentity,
  version: string,
): T & { params: Record<string, any> } {
  const existing = message.params?._meta ?? {}

  return {
    ...message,
    params: {
      ...message.params,
      _meta: {
        ...existing,
        [PROTOCOL_VERSION_META_KEY]: existing[PROTOCOL_VERSION_META_KEY] ?? version,
        [CLIENT_CAPABILITIES_META_KEY]: existing[CLIENT_CAPABILITIES_META_KEY] ?? identity.capabilities ?? {},
        ...(identity.clientInfo ? { [CLIENT_INFO_META_KEY]: existing[CLIENT_INFO_META_KEY] ?? identity.clientInfo } : {}),
      },
    },
  }
}

/**
 * Methods a 2026-07-28 server has no answer for, which this proxy therefore answers itself.
 *
 * `ping` is the one that matters in practice: it is simply gone from the modern era, and a client
 * that pings an idle connection - or a keep-alive doing it on the client's behalf - would otherwise
 * collect an error for a liveness check that was always meant to be cheap. Answering it here is
 * honest, because in a stateless era there is no session whose liveness could be in doubt.
 */
const ANSWERED_LOCALLY: Record<string, Record<string, unknown>> = { ping: {} }

export const localAnswerFor = (method: string): Record<string, unknown> | undefined => ANSWERED_LOCALLY[method]

/**
 * Notifications that mean nothing to a 2026-07-28 server, and so are dropped rather than forwarded.
 *
 * `notifications/initialized` closed a handshake that no longer happens. Forwarding it would put an
 * unknown method on the wire for no reason; the local client is never told, because from its side
 * the handshake did complete - this proxy answered it.
 */
const DROPPED_NOTIFICATIONS = new Set(['notifications/initialized'])

export const isDroppedInModernEra = (method: string): boolean => DROPPED_NOTIFICATIONS.has(method)

/**
 * Renders a modern result in terms a 2025-era client understands.
 *
 * The modern era tags every result with a `resultType`, and adds one - `input_required` - that has
 * no 2025 equivalent at all: it is the server asking for sampling, elicitation or roots mid-request,
 * and a client from before multi-round-trip requests has nowhere to put the question. That case is
 * reported as an error rather than passed through as a result the client would silently misread.
 *
 * @param result The `result` a modern server returned
 * @returns The result to hand the local client, or the error explaining why there is none
 */
export function translateModernResult(result: any): { result: any } | { error: { code: number; message: string } } {
  if (!result || typeof result !== 'object') return { result }

  const { resultType, ...rest } = result

  if (resultType === undefined || resultType === 'complete') {
    return { result: rest }
  }

  if (resultType === 'input_required') {
    return {
      error: {
        code: -32603,
        message:
          'The remote server asked for more input mid-request (a 2026-07-28 multi-round-trip request). ' +
          'The local client speaks a protocol revision with no way to answer that, so the request cannot be completed.',
      },
    }
  }

  return {
    error: { code: -32603, message: `The remote server returned a result of an unrecognised type: ${String(resultType)}` },
  }
}
