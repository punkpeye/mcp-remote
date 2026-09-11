import { DiscoverResultSchema } from '@modelcontextprotocol/core'
import {
  CLIENT_CAPABILITIES_META_KEY,
  LOG_LEVEL_META_KEY,
  SUBSCRIPTION_ID_META_KEY,
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
 *
 * Only `-32022` qualifies. The other two reserved codes describe a request rather than an era:
 * `-32020` says the headers and body disagree and `-32021` says the client declared too little, and
 * neither tells us which era answered. Treating them as evidence would report a version problem for
 * something that is not one, and end the connection over it.
 */
const MODERN_ERROR_CODES = new Set([
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
    if (code === undefined || !MODERN_ERROR_CODES.has(code)) {
      return { era: 'legacy', reason: `the server answered server/discover with error ${code}` }
    }

    const supported = parseSupportedVersions(message.error.data)
    const version = supported && chooseModernVersion(supported)
    if (version) {
      // The probe already offered this, so being asked for it again is a server we cannot follow
      return { era: 'incompatible', reason: `the server asked for protocol version ${version}, which the probe already offered` }
    }

    // A server offering a pre-2026 revision is one the local client may well speak natively, and
    // the handshake it was about to send is exactly how it would find out. Falling back there is
    // the answer the compatibility matrix gives, not a guess.
    if (!supported || supported.some((offered) => offered < FIRST_MODERN_PROTOCOL_VERSION)) {
      return {
        era: 'legacy',
        reason: `the server offers no modern revision this proxy speaks${supported ? ` (it offers ${supported.join(', ')})` : ''}`,
      }
    }

    // Every revision it offers is newer than anything here, and none of them is one the client
    // could fall back to. Saying so beats a handshake that can only fail less legibly.
    return {
      era: 'incompatible',
      reason: `the server offers ${supported.join(', ')}, and this proxy speaks ${SUPPORTED_MODERN_VERSIONS.join(', ')}`,
    }
  }

  const parsed = DiscoverResultSchema.safeParse(message.result)
  if (!parsed.success) {
    return { era: 'legacy', reason: 'the server answered server/discover with something that is not a DiscoverResult' }
  }

  // Parsed to validate, but the server's own object is what gets carried forward: capabilities are
  // explicitly not a closed set, and the schema strips every key it does not know about - including
  // the vendor capabilities a client may well understand
  const discover = { ...(parsed.data as DiscoverResult), capabilities: (message.result as DiscoverResult).capabilities }
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
 * The `supported` list out of an error's `data`, if it is really a list of revisions.
 *
 * It arrives from the server, so it is checked rather than trusted: a bare string would otherwise
 * match by substring, and a number would throw somewhere far less obvious than here.
 */
function parseSupportedVersions(data: unknown): string[] | undefined {
  const supported = (data as { supported?: unknown } | undefined)?.supported
  if (!Array.isArray(supported)) return undefined

  const versions = supported.filter((entry): entry is string => typeof entry === 'string')
  return versions.length > 0 ? versions : undefined
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
/**
 * Adds the minimum log level a legacy client asked for, where the modern era reads it.
 *
 * `logging/setLevel` set it once for a session; the 2026-07-28 era has no session to set it on and
 * reads it per request instead - and reads its absence as "send no logs at all", so a client that
 * asked for logging and then got none would have no way to tell why.
 */
export function stampLogLevel<T extends { params?: any }>(message: T, logLevel: string | undefined): T {
  if (!logLevel) return message

  return { ...message, params: { ...message.params, _meta: { ...message.params?._meta, [LOG_LEVEL_META_KEY]: logLevel } } }
}

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
const ANSWERED_LOCALLY: Record<string, Record<string, unknown>> = Object.assign(Object.create(null), {
  ping: {},
  // The 2026-07-28 era replaced these with the `subscriptions/listen` stream this proxy already
  // holds open, and with a per-request `_meta` key. The client still calls them, because the
  // capabilities it was handed still advertise them - so they are honoured here rather than sent to
  // a server that no longer has the methods.
  'resources/subscribe': {},
  'resources/unsubscribe': {},
  'logging/setLevel': {},
})

export const localAnswerFor = (method: string): Record<string, unknown> | undefined => ANSWERED_LOCALLY[method]

/** Methods the modern era retired, whose effect this proxy reproduces some other way. */
export const RETIRED_IN_MODERN_ERA = {
  subscribeResource: 'resources/subscribe',
  unsubscribeResource: 'resources/unsubscribe',
  setLogLevel: 'logging/setLevel',
} as const

/**
 * Notifications that mean nothing to a 2026-07-28 server, and so are dropped rather than forwarded.
 *
 * `notifications/initialized` closed a handshake that no longer happens. Forwarding it would put an
 * unknown method on the wire for no reason; the local client is never told, because from its side
 * the handshake did complete - this proxy answered it.
 */
const DROPPED_NOTIFICATIONS = new Set([
  'notifications/initialized',
  // Not in the 2026-07-28 notification registry: the era carries client capabilities on every
  // request instead, so a change to them is simply reflected in the next one this proxy stamps
  'notifications/roots/list_changed',
])

export const isDroppedInModernEra = (method: string): boolean => DROPPED_NOTIFICATIONS.has(method)

/**
 * Notifications the modern era sends that a 2025-era client has no idea what to do with.
 *
 * `notifications/subscriptions/acknowledged` confirms a stream this proxy opened on the client's
 * behalf - it answers a question the client never asked, and forwarding it only invites the client's
 * SDK to complain about a method it has never heard of. The change notifications that arrive on the
 * same stream are a different matter: those are exactly what the client is waiting for.
 */
const MODERN_ONLY_NOTIFICATIONS = new Set(['notifications/subscriptions/acknowledged'])

export const isModernOnlyNotification = (method: string): boolean => MODERN_ONLY_NOTIFICATIONS.has(method)

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

/**
 * The subscription a legacy client would never ask for, but behaves as though it had.
 *
 * A 2025-era client expects `notifications/tools/list_changed` and friends to simply arrive; the
 * modern era only sends them down a stream the client opened with `subscriptions/listen`. Since the
 * client will never open one, this proxy opens it on its behalf - asking for exactly the change
 * notifications the server said it can send, and nothing else.
 *
 * @param capabilities What `server/discover` advertised
 * @returns The filter to listen with, or undefined if the server announces no changes at all
 */
export function subscriptionFilterFor(capabilities: Record<string, unknown> | undefined, resourceSubscriptions: string[] = []) {
  const tools = capabilities?.tools as { listChanged?: boolean } | undefined
  const prompts = capabilities?.prompts as { listChanged?: boolean } | undefined
  const resources = capabilities?.resources as { listChanged?: boolean } | undefined

  const filter = {
    ...(tools?.listChanged ? { toolsListChanged: true } : {}),
    ...(prompts?.listChanged ? { promptsListChanged: true } : {}),
    ...(resources?.listChanged ? { resourcesListChanged: true } : {}),
    ...(resourceSubscriptions.length > 0 ? { resourceSubscriptions } : {}),
  }

  return Object.keys(filter).length > 0 ? filter : undefined
}

/**
 * What the server actually agreed to, compared with what was asked for.
 *
 * The spec has the client check the acknowledgment rather than assume it, because a server may
 * honour only part of a filter - and a notification type it quietly dropped is one the client will
 * wait for forever with nothing to say why.
 *
 * @returns The names of the notification types that were asked for and not acknowledged
 */
export function unacknowledgedSubscriptions(requested: Record<string, unknown>, acknowledged: unknown): string[] {
  if (!acknowledged || typeof acknowledged !== 'object') return []

  const granted = acknowledged as Record<string, unknown>
  return Object.keys(requested).filter((key) => {
    if (key === 'resourceSubscriptions') {
      const asked = requested[key] as string[]
      const got = Array.isArray(granted[key]) ? (granted[key] as string[]) : []
      return asked.some((uri) => !got.includes(uri))
    }
    return !granted[key]
  })
}

/** The `subscriptions/listen` request, written in the modern era like everything else. */
export function subscriptionsListenRequest(
  id: string,
  identity: LegacyClientIdentity,
  version: string,
  notifications: Record<string, unknown>,
) {
  return stampModernMeta({ jsonrpc: '2.0' as const, id, method: 'subscriptions/listen', params: { notifications } }, identity, version)
}

/**
 * Strips the correlation the modern era adds to a streamed notification.
 *
 * The notification itself is already in terms a 2025-era client knows - same method, same params -
 * because only its delivery changed. What it carries that the client has no use for is the id of
 * the subscription it arrived on, which would be the one part of the message that could not have
 * come from a 2025 server.
 */
export function stripSubscriptionMeta(message: { params?: any }) {
  const meta = message.params?._meta
  if (!meta || !(SUBSCRIPTION_ID_META_KEY in meta)) return message

  const { [SUBSCRIPTION_ID_META_KEY]: _subscriptionId, ...rest } = meta
  const params = { ...message.params }
  if (Object.keys(rest).length > 0) {
    params._meta = rest
  } else {
    delete params._meta
  }

  return { ...message, params }
}

/**
 * How many times a single request may come back asking for more input before this gives up.
 *
 * Matches the SDK's own driver. A server that keeps asking is either in a loop or negotiating
 * something a proxy has no business mediating; either way the client is better told.
 */
export const MAX_INPUT_REQUIRED_ROUNDS = 10

/** Whether this result is the modern era asking for more input rather than answering. */
export const isInputRequiredResult = (result: any): boolean => result?.resultType === 'input_required'

/**
 * The params to retry a multi-round-trip request with.
 *
 * `requestState` is echoed back byte for byte: it is the server's own opaque handle on the exchange,
 * and the spec has it treat anything that came back through a client as attacker-controlled, so
 * touching it here could only ever break a server that checks its integrity.
 */
export function inputRequiredRetryParams(originalParams: any, responses: Record<string, unknown>, requestState: string | undefined) {
  const hasResponses = Object.keys(responses).length > 0

  return {
    ...originalParams,
    ...(hasResponses ? { inputResponses: responses } : {}),
    ...(requestState !== undefined ? { requestState } : {}),
  }
}

/**
 * The 2025-era requests a server can embed in an `input_required` result.
 *
 * Each one is a server-initiated request in its own right, and a 2025 client already knows how to
 * answer all three - that era simply had the server send them directly rather than embed them. So
 * the bridge does not translate them at all: it unpacks them, asks the client, and packs the
 * answers back.
 */
const FULFILLABLE_INPUT_METHODS = new Set(['sampling/createMessage', 'roots/list', 'elicitation/create'])

/**
 * Whether an embedded question can be put to a 2025-era client as it stands.
 *
 * The three methods survive the era change unchanged - except for one shape. URL-mode elicitation is
 * a 2026 addition: the revision that introduced it also removed the `elicitationId` that
 * `2025-11-25` requires, along with the `notifications/elicitation/complete` channel that id keyed.
 * Forwarded as it arrives it is a request the client's own SDK rejects as invalid, with no way to
 * report completion even if it did not - so it is refused here, where the reason can be said.
 */
export function canFulfilInputRequest(method: string, params?: unknown): boolean {
  if (!FULFILLABLE_INPUT_METHODS.has(method)) return false
  if (method === 'elicitation/create' && (params as { mode?: string } | undefined)?.mode === 'url') return false
  return true
}

/** The capability a client must have declared before it can be asked one of these questions. */
const CAPABILITY_FOR_INPUT_METHOD: Record<string, string> = Object.assign(Object.create(null), {
  'sampling/createMessage': 'sampling',
  'roots/list': 'roots',
  'elicitation/create': 'elicitation',
})

/**
 * Whether the client said, in its handshake, that it can answer this kind of question.
 *
 * A 2025-era server had to read that declaration before sending one of these; moving the question
 * into a result does not license skipping it. Asking regardless only earns a `-32601` that then
 * fails the tool call the client actually wanted.
 */
export function clientDeclaredCapabilityFor(method: string, capabilities: Record<string, unknown> | undefined): boolean {
  const required = CAPABILITY_FOR_INPUT_METHOD[method]
  if (!required) return false
  return capabilities?.[required] !== undefined
}

/** How many questions a server may embed in one answer before this refuses to relay them. */
export const MAX_INPUT_REQUESTS_PER_ROUND = 8
