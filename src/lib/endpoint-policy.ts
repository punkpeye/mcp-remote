import { assertSecureTokenEndpoint, InsecureTokenEndpointError } from '@modelcontextprotocol/client'

/**
 * Where the requests this package sends itself are allowed to go.
 *
 * The SDK holds its own requests - the transports, the code exchange, the refresh - to two rules:
 * credentials go to an https endpoint or a loopback one, and a redirect is followed only within the
 * origin of the request. The grants and probes written here go around the SDK and were held to
 * neither, so a server could have a client secret or a `--header` value delivered somewhere the
 * user never named: by publishing an `http://` endpoint, or by answering with a redirect.
 */

/**
 * Whether credentials may be sent to this endpoint: https, or http on a loopback host.
 *
 * The verdict is the SDK's own, the one its code exchange and refresh already go through, so every
 * grant refuses and allows exactly the same hosts.
 */
export function isSecureEndpoint(endpoint: URL): boolean {
  // The SDK exempts a loopback host whatever its scheme, and fetch speaks only these two
  if (endpoint.protocol !== 'https:' && endpoint.protocol !== 'http:') return false

  try {
    assertSecureTokenEndpoint(endpoint)
    return true
  } catch (error) {
    if (error instanceof InsecureTokenEndpointError) return false
    throw error
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

/** How many redirects to follow before handing back the last one, so that a loop ends. */
const MAX_REDIRECTS = 5

/** The parts of a response that deciding about a redirect takes, common to undici's fetch and the global one. */
interface RedirectableResponse {
  status: number
  url?: string
  headers?: { get(name: string): string | null }
  body?: { cancel(): Promise<void> } | null
}

/** Whether `to` has the scheme, host and port of `from`, or is its https form with both on the default port. */
function isWithinOrigin(from: URL, to: URL): boolean {
  if (from.protocol === to.protocol && from.host === to.host) return true
  return from.protocol === 'http:' && to.protocol === 'https:' && from.hostname === to.hostname && !from.port && !to.port
}

/** Where a redirect `response` to a request for `url` points, if it is one and names somewhere. */
function redirectTarget(url: string | URL, response: RedirectableResponse): URL | undefined {
  const location = REDIRECT_STATUSES.has(response.status) ? response.headers?.get('location') : undefined
  if (!location) return undefined

  try {
    return new URL(location, url)
  } catch {
    return undefined
  }
}

/**
 * Wraps a fetch to follow a redirect only when it stays within the origin of the request and keeps
 * the method. Any other redirect is handed back as the 3xx it was, with nothing sent to its target.
 *
 * Left to itself, fetch follows a redirect anywhere. It drops `Authorization` on the way to another
 * origin and nothing else, so an `X-Api-Key` set with `--header` went along - and on a 307 or 308
 * so did the body, client secret included.
 *
 * This is the SDK's `fetchWithinOrigin`, which it applies to its own requests but does not export.
 */
export function fetchWithinOrigin<Init extends { method?: string }, R extends RedirectableResponse>(
  baseFetch: (url: string | URL, init?: Init) => Promise<R>,
): (url: string | URL, init?: Init) => Promise<R> {
  return async (url, init) => {
    const method = (init?.method ?? 'GET').toUpperCase()
    let current = url

    for (let followed = 0; ; followed++) {
      // `Init` is whichever fetch's own options type, and the compiler cannot see `redirect` in that
      const response = await baseFetch(current, { ...init, redirect: 'manual' } as unknown as Init)

      const target = redirectTarget(current, response)
      if (!target || followed === MAX_REDIRECTS) return response

      const from = new URL(current)
      // A 301, 302 or 303 turns a POST into a GET, which is no longer the request that was asked for
      const keepsMethod = method === 'GET' || response.status === 307 || response.status === 308
      const keepsUserinfo =
        !(target.username || target.password) || (target.username === from.username && target.password === from.password)
      if (!keepsMethod || !keepsUserinfo || !isWithinOrigin(from, target)) return response

      // Nothing reads a redirect's body, and leaving it unread holds the connection open
      await response.body?.cancel().catch(() => {})
      current = target
    }
  }
}

/**
 * POSTs a form that carries credentials, and fails rather than let a redirect carry them elsewhere.
 *
 * A redirect within the origin is still followed: an endpoint that moves a request to its own
 * trailing slash names nobody new. Anything else stops here saying where it pointed, which the
 * bare "HTTP 307" a caller would otherwise report does not.
 *
 * @param name What the endpoint is, for the error
 * @param endpoint Where to send the form
 * @param form The headers and body to send
 * @returns The response, from the endpoint or from wherever in its origin it redirected to
 */
export async function postWithinOrigin(
  name: string,
  endpoint: string,
  form: { headers: Headers; body: URLSearchParams },
): Promise<Response> {
  const response = await fetchWithinOrigin(fetch)(endpoint, { method: 'POST', ...form })

  const target = redirectTarget(response.url || endpoint, response)
  if (!target) return response

  // This goes into a log, and a query string is where a server would have put anything secret
  target.username = target.password = target.search = target.hash = ''
  await response.body?.cancel().catch(() => {})

  throw new Error(
    `The ${name} at ${new URL(endpoint).origin} answered HTTP ${response.status} with a redirect to ${target.href}, ` +
      'which was not followed. A request that carries credentials follows a redirect only when it is a 307 or 308 within the same origin.',
  )
}
