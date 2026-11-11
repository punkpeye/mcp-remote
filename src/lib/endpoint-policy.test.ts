import { describe, it, expect, vi, afterEach } from 'vitest'
import http from 'http'
import net from 'net'
import { fetch as undiciFetch } from 'undici'
import { fetchWithinOrigin, isSecureEndpoint, postWithinOrigin } from './endpoint-policy'

type Seen = { method: string; url: string; headers: http.IncomingHttpHeaders; body: string }

const opened: http.Server[] = []

/** A server that records what reaches it, and answers however `respond` decides. */
async function serve(respond: (request: Seen, res: http.ServerResponse) => void): Promise<{ origin: string; seen: Seen[] }> {
  const seen: Seen[] = []
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => {
      const request = { method: req.method!, url: req.url!, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') }
      seen.push(request)
      respond(request, res)
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  opened.push(server)
  return { origin: `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`, seen }
}

/** Somewhere that is not the server being asked: it records what reaches it. */
const elsewhere = () => serve((_request, res) => res.writeHead(200, { 'content-type': 'application/json' }).end('{}'))

const redirect = (status: number, location: string) => new Response(null, { status, headers: { location } })

const form = () => ({
  headers: new Headers({ 'content-type': 'application/x-www-form-urlencoded' }),
  body: new URLSearchParams({ client_id: 'c1', client_secret: 'shh' }),
})

afterEach(async () => {
  for (const server of opened.splice(0)) {
    server.closeAllConnections()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
  vi.unstubAllGlobals()
})

describe('Feature: Deciding where credentials may be sent', () => {
  it('Scenario: An https endpoint is accepted wherever it is', () => {
    expect(isSecureEndpoint(new URL('https://auth.example.com/token'))).toBe(true)
  })

  it.each(['http://localhost:9000/token', 'http://127.0.0.1:9000/token', 'http://[::1]:9000/token', 'http://auth.localhost/token'])(
    'Scenario: Plain http is accepted on a loopback host, for local development (%s)',
    (endpoint) => {
      expect(isSecureEndpoint(new URL(endpoint))).toBe(true)
    },
  )

  it.each([
    'http://auth.example.com/token',
    'http://192.168.1.10/token',
    'http://0.0.0.0:9000/token',
    // Names that only begin like a loopback host
    'http://localhost.example.com/token',
    'http://127.0.0.1.example.com/token',
  ])('Scenario: Plain http anywhere else is refused (%s)', (endpoint) => {
    expect(isSecureEndpoint(new URL(endpoint))).toBe(false)
  })

  it('Scenario: A scheme fetch does not speak is refused, even on a loopback host', () => {
    expect(isSecureEndpoint(new URL('ftp://localhost/token'))).toBe(false)
  })
})

describe('Feature: Following a redirect only within the origin of the request', () => {
  it.each([
    ['the global fetch', fetch],
    ["undici's fetch", undiciFetch],
  ] as const)('Scenario: A redirect to another origin is handed back and nothing is sent there (%s)', async (_name, baseFetch) => {
    // Given a server that answers with a redirect to somewhere else
    const other = await elsewhere()
    const server = await serve((request, res) => res.writeHead(307, { location: `${other.origin}${request.url}` }).end())

    // When a request carrying a header set for that server is sent
    const response = await fetchWithinOrigin(baseFetch as typeof fetch)(`${server.origin}/mcp`, { headers: { 'X-Api-Key': 'secret' } })

    // Then the redirect comes back as it was, and the other origin never hears of it
    expect(response.status).toBe(307)
    expect(response.headers.get('location')).toBe(`${other.origin}/mcp`)
    expect(other.seen).toEqual([])
  })

  it('Scenario: A redirect within the origin is followed with the request as it was', async () => {
    // Given a server that moves a request to its own trailing slash
    const server = await serve((request, res) => {
      if (request.url === '/token') res.writeHead(307, { location: '/token/' }).end()
      else res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}')
    })

    const response = await fetchWithinOrigin(fetch)(`${server.origin}/token`, { method: 'POST', ...form() })

    // Then the second request is the first one again, headers and body included
    expect(response.status).toBe(200)
    expect(server.seen.map((request) => `${request.method} ${request.url}`)).toEqual(['POST /token', 'POST /token/'])
    expect(new URLSearchParams(server.seen[1].body).get('client_secret')).toBe('shh')
  })

  it('Scenario: A redirect that would turn a POST into a GET is handed back', async () => {
    const server = await serve((request, res) => {
      if (request.url === '/token') res.writeHead(302, { location: '/login' }).end()
      else res.writeHead(200).end()
    })

    const response = await fetchWithinOrigin(fetch)(`${server.origin}/token`, { method: 'POST', ...form() })

    expect(response.status).toBe(302)
    expect(server.seen).toHaveLength(1)
  })

  it('Scenario: A GET follows any kind of redirect within the origin', async () => {
    const server = await serve((request, res) => {
      if (request.url === '/mcp') res.writeHead(302, { location: '/v2/mcp' }).end()
      else res.writeHead(401).end()
    })

    const response = await fetchWithinOrigin(fetch)(`${server.origin}/mcp`, { headers: { 'X-Api-Key': 'secret' } })

    expect(response.status).toBe(401)
    expect(server.seen[1].url).toBe('/v2/mcp')
    expect(server.seen[1].headers['x-api-key']).toBe('secret')
  })

  it('Scenario: A server that redirects to itself forever is given up on', async () => {
    const server = await serve((_request, res) => res.writeHead(307, { location: '/mcp' }).end())

    const response = await fetchWithinOrigin(fetch)(`${server.origin}/mcp`)

    // Then the last redirect comes back after the first request and five more
    expect(response.status).toBe(307)
    expect(server.seen).toHaveLength(6)
  })

  it('Scenario: The https form of a plain-http server is the same server', async () => {
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(redirect(301, 'https://mcp.example.com/mcp'))
      .mockResolvedValueOnce(new Response('{}', { status: 200 }))

    const response = await fetchWithinOrigin(baseFetch)('http://mcp.example.com/mcp')

    expect(response.status).toBe(200)
    expect(String(baseFetch.mock.calls[1][0])).toBe('https://mcp.example.com/mcp')
  })

  it.each([
    ['from https down to plain http', 'https://mcp.example.com/mcp', 'http://mcp.example.com/mcp'],
    ['to another port', 'https://mcp.example.com/mcp', 'https://mcp.example.com:8443/mcp'],
    ['to https on a port the request did not name', 'http://mcp.example.com:8080/mcp', 'https://mcp.example.com/mcp'],
    ['to a subdomain', 'https://mcp.example.com/mcp', 'https://eu.mcp.example.com/mcp'],
    ['to the same host with credentials added', 'https://mcp.example.com/mcp', 'https://user:pass@mcp.example.com/mcp'],
  ])('Scenario: A redirect %s is not followed', async (_change, from, to) => {
    const baseFetch = vi.fn().mockResolvedValueOnce(redirect(307, to))

    const response = await fetchWithinOrigin(baseFetch)(from)

    expect(response.status).toBe(307)
    expect(baseFetch).toHaveBeenCalledTimes(1)
  })

  it('Scenario: Every request is sent with redirects left to this, not to fetch', async () => {
    const baseFetch = vi.fn().mockResolvedValueOnce(new Response('{}', { status: 200 }))

    await fetchWithinOrigin(baseFetch)('https://mcp.example.com/mcp', { method: 'GET' })

    expect(baseFetch.mock.calls[0][1]).toMatchObject({ method: 'GET', redirect: 'manual' })
  })
})

describe('Feature: Posting credentials no further than the endpoint they were meant for', () => {
  it('Scenario: A redirect to another origin fails, and the form goes nowhere else', async () => {
    // Given a token endpoint that answers with a redirect to somewhere else
    const other = await elsewhere()
    const server = await serve((_request, res) => res.writeHead(307, { location: `${other.origin}/token?session=abc#frag` }).end())

    // When the credentials are posted to it
    const error: Error = await postWithinOrigin('token endpoint', `${server.origin}/token`, form()).catch((thrown) => thrown)

    // Then it fails saying where the endpoint pointed, without the query a secret could sit in
    expect(error.message).toContain(
      `The token endpoint at ${server.origin} answered HTTP 307 with a redirect to ${other.origin}/token, which was not followed`,
    )
    expect(error.message).not.toContain('session=abc')

    // And the other origin never received the form
    expect(other.seen).toEqual([])
    expect(server.seen).toHaveLength(1)
  })

  it('Scenario: A redirect within the origin still delivers the form', async () => {
    const server = await serve((request, res) => {
      if (request.url === '/token') res.writeHead(308, { location: '/token/' }).end()
      else res.writeHead(200, { 'content-type': 'application/json' }).end('{"access_token":"at"}')
    })

    const response = await postWithinOrigin('token endpoint', `${server.origin}/token`, form())

    expect(await response.json()).toEqual({ access_token: 'at' })
    expect(new URLSearchParams(server.seen[1].body).get('client_secret')).toBe('shh')
  })

  it('Scenario: An answer that is not a redirect comes back untouched, refusals included', async () => {
    const server = await serve((_request, res) =>
      res.writeHead(401, { 'content-type': 'application/json' }).end('{"error":"invalid_client"}'),
    )

    const response = await postWithinOrigin('token endpoint', `${server.origin}/token`, form())

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_client' })
  })
})
