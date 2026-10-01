import express from 'express'
import type { Server } from 'http'
import type { AddressInfo } from 'net'
import { createHash, randomUUID } from 'crypto'

/**
 * What the authorization server saw, counted where it cannot be faked.
 *
 * The failures this suite exists to catch - several instances each registering a client, or each
 * opening a tab - are only visible from outside the processes involved. Asserting on anything a
 * single process knows about itself is how a green suite coexists with three browser tabs.
 */
type AuthServerCounters = {
  /** Dynamic client registrations (RFC 7591). One flow should need one. */
  registrations: number
  /** Authorization requests, i.e. browser tabs actually followed. */
  authorizations: number
  /** Access tokens successfully issued. */
  tokensIssued: number
  /** Token requests refused, with the reason, e.g. `pkce_mismatch`. */
  tokenFailures: Array<{ reason: string; clientId?: string }>
  /** Every distinct redirect_uri registered or authorized against. */
  redirectUris: string[]
  /** Instances that authenticated and completed an MCP `initialize` — i.e. actually got working. */
  initializations: number
}

export type OAuthSimulator = {
  url: string
  counters: AuthServerCounters
  /** Authorization URLs handed to a browser, in order, with the offset at which each arrived. */
  tabs: Array<{ url: string; clientId: string; redirectUri: string; atMs: number }>
  /** Follows an authorization URL the way a user completing the tab would. */
  completeAuthorization: (authorizationUrl: string) => Promise<void>
  close: () => Promise<void>
}

type Registration = { clientId: string; redirectUris: string[] }
type PendingCode = { clientId: string; challenge?: string; redirectUri: string }

function base64Url(input: Buffer): string {
  return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * A local OAuth 2.0 authorization server and MCP resource server, in one process.
 *
 * Deliberately strict about the things real providers are strict about and that concurrent
 * instances get wrong: PKCE verifiers must match the challenge from the same flow, an
 * authorization code is single-use, and a code may only be redeemed by the client it was issued to.
 */
export async function startOAuthSimulator(): Promise<OAuthSimulator> {
  const app = express()
  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))

  const counters: AuthServerCounters = {
    registrations: 0,
    authorizations: 0,
    tokensIssued: 0,
    tokenFailures: [],
    redirectUris: [],
    initializations: 0,
  }
  const tabs: OAuthSimulator['tabs'] = []
  const clients = new Map<string, Registration>()
  const codes = new Map<string, PendingCode>()
  const spentCodes = new Set<string>()
  const accessTokens = new Set<string>()
  const issueAccessToken = () => {
    const token = `access-${randomUUID()}`
    accessTokens.add(token)
    return token
  }
  const startedAt = Date.now()
  let base = ''

  const noteRedirectUri = (uri: string) => {
    if (uri && !counters.redirectUris.includes(uri)) counters.redirectUris.push(uri)
  }

  app.get('/.well-known/oauth-protected-resource', (_req, res) => {
    res.json({ resource: base, authorization_servers: [base] })
  })

  app.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.json({
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    })
  })

  app.post('/register', (req, res) => {
    counters.registrations++
    const clientId = `client-${counters.registrations}`
    const redirectUris: string[] = req.body?.redirect_uris ?? []
    redirectUris.forEach(noteRedirectUri)
    clients.set(clientId, { clientId, redirectUris })
    res.status(201).json({
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: redirectUris,
      token_endpoint_auth_method: 'none',
    })
  })

  // A browser would land here. Recorded rather than rendered: the count of these is the count of
  // tabs a user would have been shown.
  app.get('/authorize', (req, res) => {
    counters.authorizations++
    const clientId = String(req.query.client_id ?? '')
    const redirectUri = String(req.query.redirect_uri ?? '')
    noteRedirectUri(redirectUri)
    tabs.push({ url: `${base}${req.originalUrl}`, clientId, redirectUri, atMs: Date.now() - startedAt })

    const code = randomUUID()
    codes.set(code, { clientId, challenge: req.query.code_challenge as string | undefined, redirectUri })

    const target = new URL(redirectUri)
    target.searchParams.set('code', code)
    if (req.query.state) target.searchParams.set('state', String(req.query.state))
    res.redirect(302, target.toString())
  })

  app.post('/token', (req, res) => {
    const grantType = req.body?.grant_type
    const clientId = req.body?.client_id

    if (grantType === 'refresh_token') {
      counters.tokensIssued++
      res.json({ access_token: issueAccessToken(), refresh_token: req.body.refresh_token, token_type: 'Bearer', expires_in: 3600 })
      return
    }

    const code = req.body?.code
    const record = codes.get(code)
    if (!record) {
      const reason = spentCodes.has(code) ? 'unknown_or_used_code' : 'unknown_code'
      counters.tokenFailures.push({ reason, clientId })
      res.status(400).json({ error: 'invalid_grant', error_description: reason })
      return
    }
    // A code belongs to the client it was issued to. Instances that re-registered over a shared
    // client_info.json present a different one and must be refused, as a real provider would.
    if (record.clientId !== clientId) {
      counters.tokenFailures.push({ reason: 'client_mismatch', clientId })
      res.status(400).json({ error: 'invalid_grant', error_description: 'client_mismatch' })
      return
    }
    if (record.challenge) {
      const verifier = req.body?.code_verifier ?? ''
      const derived = base64Url(createHash('sha256').update(verifier).digest())
      if (derived !== record.challenge) {
        counters.tokenFailures.push({ reason: 'pkce_mismatch', clientId })
        res.status(400).json({ error: 'invalid_grant', error_description: 'pkce_mismatch' })
        return
      }
    }
    codes.delete(code)
    spentCodes.add(code)
    counters.tokensIssued++
    res.json({ access_token: issueAccessToken(), refresh_token: `refresh-${randomUUID()}`, token_type: 'Bearer', expires_in: 3600 })
  })

  // The MCP resource server. Unauthenticated requests get the challenge that starts the flow.
  // Counting `initialize` here is how the suite knows an instance did not merely obtain a token
  // but actually reached the server with it - the outcome a user would call "it worked".
  app.all('/mcp', (req, res) => {
    const authorization = req.headers.authorization
    if (!authorization?.startsWith('Bearer ') || !accessTokens.has(authorization.slice('Bearer '.length))) {
      res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`)
      res.status(401).json({ error: 'unauthorized' })
      return
    }

    const method = req.body?.method
    if (method === 'initialize') {
      counters.initializations++
      res.json({
        jsonrpc: '2.0',
        id: req.body.id,
        result: {
          protocolVersion: req.body?.params?.protocolVersion ?? '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'oauth-simulator', version: '1.0.0' },
        },
      })
      return
    }
    if (req.body?.id === undefined) {
      res.status(202).end() // a notification
      return
    }
    res.json({ jsonrpc: '2.0', id: req.body.id, result: {} })
  })

  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s))
  })
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`

  return {
    url: base,
    counters,
    tabs,
    completeAuthorization: async (authorizationUrl: string) => {
      // `redirect: 'manual'` so the callback server sees the redirect, as a browser would
      const response = await fetch(authorizationUrl, { redirect: 'manual' })
      const location = response.headers.get('location')
      if (location) await fetch(location).catch(() => {})
    },
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve())
      }),
  }
}

export type PublicMcpServer = { url: string; initializations: number; close: () => Promise<void> }

/**
 * An MCP server that never asks for OAuth, as a public one or one authenticated by `--header` is.
 *
 * Instances must not coordinate a sign-in for a server that will never have one: no tokens are
 * ever written, so anything waiting for them waits forever.
 */
export async function startPublicMcpServer(): Promise<PublicMcpServer> {
  const app = express()
  app.use(express.json())
  const state = { initializations: 0 }

  app.all('/mcp', (req, res) => {
    if (req.body?.method === 'initialize') {
      state.initializations++
      res.json({
        jsonrpc: '2.0',
        id: req.body.id,
        result: {
          protocolVersion: req.body?.params?.protocolVersion ?? '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'public-mcp', version: '1.0.0' },
        },
      })
      return
    }
    if (req.body?.id === undefined) {
      res.status(202).end()
      return
    }
    res.json({ jsonrpc: '2.0', id: req.body.id, result: {} })
  })

  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s))
  })
  const port = (server.address() as AddressInfo).port

  return {
    url: `http://127.0.0.1:${port}`,
    get initializations() {
      return state.initializations
    },
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve())
      }),
  }
}
