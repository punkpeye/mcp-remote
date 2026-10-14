import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { EventEmitter } from 'events'
import express from 'express'
import net from 'net'
import http from 'http'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { coordinateAuth, serverIssuesAuthChallenge } from './coordination'
import { writeJsonFile } from './mcp-auth-config'
import { MCP_REMOTE_ID_PATH } from './utils'

/**
 * Deciding who runs the sign-in.
 *
 * This is the substance of the port-ownership design and it shipped untested, which is how a
 * follower came to accept the very token the pre-connect gate had just rejected.
 */
const HASH = 'coordinate-test'
let configDir: string
const opened: Array<{ close: () => Promise<void> }> = []

/** Something that is not us, holding a port. */
async function stranger(port: number): Promise<void> {
  const server = http.createServer((_req, res) => res.writeHead(404).end())
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve))
  opened.push({ close: () => new Promise((r) => (server.closeAllConnections(), server.close(() => r()))) })
}

/** Something claiming to be one of us for this server, holding a port. */
async function sibling(port: number, serverUrlHash = HASH): Promise<void> {
  const app = express()
  app.get(MCP_REMOTE_ID_PATH, (_req, res) => {
    res.json({ mcpRemote: true, serverUrlHash })
  })
  const server = await new Promise<http.Server>((resolve) => {
    const s = app.listen(port, '127.0.0.1', () => resolve(s))
  })
  opened.push({ close: () => new Promise((r) => (server.closeAllConnections(), server.close(() => r()))) })
}

async function freePort(): Promise<number> {
  const probe = net.createServer()
  const port = await new Promise<number>((resolve) =>
    probe.listen(0, '127.0.0.1', () => resolve((probe.address() as net.AddressInfo).port)),
  )
  await new Promise<void>((resolve) => probe.close(() => resolve()))
  return port
}

const coordinate = (port: number, patienceMs = 500) =>
  coordinateAuth(HASH, '/oauth/callback', port, new EventEmitter(), 1000, false, patienceMs)

beforeEach(async () => {
  configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-coord-'))
  process.env.MCP_REMOTE_CONFIG_DIR = configDir
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(async () => {
  for (const o of opened.splice(0)) await o.close()
  delete process.env.MCP_REMOTE_CONFIG_DIR
  await fs.rm(configDir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

describe('Feature: Deciding who runs the sign-in', () => {
  it('Scenario: A free port makes this instance the owner', async () => {
    const port = await freePort()

    const result = await coordinate(port)

    expect(result.skipBrowserAuth).toBe(false)
    expect(result.actualPort).toBe(port)
    result.server.close()
  })

  it('Scenario: A sibling on the port makes this instance a follower', async () => {
    const port = await freePort()
    await sibling(port)
    await writeJsonFile(HASH, 'tokens.json', { access_token: 'a', token_type: 'Bearer', expires_at: Date.now() + 3_600_000 })

    const result = await coordinate(port)

    expect(result.skipBrowserAuth).toBe(true)
    expect(result.actualPort).toBe(port)
    result.server.close()
  })

  it('Scenario: A stranger on the port is stepped over, not waited for', async () => {
    const port = await freePort()
    await stranger(port)

    const result = await coordinate(port)

    // Someone else's process is not a sign-in to wait for
    expect(result.skipBrowserAuth).toBe(false)
    expect(result.actualPort).toBeGreaterThan(port)
    result.server.close()
  })

  it('Scenario: A sibling holding a token nobody can use is not mistaken for a finished sign-in', async () => {
    // The pre-connect gate rejects an expired token with nothing to refresh from. A follower that
    // accepted the same file would reconnect with it, get a 401, and open a tab of its own.
    const port = await freePort()
    await sibling(port)
    await writeJsonFile(HASH, 'tokens.json', { access_token: 'stale', token_type: 'Bearer', expires_at: Date.now() - 60_000 })

    await expect(coordinate(port, 400)).rejects.toThrow(/Authentication is still pending in another instance/)
  })

  it('Scenario: An unanswered sign-in stops the follower instead of authorizing without ownership', async () => {
    const port = await freePort()
    await sibling(port)

    await expect(coordinate(port, 400)).rejects.toThrow(/Complete that sign-in and retry/)
  })

  it('Scenario: A sign-in completed while the follower waits allows it to reconnect', async () => {
    const port = await freePort()
    await sibling(port)
    const pending = coordinate(port)
    await new Promise((resolve) => setTimeout(resolve, 100))
    await writeJsonFile(HASH, 'tokens.json', { access_token: 'new', token_type: 'Bearer', expires_at: Date.now() + 3_600_000 })

    const result = await pending
    expect(result.skipBrowserAuth).toBe(true)
    result.server.close()
  })

  it('Scenario: The follower takes over when the owner exits without completing login', async () => {
    const port = await freePort()
    await sibling(port)
    const owner = opened.pop()!
    const pending = coordinate(port)
    await new Promise((resolve) => setTimeout(resolve, 100))
    await owner.close()

    const result = await pending
    expect(result.skipBrowserAuth).toBe(false)
    expect(result.actualPort).toBe(port)
    result.server.close()
  })

  it('Scenario: A sibling for a different server is a stranger', async () => {
    const port = await freePort()
    await sibling(port, 'some-other-server')

    const result = await coordinate(port)

    expect(result.skipBrowserAuth).toBe(false)
    expect(result.actualPort).toBeGreaterThan(port)
    result.server.close()
  })
})

describe('Feature: Asking whether the server wants a sign-in', () => {
  it('Scenario: A challenge means coordinate', async () => {
    const server = http.createServer((_req, res) => res.writeHead(401).end())
    const port = await new Promise<number>((r) => server.listen(0, '127.0.0.1', () => r((server.address() as net.AddressInfo).port)))
    opened.push({ close: () => new Promise((r) => (server.closeAllConnections(), server.close(() => r()))) })

    await expect(serverIssuesAuthChallenge(`http://127.0.0.1:${port}/mcp`)).resolves.toBe(true)
  })

  it('Scenario: A server that serves us needs no coordination', async () => {
    const server = http.createServer((_req, res) => res.writeHead(200).end('{}'))
    const port = await new Promise<number>((r) => server.listen(0, '127.0.0.1', () => r((server.address() as net.AddressInfo).port)))
    opened.push({ close: () => new Promise((r) => (server.closeAllConnections(), server.close(() => r()))) })

    await expect(serverIssuesAuthChallenge(`http://127.0.0.1:${port}/mcp`)).resolves.toBe(false)
  })

  it('Scenario: A server we cannot reach is left to the 401 handler', async () => {
    await expect(serverIssuesAuthChallenge('http://127.0.0.1:9/mcp')).resolves.toBe(false)
  })
})
