import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { writeJsonFile } from './mcp-auth-config'
import { createLazyAuthCoordinator, hasUsableTokens } from './coordination'
import { EventEmitter } from 'events'
import net from 'net'
import http from 'http'

describe('Feature: Two 401s arriving in the same tick', () => {
  let configDir: string

  beforeEach(async () => {
    configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-lazy-'))
    process.env.MCP_REMOTE_CONFIG_DIR = configDir
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(async () => {
    delete process.env.MCP_REMOTE_CONFIG_DIR
    await fs.rm(configDir, { recursive: true, force: true })
    vi.restoreAllMocks()
  })

  it('Scenario: They share one flow instead of racing for the callback port', async () => {
    // Concurrent re-entry used to slip past a guard that tested the resolved value, so both calls
    // started a flow and the loser died on an unhandled EADDRINUSE - taking the winner's callback
    // server down with it (#317).
    const coordinator = createLazyAuthCoordinator('lazy-shared', '/oauth/callback', 0, new EventEmitter(), 5000)

    const [first, second] = await Promise.all([coordinator.initializeAuth(), coordinator.initializeAuth()])

    // One flow, so there is no second callback server to collide with the first
    expect(first).toBe(second)
    first.server.close()
  })

  it('Scenario: A failed attempt is not cached, so a retry can still succeed', async () => {
    // Given the port is taken by something that is not us, and pinned, so the attempt must fail
    const blocker = http.createServer((_req, res) => {
      res.writeHead(404).end()
    })
    const blockedPort = await new Promise<number>((resolve) => {
      blocker.listen(0, '127.0.0.1', () => resolve((blocker.address() as net.AddressInfo).port))
    })
    const coordinator = createLazyAuthCoordinator('lazy-retry', '/oauth/callback', blockedPort, new EventEmitter(), 5000, true)

    await expect(coordinator.initializeAuth()).rejects.toMatchObject({ code: 'EADDRINUSE' })

    // When the port frees up, a retry has to be able to take it - a cached rejection would
    // replay the original failure forever
    blocker.closeAllConnections()
    await new Promise<void>((resolve) => blocker.close(() => resolve()))
    const retried = await coordinator.initializeAuth()

    expect(retried.actualPort).toBe(blockedPort)
    retried.server.close()
  }, 15_000)
})

describe('Feature: Giving the callback port back after a sign-in', () => {
  let configDir: string

  beforeEach(async () => {
    configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-release-'))
    process.env.MCP_REMOTE_CONFIG_DIR = configDir
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(async () => {
    delete process.env.MCP_REMOTE_CONFIG_DIR
    await fs.rm(configDir, { recursive: true, force: true })
    vi.restoreAllMocks()
  })

  const freePort = () =>
    new Promise<number>((resolve) => {
      const probe = net.createServer().listen(0, '127.0.0.1', () => {
        const { port } = probe.address() as net.AddressInfo
        probe.close(() => resolve(port))
      })
    })

  const canBind = (port: number) =>
    new Promise<boolean>((resolve) => {
      const probe = net.createServer()
      probe.once('error', () => resolve(false))
      probe.listen(port, '127.0.0.1', () => probe.close(() => resolve(true)))
    })

  it('Scenario: A finished sign-in frees the port for the next instance that needs one', async () => {
    // Given this instance owns the sign-in on a pinned port
    const port = await freePort()
    const coordinator = createLazyAuthCoordinator('release-frees', '/oauth/callback', port, new EventEmitter(), 5000, true)
    const owned = await coordinator.initializeAuth()
    expect(owned.skipBrowserAuth).toBe(false)
    expect(await canBind(port)).toBe(false)

    // When its sign-in is done
    await coordinator.release()

    // Then a later instance can bind the port instead of waiting on an owner that signs no one in
    expect(await canBind(port)).toBe(true)
  })

  it('Scenario: The next 401 after a release coordinates afresh', async () => {
    const port = await freePort()
    const coordinator = createLazyAuthCoordinator('release-again', '/oauth/callback', port, new EventEmitter(), 5000, true)
    const first = await coordinator.initializeAuth()
    await coordinator.release()

    // A cached verdict would hand back the closed server; a fresh one binds the port again
    const second = await coordinator.initializeAuth()
    expect(second).not.toBe(first)
    expect(second.actualPort).toBe(port)
    expect(await canBind(port)).toBe(false)
    await coordinator.release()
  })

  it('Scenario: Releasing when nothing is held does nothing', async () => {
    const coordinator = createLazyAuthCoordinator('release-idle', '/oauth/callback', 0, new EventEmitter(), 5000)
    await expect(coordinator.release()).resolves.toBeUndefined()
  })
})

describe('Feature: Deciding whether a browser sign-in is needed', () => {
  let configDir: string

  beforeEach(async () => {
    configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-usable-'))
    process.env.MCP_REMOTE_CONFIG_DIR = configDir
  })

  afterEach(async () => {
    delete process.env.MCP_REMOTE_CONFIG_DIR
    await fs.rm(configDir, { recursive: true, force: true })
  })

  const store = (tokens: Record<string, unknown>) => writeJsonFile('usable-test', 'tokens.json', tokens)

  it('Scenario: No tokens at all means a sign-in is needed', async () => {
    await expect(hasUsableTokens('usable-test')).resolves.toBe(false)
  })

  it('Scenario: A live token needs nothing', async () => {
    await store({ access_token: 'a', token_type: 'Bearer', expires_at: Date.now() + 3_600_000 })
    await expect(hasUsableTokens('usable-test')).resolves.toBe(true)
  })

  it('Scenario: An expired token that can be refreshed needs no browser', async () => {
    await store({ access_token: 'a', token_type: 'Bearer', expires_at: Date.now() - 1000, refresh_token: 'r' })
    await expect(hasUsableTokens('usable-test')).resolves.toBe(true)
  })

  it('Scenario: An expired token with nothing to refresh from needs a sign-in', async () => {
    // Treating this as usable is what let every instance skip coordination on re-authentication
    // and open a tab of its own
    await store({ access_token: 'a', token_type: 'Bearer', expires_at: Date.now() - 1000 })
    await expect(hasUsableTokens('usable-test')).resolves.toBe(false)
  })

  it('Scenario: A token expiring within the refresh margin counts as expired', async () => {
    await store({ access_token: 'a', token_type: 'Bearer', expires_at: Date.now() + 5_000 })
    await expect(hasUsableTokens('usable-test')).resolves.toBe(false)
  })
})
