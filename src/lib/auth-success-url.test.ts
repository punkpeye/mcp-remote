import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EventEmitter } from 'events'
import type { Server } from 'node:http'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { parseCommandLineArgs, setupOAuthCallbackServerWithLongPoll } from './utils'
import { coordinateAuth, createLazyAuthCoordinator } from './coordination'

const successUrl = 'https://app.example.com/cli-connected'
const servers: Server[] = []
let configDir: string
let previousConfigDir: string | undefined

beforeEach(async () => {
  previousConfigDir = process.env.MCP_REMOTE_CONFIG_DIR
  configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-success-'))
  process.env.MCP_REMOTE_CONFIG_DIR = configDir
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
  if (previousConfigDir === undefined) delete process.env.MCP_REMOTE_CONFIG_DIR
  else process.env.MCP_REMOTE_CONFIG_DIR = previousConfigDir
  await fs.rm(configDir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

const parse = (args: string[]) => parseCommandLineArgs(['https://mcp.example.com/mcp', ...args], 'usage')

async function callback(authSuccessUrl: string | undefined = successUrl, authTimeoutMs = 1000) {
  const flow = await setupOAuthCallbackServerWithLongPoll({
    port: 0,
    path: '/custom/callback',
    events: new EventEmitter(),
    serverUrlHash: 'success-test',
    authSuccessUrl,
    authTimeoutMs,
  })
  servers.push(flow.server)
  return { ...flow, origin: `http://127.0.0.1:${flow.actualPort}` }
}

describe('--auth-success-url parsing', () => {
  it.each([
    successUrl,
    'https://localhost:3443/cli-connected',
    'http://localhost:3000/connected',
    'http://127.0.0.1/connected',
    'http://[::1]/connected',
  ])('accepts %s without changing the callback or credential cache', async (url) => {
    const original = await parse(['3600', '--callback-path', '/custom/callback'])
    const branded = await parse(['3600', '--callback-path', '/custom/callback', '--auth-success-url', url])
    expect(branded.authSuccessUrl).toBe(url)
    expect(branded.callbackPort).toBe(original.callbackPort)
    expect(branded.callbackPath).toBe(original.callbackPath)
    expect(branded.serverUrlHash).toBe(original.serverUrlHash)
    expect(original.authSuccessUrl).toBeUndefined()
  })

  it('allows private-network HTTP only with an explicit --allow-http', async () => {
    const url = 'http://console.internal/connected'
    await expect(parse(['--auth-success-url', url])).rejects.toThrow('--auth-success-url requires')
    expect((await parse(['--auth-success-url', url, '--allow-http'])).authSuccessUrl).toBe(url)
  })

  it.each([
    'javascript:alert(1)',
    'file:///tmp/connected',
    '/connected',
    'not-a-url',
    'https://user:secret@example.com/connected',
    `${successUrl}?token=secret`,
    `${successUrl}#secret`,
  ])('rejects unsafe or secret-bearing destinations without echoing them: %s', async (url) => {
    await expect(parse(['--auth-success-url', url, '--allow-http'])).rejects.toThrow('--auth-success-url requires')
    await expect(parse(['--auth-success-url', url])).rejects.not.toThrow(url)
  })

  it.each([
    ['--auth-success-url'],
    ['--auth-success-url', '--debug'],
    ['--auth-success-url', successUrl, '--auth-success-url', successUrl],
  ])('rejects missing or repeated values: %j', async (...args) => {
    await expect(parse(args)).rejects.toThrow('--auth-success-url requires')
  })
})

describe('OAuth browser completion', () => {
  it('redirects only after a successful exchange, without forwarding callback parameters', async () => {
    const flow = await callback()
    const response = fetch(`${flow.origin}/custom/callback?code=test-code&state=test-state&iss=https%3A%2F%2Fissuer.example.com`, {
      redirect: 'manual',
    })
    const received = await flow.waitForAuthCode()
    expect(received).toMatchObject({ code: 'test-code', state: 'test-state', iss: 'https://issuer.example.com' })
    expect((await fetch(`${flow.origin}/wait-for-auth?poll=false`)).status).toBe(202)

    received.completeAuthorization!(true)
    const result = await response
    expect(result.status).toBe(303)
    expect(result.headers.get('location')).toBe(successUrl)
    expect(result.headers.get('cache-control')).toBe('no-store')
    expect(result.headers.get('referrer-policy')).toBe('no-referrer')
    expect(await result.text()).toBe('')
    expect(await flow.authCompletedPromise).toBe(received)
    expect((await fetch(`${flow.origin}/wait-for-auth?poll=false`)).status).toBe(200)
  })

  it('does not redirect or report completion when the exchange fails', async () => {
    const flow = await callback()
    const response = fetch(`${flow.origin}/custom/callback?code=rejected-code&state=invalid-state`, { redirect: 'manual' })
    const received = await flow.waitForAuthCode()
    received.completeAuthorization!(false)
    received.completeAuthorization!(true)
    const result = await response
    expect(result.status).toBe(502)
    expect(result.headers.get('location')).toBeNull()
    expect(await result.text()).not.toMatch(/rejected-code|invalid-state/)
    expect((await fetch(`${flow.origin}/wait-for-auth?poll=false`)).status).toBe(202)
  })

  it('times out without redirecting and tolerates late completion', async () => {
    const flow = await callback(successUrl, 100)
    const response = fetch(`${flow.origin}/custom/callback?code=slow-code`, { redirect: 'manual' })
    const received = await flow.waitForAuthCode()
    const result = await response
    expect(result.status).toBe(504)
    expect(result.headers.get('location')).toBeNull()
    expect((await fetch(`${flow.origin}/wait-for-auth?poll=false`)).status).toBe(202)
    expect(() => received.completeAuthorization!(true)).not.toThrow()
  })

  it('ties each completion to its own browser response on repeated sign-ins', async () => {
    const flow = await callback()
    const firstResponse = fetch(`${flow.origin}/custom/callback?code=first`, { redirect: 'manual' })
    const first = await flow.waitForAuthCode()
    const secondResponse = fetch(`${flow.origin}/custom/callback?code=second`, { redirect: 'manual' })
    const second = await flow.waitForAuthCode()
    second.completeAuthorization!(true)
    expect((await secondResponse).status).toBe(303)
    first.completeAuthorization!(false)
    expect((await firstResponse).status).toBe(502)
  })

  it('does not redirect after denial or a missing code', async () => {
    const flow = await callback()
    const denied = flow.waitForAuthCode().catch((error: Error) => error)
    const response = await fetch(`${flow.origin}/custom/callback?error=access_denied&error_description=private-description`, {
      redirect: 'manual',
    })
    expect(response.status).toBe(400)
    expect(response.headers.get('location')).toBeNull()
    expect(await response.text()).not.toContain('private-description')
    expect(await denied).toBeInstanceOf(Error)
    expect((await fetch(`${flow.origin}/custom/callback`, { redirect: 'manual' })).status).toBe(400)
  })

  it('preserves the existing page when no destination is configured', async () => {
    const flow = await setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/custom/callback',
      events: new EventEmitter(),
      serverUrlHash: 'default-success',
    })
    servers.push(flow.server)
    const origin = `http://127.0.0.1:${flow.actualPort}`
    const response = await fetch(`${origin}/custom/callback?code=default-code`, { redirect: 'manual' })
    expect(response.status).toBe(200)
    expect(await response.text()).toContain('Authorization successful!')
    expect((await flow.waitForAuthCode()).completeAuthorization).toBeUndefined()
  })

  it('ignores completion destinations supplied in callback query parameters', async () => {
    const flow = await callback()
    const response = fetch(`${flow.origin}/custom/callback?code=safe-code&auth-success-url=https%3A%2F%2Fevil.example.com`, {
      redirect: 'manual',
    })
    const received = await flow.waitForAuthCode()
    received.completeAuthorization!(true)
    expect((await response).headers.get('location')).toBe(successUrl)
  })

  it('tolerates the browser disconnecting before a successful exchange', async () => {
    const flow = await callback()
    const controller = new AbortController()
    const response = fetch(`${flow.origin}/custom/callback?code=disconnected`, { redirect: 'manual', signal: controller.signal }).catch(
      (error) => error,
    )
    const received = await flow.waitForAuthCode()
    controller.abort()
    expect(await response).toBeInstanceOf(Error)
    expect(() => received.completeAuthorization!(true)).not.toThrow()
    expect(await flow.authCompletedPromise).toBe(received)
  })

  it('forwards the option through lazy coordination, preserving the custom callback path', async () => {
    const coordinator = createLazyAuthCoordinator('lazy-success', '/custom/callback', 0, new EventEmitter(), 1000, true, successUrl)
    const flow = await coordinator.initializeAuth()
    servers.push(flow.server)
    const response = fetch(`http://127.0.0.1:${flow.actualPort}/custom/callback?code=coordinated`, { redirect: 'manual' })
    const received = await flow.waitForAuthCode()
    received.completeAuthorization!(true)
    expect((await response).headers.get('location')).toBe(successUrl)
  })

  it('keeps the option when a follower takes over a departed owner', async () => {
    const owner = await coordinateAuth('takeover-success', '/custom/callback', 0, new EventEmitter(), 1000, true)
    servers.push(owner.server)
    const following = coordinateAuth(
      'takeover-success',
      '/custom/callback',
      owner.actualPort,
      new EventEmitter(),
      1000,
      true,
      1000,
      successUrl,
    )
    await vi.waitFor(() => expect(owner.server.listening).toBe(true))
    await new Promise((resolve) => setTimeout(resolve, 100))
    await new Promise<void>((resolve) => owner.server.close(() => resolve()))
    const follower = await following
    servers.push(follower.server)
    expect(follower.actualPort).toBe(owner.actualPort)
    expect(follower.skipBrowserAuth).toBe(false)
    const response = fetch(`http://127.0.0.1:${follower.actualPort}/custom/callback?code=takeover`, { redirect: 'manual' })
    const received = await follower.waitForAuthCode()
    received.completeAuthorization!(true)
    expect((await response).headers.get('location')).toBe(successUrl)
  })
})
