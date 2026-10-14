import { it, expect, vi } from 'vitest'
import { EventEmitter } from 'events'
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import path from 'path'
import { coordinateAuth } from '../src/lib/coordination'
import { writeJsonFile } from '../src/lib/mcp-auth-config'
import { getServerUrlHash } from '../src/lib/utils'
import { startOAuthSimulator } from './oauth-simulator/server'
import { runInstances } from './oauth-simulator/instances'

it('does not open login tabs when a sibling keeps the callback port after its token expires', async () => {
  const auth = await startOAuthSimulator()
  const serverUrl = `${auth.url}/mcp`
  const hash = getServerUrlHash(serverUrl)
  const configDir = mkdtempSync(path.join(tmpdir(), 'mcp-remote-ignored-login-'))
  vi.stubEnv('MCP_REMOTE_CONFIG_DIR', configDir)

  // A still-running instance owns the real callback server, but its cached token has expired
  // and nobody has completed a new login. Followers must not mistake timeout for authentication.
  const owner = await coordinateAuth(hash, '/oauth/callback', 0, new EventEmitter(), 1000)
  try {
    await writeJsonFile(hash, 'tokens.json', {
      access_token: 'expired-test-token',
      token_type: 'Bearer',
      expires_at: Date.now() - 60_000,
    })
    const run = await runInstances({
      count: 2,
      serverUrl,
      configDir,
      args: [String(owner.actualPort), '--transport', 'http-only', '--auth-timeout', '1'],
      ignoreAuthorization: true,
      // Exercise the production three-minute follower deadline in real processes.
      settleMs: 195_000,
    })

    expect(run.tabs).toHaveLength(0)
    expect(auth.counters.registrations).toBe(0)
    expect(auth.counters.tokensIssued).toBe(0)
    expect(auth.counters.initializations).toBe(0)
    for (const log of run.logs) expect(log).toContain('Authentication is still pending in another instance')

    // Closing the old instance and explicitly retrying must still allow a fresh sign-in.
    owner.server.closeAllConnections()
    await new Promise<void>((resolve) => owner.server.close(() => resolve()))
    const retry = await runInstances({
      count: 1,
      serverUrl,
      configDir,
      args: [String(owner.actualPort), '--transport', 'http-only', '--auth-timeout', '1'],
      settleMs: 12_000,
    })
    expect(retry.tabs).toHaveLength(1)
    expect(auth.counters.tokensIssued).toBe(1)
    expect(auth.counters.initializations).toBe(1)
    expect(auth.counters.tokenFailures).toEqual([])
  } finally {
    owner.server.closeAllConnections()
    await new Promise<void>((resolve) => owner.server.close(() => resolve()))
    await auth.close()
    vi.unstubAllEnvs()
    rmSync(configDir, { recursive: true, force: true })
  }
}, 225_000)
