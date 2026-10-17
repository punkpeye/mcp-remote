import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import {
  writeJsonFile,
  getConfigFilePath,
  deleteStaleConfigFiles,
  getConfigDir,
  acquireConfigLease,
  readConfigLease,
  releaseConfigLease,
} from './mcp-auth-config'

vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
  MCP_REMOTE_VERSION: '1.0.0',
  getServerUrlHash: () => 'test-hash',
}))

let configDir: string

beforeEach(async () => {
  configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-config-'))
  process.env.MCP_REMOTE_CONFIG_DIR = configDir
})

afterEach(async () => {
  delete process.env.MCP_REMOTE_CONFIG_DIR
  await fs.rm(configDir, { recursive: true, force: true })
})

describe('Feature: Where credentials are stored', () => {
  const configDirEnv = process.env.MCP_REMOTE_CONFIG_DIR

  afterEach(() => {
    if (configDirEnv === undefined) delete process.env.MCP_REMOTE_CONFIG_DIR
    else process.env.MCP_REMOTE_CONFIG_DIR = configDirEnv
  })

  it('Scenario: The path does not move when the package version does', () => {
    // Given the package version the rest of the code reports
    delete process.env.MCP_REMOTE_CONFIG_DIR
    const before = getConfigDir()

    // When a release ships - the mocked version above stands in for it
    // Then the credentials are still looked for in the same place, so nobody has to sign in again
    expect(before).not.toContain('1.0.0')
    expect(before).toBe(path.join(os.homedir(), '.mcp-auth', 'mcp-remote-v1'))
  })

  it('Scenario: MCP_REMOTE_CONFIG_DIR relocates the store and keeps it stable', () => {
    // The documented workaround for this used to relocate the base and then append the package
    // version underneath it anyway, so it never actually stopped the re-authentication
    process.env.MCP_REMOTE_CONFIG_DIR = '/tmp/somewhere-else'

    expect(getConfigDir()).toBe(path.join('/tmp/somewhere-else', 'mcp-remote-v1'))
    expect(getConfigDir()).not.toContain('1.0.0')
  })
})

describe('Feature: Config file writes', () => {
  const hash = 'write-test'
  const filename = 'tokens.json'
  const target = () => getConfigFilePath(hash, filename)

  it('Scenario: A reader never observes a half-written file', async () => {
    // Given a payload large enough that a plain writeFile spans several syscalls.
    // Measured on this write path: 5 MB tears reliably, 1 MB does not tear at all,
    // so a smaller payload would make this test pass against the bug it guards.
    const big = { access_token: 'a'.repeat(5_000_000), refresh_token: 'r' }

    // When a reader polls the path while the write is in flight
    let torn = false
    const poll = setInterval(() => {
      try {
        JSON.parse(require('fs').readFileSync(target(), 'utf-8'))
      } catch (error: any) {
        // ENOENT is fine - the file simply is not there yet. A parse error is not.
        if (error.code !== 'ENOENT') torn = true
      }
    }, 0)

    await writeJsonFile(hash, filename, big)
    clearInterval(poll)

    // Then every observation was either "absent" or "complete"
    expect(torn).toBe(false)
    const written = JSON.parse(await fs.readFile(target(), 'utf-8'))
    expect(written.access_token).toHaveLength(5_000_000)
  })

  it('Scenario: No temp files are left behind', async () => {
    await writeJsonFile(hash, filename, { access_token: 'a' })

    const dir = path.dirname(target())
    const leftovers = (await fs.readdir(dir)).filter((f) => f.startsWith(`${filename}`) && f.endsWith('.tmp'))
    expect(leftovers).toEqual([])
  })

  // Windows does not report POSIX permission bits: a file created with mode 0o600 comes back as
  // 0o666, so this assertion can only run where the bits are real. The mode passed to the write is
  // unchanged - only the check that cannot observe it is skipped.
  it.skipIf(process.platform === 'win32')('Scenario: The file stays owner-only', async () => {
    await writeJsonFile(hash, filename, { access_token: 'a' })

    const stat = await fs.stat(target())
    // The temp file carries mode 0o600 through the rename
    expect(stat.mode & 0o777).toBe(0o600)
  })
})

describe('Feature: Sweeping files nothing will name again', () => {
  const hash = 'sweep-test'
  const prefix = 'code_verifier_'

  const write = async (filename: string, ageMs: number) => {
    const filePath = getConfigFilePath(hash, filename)
    await writeJsonFile(hash, filename, 'verifier')
    const when = new Date(Date.now() - ageMs)
    await fs.utimes(filePath, when, when)
    return filePath
  }

  it('Scenario: An abandoned flow leaves nothing behind, a live one keeps its file', async () => {
    const abandoned = await write(`${prefix}old.txt`, 60 * 60 * 1000)
    const inFlight = await write(`${prefix}fresh.txt`, 0)
    const unrelated = await write('tokens.json', 60 * 60 * 1000)

    await deleteStaleConfigFiles(hash, prefix, 10 * 60 * 1000)

    await expect(fs.access(abandoned)).rejects.toThrow(/ENOENT/)
    await expect(fs.access(inFlight)).resolves.toBeUndefined()
    // The sweep stays inside the prefix it was given
    await expect(fs.access(unrelated)).resolves.toBeUndefined()

    await fs.unlink(inFlight).catch(() => {})
    await fs.unlink(unrelated).catch(() => {})
  })
})

describe('Feature: Leasing a filename to one instance at a time', () => {
  const hash = 'lease-test'
  const filename = 'refresh_in_progress.json'
  const TTL = 30_000
  const leaseOnDisk = async () => JSON.parse(await fs.readFile(getConfigFilePath(hash, filename), 'utf-8'))
  const writeFileInStore = async (contents: string) => {
    await fs.mkdir(getConfigDir(), { recursive: true })
    await fs.writeFile(getConfigFilePath(hash, filename), contents, 'utf-8')
  }
  const writeLease = (lease: Record<string, unknown>) => writeFileInStore(JSON.stringify(lease))

  // A pid nothing can be running under: the kernel rejects it outright, so it can never be reused
  const DEAD_PID = 0x7fffffff

  it('Scenario: Several instances race and exactly one comes away with the lease', async () => {
    const claims = await Promise.all(Array.from({ length: 8 }, () => acquireConfigLease(hash, filename, TTL)))

    // A refresh token spent twice is a revoked chain, so "roughly one winner" is not good enough
    expect(claims.filter(Boolean)).toHaveLength(1)
    expect((await leaseOnDisk()).nonce).toBe(claims.find(Boolean))
  })

  it('Scenario: An instance that is still working keeps its lease', async () => {
    expect(await acquireConfigLease(hash, filename, TTL)).toBeTruthy()

    expect(await acquireConfigLease(hash, filename, TTL)).toBeUndefined()
    expect((await readConfigLease(hash, filename, TTL))?.live).toBe(true)
  })

  it('Scenario: A lease its owner died holding is taken over at once', async () => {
    // Killed mid-refresh a moment ago. Waiting out the age of a lease nobody will ever release
    // stalls every other instance for the whole of it.
    await writeLease({ pid: DEAD_PID, nonce: 'theirs', at: Date.now() })

    expect(await readConfigLease(hash, filename, TTL)).toMatchObject({ live: false })
    expect(await acquireConfigLease(hash, filename, TTL)).toBeTruthy()
    expect((await leaseOnDisk()).pid).toBe(process.pid)
  })

  it('Scenario: A live owner that has run past its deadline stops holding everyone up', async () => {
    await writeLease({ pid: process.pid, nonce: 'theirs', at: Date.now() - TTL - 1 })

    expect(await readConfigLease(hash, filename, TTL)).toMatchObject({ live: false })
    expect(await acquireConfigLease(hash, filename, TTL)).toBeTruthy()
  })

  it('Scenario: A lease nothing can make sense of is not left blocking everyone', async () => {
    await writeFileInStore('not json at all')

    expect(await readConfigLease(hash, filename, TTL)).toBeUndefined()
    expect(await acquireConfigLease(hash, filename, TTL)).toBeTruthy()
  })

  it('Scenario: Releasing only clears a lease this instance still holds', async () => {
    const nonce = await acquireConfigLease(hash, filename, TTL)
    // Overran its deadline, and a sibling has since taken over
    await writeLease({ pid: process.pid, nonce: 'somebody-else', at: Date.now() })

    await releaseConfigLease(hash, filename, nonce!)

    // Deleting it would hand the same work to a third instance
    expect((await leaseOnDisk()).nonce).toBe('somebody-else')
  })

  it('Scenario: Releasing frees the filename for the next instance', async () => {
    const nonce = await acquireConfigLease(hash, filename, TTL)

    await releaseConfigLease(hash, filename, nonce!)

    expect(await readConfigLease(hash, filename, TTL)).toBeUndefined()
    expect(await acquireConfigLease(hash, filename, TTL)).toBeTruthy()
  })

  // Skipped on Windows for the same reason as "The file stays owner-only": the lease is written
  // with mode 0o600, but fs.stat cannot report it there, so the check cannot fail honestly.
  it.skipIf(process.platform === 'win32')('Scenario: The lease is readable only by its owner', async () => {
    await acquireConfigLease(hash, filename, TTL)

    const mode = (await fs.stat(getConfigFilePath(hash, filename))).mode & 0o777
    expect(mode).toBe(0o600)
  })
})
