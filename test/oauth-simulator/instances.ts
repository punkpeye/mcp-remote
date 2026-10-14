import { spawn, type ChildProcess } from 'child_process'
import net from 'net'
// Imported rather than reimplemented: a test that derives the port its own way stops testing the
// thing the instances actually do the moment either side changes.
import { calculateDefaultPort, getServerUrlHash } from '../../src/lib/utils'
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'fs'
import { tmpdir } from 'os'
import path from 'path'
import { fileURLToPath } from 'url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../..')

export type InstanceRun = {
  /** Authorization URLs opened across all instances, i.e. the tabs a user would have seen. */
  tabs: Array<{ atMs: number; pid: number; url: string }>
  /** Per-instance stderr, for asserting on what an instance decided. */
  logs: string[]
  /** The instance killed mid-flow, when a scenario asked for one. */
  killedPid?: number
  configDir: string
}

export type RunOptions = {
  /** How many instances the host starts at once. */
  count: number
  serverUrl: string
  /** Extra CLI args, e.g. `['--port', '9999']`. */
  args?: string[]
  /** How long to let the flow run before tearing down. */
  settleMs?: number
  /** Kills the instance that opened the first tab, this long after it opens. */
  killTabOwnerAfterMs?: number
  /**
   * Approves the first tab this long after the instance that opened it was killed, from the
   * harness rather than from inside an instance - a browser outlives the process that opened it.
   */
  approveFirstTabAfterKillMs?: number
  /** Reuses an existing config dir, standing in for a restart after a successful sign-in. */
  configDir?: string
  /** Holds the port these instances would derive, standing in for an unrelated process. */
  squatDerivedPort?: boolean
  /** Records login tabs without completing them, as when the workstation is unattended. */
  ignoreAuthorization?: boolean
}

/**
 * Starts `count` real mcp-remote processes against one server, as an MCP host does.
 *
 * They are run from source under `tsx` rather than from `dist` so that the `open` package can be
 * aliased away by a module hook; the bundler inlines it, which would put a real browser launch
 * inside a test run.
 */
export async function runInstances(options: RunOptions): Promise<InstanceRun> {
  const { count, serverUrl, args = [], settleMs = 8000 } = options
  const configDir = options.configDir ?? mkdtempSync(path.join(tmpdir(), 'mcp-remote-e2e-'))
  const tabLog = path.join(configDir, 'tabs.log')
  writeFileSync(tabLog, '')

  const squatter = options.squatDerivedPort ? await squatPort(calculateDefaultPort(getServerUrlHash(serverUrl))) : undefined

  const startedAt = Date.now()
  let killedPid: number | undefined
  const children: ChildProcess[] = []
  const logs: string[] = Array.from({ length: count }, () => '')

  for (let i = 0; i < count; i++) {
    const child = spawn(path.join(repoRoot, 'node_modules/.bin/tsx'), [path.join(repoRoot, 'src/proxy.ts'), serverUrl, ...args], {
      cwd: repoRoot,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        MCP_REMOTE_CONFIG_DIR: configDir,
        MCP_TEST_TAB_LOG: tabLog,
        ...(options.approveFirstTabAfterKillMs === undefined && !options.ignoreAuthorization
          ? {}
          : { MCP_TEST_TABS_APPROVED_EXTERNALLY: '1' }),
        NODE_OPTIONS: `--import ${pathToImport(path.join(here, 'browser-hook.mjs'))}`,
      },
    })
    child.stderr?.on('data', (chunk) => {
      logs[i] += String(chunk)
    })
    children.push(child)
  }

  // Kills whichever instance opened the tab, as an MCP host restarting its servers does. The
  // browser tab it opened stays open, pointing at the callback port it no longer holds.
  if (options.killTabOwnerAfterMs !== undefined) {
    const killedAt = Date.now() + options.killTabOwnerAfterMs
    while (Date.now() < killedAt || !readTabPids(tabLog).length) {
      if (Date.now() > killedAt + 10_000) break
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    const [ownerPid] = readTabPids(tabLog)
    if (ownerPid) {
      try {
        process.kill(ownerPid, 'SIGKILL')
        killedPid = ownerPid
      } catch {
        // Already gone
      }
      children.find((c) => c.pid === ownerPid)?.kill('SIGKILL')
    }
  }

  if (options.approveFirstTabAfterKillMs !== undefined) {
    await new Promise((resolve) => setTimeout(resolve, options.approveFirstTabAfterKillMs))
    const [firstTab] = readTabUrls(tabLog)
    // Following the redirect chain is what a browser does: authorize, then the callback. The
    // callback leg is retried because the instance taking the flow over may not have rebound the
    // port yet - and only that leg, since re-fetching the authorize URL would mint a second code.
    if (firstTab) {
      const authorized = await fetch(firstTab, { redirect: 'manual' }).catch(() => undefined)
      const callback = authorized?.headers.get('location')
      if (callback) {
        for (let attempt = 0; attempt < 40; attempt++) {
          try {
            await fetch(callback)
            break
          } catch {
            await new Promise((r) => setTimeout(r, 50))
          }
        }
      }
    }
  }

  await new Promise((resolve) => setTimeout(resolve, settleMs))
  for (const child of children) child.kill('SIGKILL')
  if (squatter) await squatter.release()

  const tabs = existsSync(tabLog)
    ? readFileSync(tabLog, 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((line) => {
          const [at, pid, ...rest] = line.split(' ')
          return { atMs: Number(at) - startedAt, pid: Number(pid), url: rest.join(' ') }
        })
    : []

  return {
    tabs,
    logs,
    killedPid,
    configDir,
  }
}

function readTabUrls(tabLog: string): string[] {
  if (!existsSync(tabLog)) return []
  return readFileSync(tabLog, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((line) => line.split(' ').slice(2).join(' '))
}

function readTabPids(tabLog: string): number[] {
  if (!existsSync(tabLog)) return []
  return readFileSync(tabLog, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((line) => Number(line.split(' ')[1]))
}

export function cleanupRun(run: InstanceRun): void {
  rmSync(run.configDir, { recursive: true, force: true })
}

/**
 * Holds a port the way an unrelated process would: accepting connections, answering nothing.
 *
 * Sockets are tracked so the port can be released afterwards - an identity probe leaves its
 * connection open, and `close()` waits for every one of them.
 */
function squatPort(port: number): Promise<{ release: () => Promise<void> }> {
  return new Promise((resolve, reject) => {
    const sockets = new Set<net.Socket>()
    const server = net.createServer((socket) => {
      sockets.add(socket)
      socket.on('close', () => sockets.delete(socket))
    })
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () =>
      resolve({
        release: async () => {
          for (const socket of sockets) socket.destroy()
          await new Promise<void>((done) => server.close(() => done()))
        },
      }),
    )
  })
}

function pathToImport(p: string): string {
  return new URL(`file://${p}`).href
}
