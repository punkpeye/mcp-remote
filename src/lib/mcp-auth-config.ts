import path from 'path'
import os from 'os'
import fs from 'fs/promises'
import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { log, debugLog } from './utils'

/**
 * MCP Remote Authentication Configuration
 *
 * This module handles the storage and retrieval of authentication-related data for MCP Remote.
 *
 * Configuration directory structure:
 * - The config directory is determined by MCP_REMOTE_CONFIG_DIR env var or defaults to ~/.mcp-auth,
 *   with a subdirectory naming the store layout - stable across releases, see CONFIG_STORE_VERSION
 * - Each file is prefixed with a hash of the server URL to separate configurations for different servers
 *
 * Files stored in the config directory:
 * - {server_hash}_client_info.json: Contains OAuth client registration information
 *   - Format: OAuthClientInformation object with client_id and other registration details
 * - {server_hash}_tokens.json: Contains OAuth access and refresh tokens
 *   - Format: OAuthTokens object with access_token, refresh_token, and expiration information
 * - {server_hash}_code_verifier_{state}.txt: Contains the PKCE code verifier for one OAuth flow
 *   - Format: Plain text string used for PKCE verification
 *   - Scoped to the flow's authorization state rather than to a process, so whichever instance
 *     holds the callback port when the user finishes can redeem a code from a flow another
 *     instance started - including one the host has since stopped (see issue #235)
 *
 * All JSON files are stored with 2-space indentation for readability.
 */

/**
 * The layout of the stored credentials, not the version of this package.
 *
 * Raise it by hand, and only when something already on disk would be misread by the code reading
 * it - a renamed file, a changed shape, a credential that has to be reissued. Everyone's stored
 * sign-ins are discarded when it changes, so that is the whole point of it and also the reason it
 * should almost never move.
 *
 * It used to be the package version, which meant every release discarded them: a token store is
 * keyed by this directory, so a new version always found an empty one and every server asked the
 * user to sign in again. At ten releases in three days, that was a sign-in per release per server
 * (see https://github.com/geelen/mcp-remote/issues/200).
 */
const CONFIG_STORE_VERSION = 1

/**
 * Gets the configuration directory path
 * @returns The path to the configuration directory
 */
export function getConfigDir(): string {
  const baseConfigDir = process.env.MCP_REMOTE_CONFIG_DIR || path.join(os.homedir(), '.mcp-auth')
  return path.join(baseConfigDir, `mcp-remote-v${CONFIG_STORE_VERSION}`)
}

/**
 * Ensures the configuration directory exists
 */
async function ensureConfigDir(): Promise<void> {
  try {
    const configDir = getConfigDir()
    await fs.mkdir(configDir, { recursive: true })
  } catch (error) {
    log('Error creating config directory:', error)
    throw error
  }
}

/**
 * Gets the file path for a config file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file
 * @returns The absolute file path
 */
export function getConfigFilePath(serverUrlHash: string, filename: string): string {
  const configDir = getConfigDir()
  return path.join(configDir, `${serverUrlHash}_${filename}`)
}

/**
 * Deletes a config file if it exists
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to delete
 */
export async function deleteConfigFile(serverUrlHash: string, filename: string): Promise<void> {
  try {
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.unlink(filePath)
  } catch (error) {
    // Ignore if file doesn't exist
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      log(`Error deleting ${filename}:`, error)
    }
  }
}

/**
 * Deletes a JSON config file, but only if what it holds is what the caller means to delete.
 *
 * Instances sharing a store replace each other's files, so the file read a moment ago may not be
 * the one on disk now. The case this exists for is a token refused for one instance while a sibling
 * saves the fresh one that replaced it (issue #389): deleting by name after checking the content
 * would remove the fresh token and send every instance back to the browser.
 *
 * So the file is renamed aside first, which takes exactly one version out of the next writer's
 * way, and only that version is judged and deleted. One that turns out to be newer goes back,
 * unless an even newer one has been written in its place meanwhile. Writers replace the file by
 * rename as well (see {@link writeJsonFile}), so nothing is deleted that was not checked.
 *
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file
 * @param schema The schema the content is parsed with
 * @param shouldDelete Whether the content is what should go - undefined if it does not parse
 * @returns Whether the file was deleted
 */
export async function deleteJsonFileIf<T>(
  serverUrlHash: string,
  filename: string,
  schema: { parse(value: unknown): T },
  shouldDelete: (content: T | undefined) => boolean,
): Promise<boolean> {
  const filePath = getConfigFilePath(serverUrlHash, filename)
  const judge = (raw: string) => {
    let content: T | undefined
    try {
      content = schema.parse(JSON.parse(raw))
    } catch {
      content = undefined
    }
    return shouldDelete(content)
  }

  let checked: string
  try {
    checked = await fs.readFile(filePath, 'utf-8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') log(`Error reading ${filename}:`, error)
    return false
  }
  if (!judge(checked)) return false

  const aside = `${filePath}.${process.pid}.${randomUUID()}.discard`
  try {
    await fs.rename(filePath, aside)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    // Windows refuses to rename a file another process has open. Deleting it by name is what
    // happened before this check existed, and still beats keeping a credential known to be bad.
    debugLog(`Could not set ${filename} aside; deleting it in place`, error)
    await deleteConfigFile(serverUrlHash, filename)
    return true
  }

  try {
    // A version that cannot be read back cannot be checked either, so it goes back like a newer one
    const setAside = await fs.readFile(aside, 'utf-8').catch(() => undefined)
    if (setAside !== undefined && (setAside === checked || judge(setAside))) return true

    debugLog(`Kept ${filename}, which changed after it was checked`)
    await restoreConfigFile(aside, filePath)
    return false
  } finally {
    await fs.unlink(aside).catch(() => {})
  }
}

/** Puts a file that was set aside back under its name, without overwriting one written there since. */
async function restoreConfigFile(aside: string, filePath: string): Promise<void> {
  try {
    // A hard link appears whole or not at all, and fails rather than replace a newer file
    await fs.link(aside, filePath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return
    // A filesystem without hard links: copy instead, still refusing to overwrite
    await fs.copyFile(aside, filePath, fs.constants.COPYFILE_EXCL).catch((copyError: NodeJS.ErrnoException) => {
      if (copyError.code !== 'EEXIST') log(`Error restoring ${path.basename(filePath)}:`, copyError)
    })
  }
}

/**
 * Removes this server's config files with the given prefix that are older than maxAgeMs
 *
 * A filename carrying a one-off identifier is never written again, so abandoned ones would stay
 * forever. The age check leaves alone any file a flow still in progress may need.
 * @param serverUrlHash The hash of the server URL
 * @param prefix The filename prefix to sweep
 * @param maxAgeMs How old a file must be before it is removed
 */
export async function deleteStaleConfigFiles(serverUrlHash: string, prefix: string, maxAgeMs: number): Promise<void> {
  try {
    const configDir = getConfigDir()
    const cutoff = Date.now() - maxAgeMs
    const entries = await fs.readdir(configDir)

    await Promise.all(
      entries
        .filter((entry) => entry.startsWith(`${serverUrlHash}_${prefix}`))
        .map(async (entry) => {
          const filePath = path.join(configDir, entry)
          try {
            if ((await fs.stat(filePath)).mtimeMs > cutoff) return
            await fs.unlink(filePath)
            debugLog(`Removed stale config file: ${entry}`)
          } catch (error) {
            // Another instance may be sweeping the same directory
            debugLog(`Could not remove stale config file ${entry}`, error)
          }
        }),
    )
  } catch (error) {
    debugLog('Could not sweep stale config files', error)
  }
}

/**
 * Reads a JSON file and parses it with the provided schema
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to read
 * @param schema The schema to validate against
 * @returns The parsed file content or undefined if the file doesn't exist
 */
export async function readJsonFile<T>(serverUrlHash: string, filename: string, schema: any): Promise<T | undefined> {
  try {
    await ensureConfigDir()

    const filePath = getConfigFilePath(serverUrlHash, filename)
    const content = await fs.readFile(filePath, 'utf-8')
    const result = await schema.parseAsync(JSON.parse(content))
    // console.log({ filename: result })
    return result
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      // console.log(`File ${filename} does not exist`)
      return undefined
    }
    log(`Error reading ${filename}:`, error)
    return undefined
  }
}

/**
 * Writes a JSON object to a file atomically using temp file + rename pattern.
 * This prevents race conditions where multiple processes might read partially-written files.
 * The rename operation is atomic on POSIX systems.
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to write
 * @param data The data to write
 */
export async function writeJsonFile(serverUrlHash: string, filename: string, data: any): Promise<void> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)

    // Write to a sibling temp file and rename over the target, so a concurrent
    // reader sees either the old file or the new one but never a half-written
    // one. mcp-remote routinely runs several instances against the same config
    // directory, and a torn read of tokens.json surfaces as a parse failure that
    // looks like corrupted credentials.
    const serialized = JSON.stringify(data, null, 2)
    // Unique per write, not per millisecond: two writes from one process can land in the same one,
    // and the second would then rename a temp file the first had already moved
    const tempPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`

    try {
      await fs.writeFile(tempPath, serialized, { encoding: 'utf-8', mode: 0o600 })
      await fs.rename(tempPath, filePath)
    } catch (renameError) {
      await fs.unlink(tempPath).catch(() => {})

      // Windows rejects a rename onto a file another process still holds open.
      // A direct write can tear, but failing outright would lose the data.
      if (process.platform === 'win32') {
        debugLog('Atomic rename failed, falling back to a direct write', { filename, renameError })
        await fs.writeFile(filePath, serialized, { encoding: 'utf-8', mode: 0o600 })
        return
      }
      throw renameError
    }
  } catch (error) {
    log(`Error writing ${filename}:`, error)
    throw error
  }
}

/**
 * Reads a text file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to read
 * @param errorMessage Optional custom error message
 * @returns The file content as a string
 */
export async function readTextFile(serverUrlHash: string, filename: string, errorMessage?: string): Promise<string> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    return await fs.readFile(filePath, 'utf-8')
  } catch (error) {
    throw new Error(errorMessage || `Error reading ${filename}`, { cause: error })
  }
}

/**
 * Writes a text string to a file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to write
 * @param text The text to write
 */
export async function writeTextFile(serverUrlHash: string, filename: string, text: string): Promise<void> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.writeFile(filePath, text, { encoding: 'utf-8', mode: 0o600 })
  } catch (error) {
    log(`Error writing ${filename}:`, error)
    throw error
  }
}

/**
 * A lease records who took it and when, so a challenger can tell an owner still working from one
 * that will never come back. The nonce is the part no other instance can guess, which is what
 * makes ownership checkable after the fact.
 */
const ConfigLeaseSchema = z.object({ pid: z.number().int().positive(), nonce: z.string().min(1), at: z.number() })

/** A lease read off disk, with whether its owner still appears to hold it. */
export type ConfigLease = z.infer<typeof ConfigLeaseSchema> & { live: boolean }

/**
 * Whether a process still exists.
 *
 * Signal 0 sends nothing; it only asks the kernel to do the permission and existence checks it
 * would do for a real signal. EPERM means the process is there and belongs to someone else.
 */
function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM'
  }
}

/**
 * Takes a lease on a filename, naming this process as its owner.
 *
 * The claim itself is one `O_CREAT|O_EXCL` write, so the kernel picks the winner and no two
 * instances can create the same file. What a file cannot do is release itself when its owner
 * dies, so the lease also records a pid and a timestamp: an owner that no longer exists is gone
 * for good and its lease is taken immediately, and one that exists but has held the lease past
 * `maxAgeMs` is treated the same way, since a wedged instance would otherwise block every other
 * one forever.
 *
 * Clearing an abandoned lease is not atomic on its own - two challengers can each delete what
 * they found and each create their own - so a claim is only trusted once the file is read back
 * and still carries the nonce this call wrote.
 *
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the lease file
 * @param maxAgeMs How long an owner may hold the lease before a challenger may take it
 * @returns The nonce identifying this lease, or undefined if another instance holds it
 */
export async function acquireConfigLease(serverUrlHash: string, filename: string, maxAgeMs: number): Promise<string | undefined> {
  await ensureConfigDir()
  const filePath = getConfigFilePath(serverUrlHash, filename)
  const nonce = randomUUID()

  // At most one round of clearing an abandoned lease, so a filename nothing can hold - a
  // directory, say - cannot spin here.
  for (const attempt of [0, 1]) {
    try {
      const lease = { pid: process.pid, nonce, at: Date.now() }
      await fs.writeFile(filePath, JSON.stringify(lease, null, 2), { encoding: 'utf-8', mode: 0o600, flag: 'wx' })
      return (await readLeaseFile(serverUrlHash, filename))?.nonce === nonce ? nonce : undefined
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST' || attempt > 0) return undefined

      const held = await readConfigLease(serverUrlHash, filename, maxAgeMs)
      if (held?.live) return undefined

      // Abandoned, or unreadable and so of no use to whoever wrote it either
      debugLog('Clearing an abandoned lease', { filename, heldBy: held?.pid })
      await fs.unlink(filePath).catch(() => {})
    }
  }
  return undefined
}

/** @returns The lease on disk, or undefined if there is none or it cannot be read */
async function readLeaseFile(serverUrlHash: string, filename: string): Promise<z.infer<typeof ConfigLeaseSchema> | undefined> {
  return readJsonFile<z.infer<typeof ConfigLeaseSchema>>(serverUrlHash, filename, ConfigLeaseSchema)
}

/**
 * Reads the lease on a filename, if one is held
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the lease file
 * @param maxAgeMs How long an owner may hold the lease before a challenger may take it
 * @returns The lease and whether its owner still holds it, or undefined if nobody does
 */
export async function readConfigLease(serverUrlHash: string, filename: string, maxAgeMs: number): Promise<ConfigLease | undefined> {
  const lease = await readLeaseFile(serverUrlHash, filename)
  if (!lease) return undefined
  return { ...lease, live: Date.now() - lease.at < maxAgeMs && processIsAlive(lease.pid) }
}

/**
 * Releases a lease, if this instance still holds it.
 *
 * An owner that ran past `maxAgeMs` may find the lease already taken by someone else, and
 * deleting that one would hand the same work to a third instance.
 *
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the lease file
 * @param nonce The nonce returned when the lease was acquired
 */
export async function releaseConfigLease(serverUrlHash: string, filename: string, nonce: string): Promise<void> {
  if ((await readLeaseFile(serverUrlHash, filename))?.nonce !== nonce) return
  await deleteConfigFile(serverUrlHash, filename)
}
