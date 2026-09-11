import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  connectToRemoteServer,
  encodeMcpHeaderValue,
  parseCommandLineArgs,
  shouldIncludeTool,
  mcpProxy,
  setupOAuthCallbackServerWithLongPoll,
  getServerUrlHash,
  calculateDefaultPort,
  mergeHeaders,
  parseSecondsOption,
  parseAuthorizeParams,
  fetchWithMcpHeaders,
} from './utils'
import { getConfigDir } from './mcp-auth-config'
import { Headers as UndiciHeaders } from 'undici'
import {
  Client,
  OAuthError,
  OAuthErrorCode,
  parseErrorResponse,
  SdkErrorCode,
  SdkHttpError,
  UnauthorizedError,
} from '@modelcontextprotocol/client'
import type { OAuthClientProvider } from '@modelcontextprotocol/client'
import type { Transport } from '@modelcontextprotocol/client'
import { EventEmitter } from 'events'
import { createServer, type ServerResponse } from 'node:http'

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))
import net from 'net'
import fs from 'fs'
import os from 'os'
import path from 'path'

// All sanitizeUrl tests have been moved to the strict-url-sanitise package

describe('Feature: Command Line Arguments Parsing', () => {
  it('Scenario: Show help without parsing server URL', async () => {
    // Given command line arguments with only the help flag
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((() => true) as any)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit:${code}`)
    })

    // When parsing the command line arguments
    await expect(parseCommandLineArgs(['--help'], 'test usage')).rejects.toThrow('process.exit:0')

    // Then usage should be written before URL validation
    expect(stdoutSpy).toHaveBeenCalledWith('test usage\n')

    stdoutSpy.mockRestore()
    exitSpy.mockRestore()
  })

  it('Scenario: Show version without parsing server URL', async () => {
    // Given command line arguments with only the version flag
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((() => true) as any)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit:${code}`)
    })

    // When parsing the command line arguments
    await expect(parseCommandLineArgs(['--version'], 'test usage')).rejects.toThrow('process.exit:0')

    // Then the version should be written before URL validation
    expect(stdoutSpy).toHaveBeenCalledWith(expect.stringMatching(/^\d+\.\d+\.\d+\n$/))

    stdoutSpy.mockRestore()
    exitSpy.mockRestore()
  })

  it('Scenario: Parse basic server URL', async () => {
    // Given command line arguments with only a server URL
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the server URL should be correctly extracted
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(typeof result.serverUrl).toBe('string')
  })

  it('Scenario: Parse server URL with callback port', async () => {
    // Given command line arguments with server URL and port
    const args = ['https://example.com/sse', '3000']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then both server URL and callback port should be correctly extracted
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.callbackPort).toBe(3000)
  })

  it('Scenario: Default to the standard callback path when --callback-path is absent', async () => {
    // Given command line arguments without a callback path
    const args = ['https://example.com/sse']

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, 'test usage')

    // Then the standard callback path should be used
    expect(result.callbackPath).toBe('/oauth/callback')
  })

  it('Scenario: Parse server URL with callback path', async () => {
    // Given command line arguments with a custom callback path
    const args = ['https://example.com/sse', '--callback-path', '/custom-callback']

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, 'test usage')

    // Then both server URL and callback path should be correctly extracted
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.callbackPath).toBe('/custom-callback')
  })

  it('Scenario: Parse a client metadata document URL', async () => {
    // Given a URL serving this client's metadata document (SEP-991)
    const args = ['https://example.com/sse', '--client-metadata-url', 'https://example.com/.well-known/oauth-client-metadata']

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, 'test usage')

    // Then it is carried through to the OAuth client provider
    expect(result.clientMetadataUrl).toBe('https://example.com/.well-known/oauth-client-metadata')
  })

  it('Scenario: Ignore a client metadata URL an authorization server would reject', async () => {
    // Given URLs failing the two rules SEP-991 imposes: HTTPS, and a path to distinguish
    // the client id from the origin serving it
    for (const url of ['http://example.com/client-metadata', 'https://example.com/', 'https://example.com', 'not-a-url']) {
      const result = await parseCommandLineArgs(['https://example.com/sse', '--client-metadata-url', url], 'test usage')

      // Then it is dropped here, rather than thrown from inside the sign-in
      expect(result.clientMetadataUrl).toBeUndefined()
    }
  })

  it('Scenario: Register dynamically when no client metadata URL is given', async () => {
    const result = await parseCommandLineArgs(['https://example.com/sse'], 'test usage')

    expect(result.clientMetadataUrl).toBeUndefined()
  })

  it('Scenario: Ask for the ID token to be sent as the bearer credential', async () => {
    const result = await parseCommandLineArgs(['https://example.com/sse', '--use-id-token'], 'test usage')

    expect(result.useIdToken).toBe(true)
  })

  it('Scenario: Send the access token when nothing asks otherwise', async () => {
    const result = await parseCommandLineArgs(['https://example.com/sse'], 'test usage')

    expect(result.useIdToken).toBe(false)
  })

  it('Scenario: Ask to sign in without a browser on this machine', async () => {
    const result = await parseCommandLineArgs(['https://example.com/sse', '--device-code'], 'test usage')

    expect(result.useDeviceCode).toBe(true)
  })

  it('Scenario: Use the browser flow when nothing asks otherwise', async () => {
    const result = await parseCommandLineArgs(['https://example.com/sse'], 'test usage')

    expect(result.useDeviceCode).toBe(false)
  })

  it('Scenario: Keep credentials for a metadata document client apart from registered ones', async () => {
    // Given the same server reached once by registration and once by metadata document
    const registered = await parseCommandLineArgs(['https://example.com/sse'], 'test usage')
    const byDocument = await parseCommandLineArgs(
      ['https://example.com/sse', '--client-metadata-url', 'https://client.example.com/metadata'],
      'test usage',
    )

    // Then they do not share a token store: a refresh token belongs to the client that
    // obtained it, so the other client cannot renew it
    expect(byDocument.serverUrlHash).not.toBe(registered.serverUrlHash)
  })

  it('Scenario: Ignore a callback path that is not rooted', async () => {
    // Given a callback path Express cannot route back to the redirect URI we would advertise
    const args = ['https://example.com/sse', '--callback-path', 'custom-callback']

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, 'test usage')

    // Then the standard callback path should be kept
    expect(result.callbackPath).toBe('/oauth/callback')
  })

  it('Scenario: Ignore a callback path that shadows the long-poll endpoint', async () => {
    // Given a callback path that collides with the endpoint secondary instances poll
    const args = ['https://example.com/sse', '--callback-path', '/wait-for-auth']

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, 'test usage')

    // Then the standard callback path should be kept
    expect(result.callbackPath).toBe('/oauth/callback')
  })

  it('Scenario: Parse localhost URL with HTTP protocol', async () => {
    // Given command line arguments with localhost HTTP URL
    const args = ['http://localhost:8080/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the localhost HTTP URL should be accepted
    expect(result.serverUrl).toBe('http://localhost:8080/sse')
  })

  it('Scenario: Parse 127.0.0.1 URL with HTTP protocol', async () => {
    // Given command line arguments with 127.0.0.1 HTTP URL
    const args = ['http://127.0.0.1:8080/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the 127.0.0.1 HTTP URL should be accepted
    expect(result.serverUrl).toBe('http://127.0.0.1:8080/sse')
  })

  it('Scenario: Parse single custom header', async () => {
    // Given command line arguments with a custom header
    const args = ['https://example.com/sse', '--header', 'foo: taz']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the custom header should be correctly parsed
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.headers).toEqual({ foo: 'taz' })
  })

  it('Scenario: Parse multiple custom headers', async () => {
    // Given command line arguments with multiple custom headers
    const args = ['https://example.com/sse', '--header', 'Authorization: Bearer token123', '--header', 'Content-Type: application/json']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then all custom headers should be correctly parsed
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.headers).toEqual({
      Authorization: 'Bearer token123',
      'Content-Type': 'application/json',
    })
  })

  it('Scenario: Never log custom header values', async () => {
    // Given a header carrying a secret
    const logSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--header', 'Authorization: Bearer super-secret-token']

    // When parsing the command line arguments
    await parseCommandLineArgs(args, 'test usage')

    // Then the header name is logged but the secret never is
    const logged = logSpy.mock.calls.map((c) => c.map(String).join(' ')).join('\n')
    expect(logged).toContain('Authorization')
    expect(logged).not.toContain('super-secret-token')

    logSpy.mockRestore()
  })

  it('Scenario: Read headers from a file', async () => {
    // Given a header file, which is how you keep a credential out of the process arguments
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-remote-headers-'))
    const file = path.join(dir, 'headers.txt')
    fs.writeFileSync(
      file,
      ['# credentials for the example server', 'Authorization: Bearer secret-token', 'X-Tenant:acme', '', '  '].join('\n'),
    )

    const result = await parseCommandLineArgs(['https://example.remote/server', '--header-file', file], 'usage')

    // Then comments and blank lines are skipped, and values are trimmed as --header trims them
    expect(result.headers).toEqual({ Authorization: 'Bearer secret-token', 'X-Tenant': 'acme' })
    fs.rmSync(dir, { recursive: true, force: true })
  })

  it('Scenario: A header file that cannot be read is fatal', async () => {
    // Carrying on would send the request unauthenticated and surface far from the real mistake
    await expect(parseCommandLineArgs(['https://example.remote/server', '--header-file', '/nope/missing.txt'], 'usage')).rejects.toThrow(
      /Could not read the header file/,
    )
  })

  it('Scenario: A malformed line in a header file is reported without its contents', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-remote-headers-'))
    const file = path.join(dir, 'headers.txt')
    fs.writeFileSync(file, ['Authorization Bearer super-secret', 'X-Ok: fine'].join('\n'))
    const logged: string[] = []
    const spy = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => void logged.push(a.join(' ')))

    const result = await parseCommandLineArgs(['https://example.remote/server', '--header-file', file], 'usage')

    // The good line still loads, and the bad one is named by line number - it is where a
    // credential would be if someone forgot the colon
    expect(result.headers).toEqual({ 'X-Ok': 'fine' })
    expect(logged.join('\n')).toContain('line 1')
    expect(logged.join('\n')).not.toContain('super-secret')
    spy.mockRestore()
    fs.rmSync(dir, { recursive: true, force: true })
  })

  it('Scenario: A malformed --header argument is reported without its value', async () => {
    const logged: string[] = []
    const spy = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => void logged.push(a.join(' ')))

    await parseCommandLineArgs(['https://example.remote/server', '--header', 'Authorization Bearer super-secret'], 'usage')

    expect(logged.join('\n')).not.toContain('super-secret')
    spy.mockRestore()
  })

  it('Scenario: Ignore invalid header format', async () => {
    // Given command line arguments with an invalid header format
    const args = ['https://example.com/sse', '--header', 'invalid-header-format']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the invalid header should be ignored and headers should be empty
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.headers).toEqual({})
  })

  it('Scenario: Handle --allow-http flag for non-localhost URLs', async () => {
    // Given command line arguments with HTTP URL and --allow-http flag
    const args = ['http://example.com/sse', '--allow-http']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the HTTP URL should be accepted due to --allow-http flag
    expect(result.serverUrl).toBe('http://example.com/sse')
  })

  it('Scenario: Accept HTTPS URLs without --allow-http flag', async () => {
    // Given command line arguments with HTTPS URL only
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the HTTPS URL should be accepted without any additional flags
    expect(result.serverUrl).toBe('https://example.com/sse')
  })

  it('Scenario: Handle --allow-http with other arguments', async () => {
    // Given command line arguments with HTTP URL, port, --allow-http flag, and custom header
    const args = ['http://example.com/sse', '4000', '--allow-http', '--header', 'Authorization: Bearer abc123']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then all arguments should be correctly parsed including HTTP URL acceptance
    expect(result.serverUrl).toBe('http://example.com/sse')
    expect(result.callbackPort).toBe(4000)
    expect(result.headers).toEqual({ Authorization: 'Bearer abc123' })
  })

  it('Scenario: Use default transport strategy when not specified', async () => {
    // Given command line arguments with only server URL
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default transport strategy should be http-first
    expect(result.transportStrategy).toBe('http-first')
  })

  it('Scenario: Parse transport strategy sse-only', async () => {
    // Given command line arguments with --transport sse-only
    const args = ['https://example.com/sse', '--transport', 'sse-only']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the transport strategy should be set to sse-only
    expect(result.transportStrategy).toBe('sse-only')
  })

  it('Scenario: Parse transport strategy http-only', async () => {
    // Given command line arguments with --transport http-only
    const args = ['https://example.com/sse', '--transport', 'http-only']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the transport strategy should be set to http-only
    expect(result.transportStrategy).toBe('http-only')
  })

  it('Scenario: Parse transport strategy sse-first', async () => {
    // Given command line arguments with --transport sse-first
    const args = ['https://example.com/sse', '--transport', 'sse-first']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the transport strategy should be set to sse-first
    expect(result.transportStrategy).toBe('sse-first')
  })

  it('Scenario: Parse transport strategy http-first', async () => {
    // Given command line arguments with --transport http-first
    const args = ['https://example.com/sse', '--transport', 'http-first']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the transport strategy should be set to http-first
    expect(result.transportStrategy).toBe('http-first')
  })

  it('Scenario: Ignore invalid transport strategy and use default', async () => {
    // Given command line arguments with invalid transport strategy
    const args = ['https://example.com/sse', '--transport', 'invalid-strategy']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the invalid strategy should be ignored and default should be used
    expect(result.transportStrategy).toBe('http-first') // Should fallback to default
  })

  it('Scenario: Use default host when not specified', async () => {
    // Given command line arguments with only server URL
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default host should be localhost
    expect(result.host).toBe('localhost')
  })

  it('Scenario: Default to the IPv4 loopback literal on Windows', async () => {
    // Given Windows, where `localhost` often resolves to ::1 first while the
    // callback server binds 127.0.0.1, so the redirect lands on a closed socket
    const original = Object.getOwnPropertyDescriptor(process, 'platform')!
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })

    try {
      // When parsing without an explicit --host
      const result = await parseCommandLineArgs(['https://example.com/sse'], 'test usage')

      // Then the redirect URI names the address the listener is actually on
      expect(result.host).toBe('127.0.0.1')
    } finally {
      Object.defineProperty(process, 'platform', original)
    }
  })

  it('Scenario: An explicit --host still wins on Windows', async () => {
    const original = Object.getOwnPropertyDescriptor(process, 'platform')!
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })

    try {
      const result = await parseCommandLineArgs(['https://example.com/sse', '--host', 'myserver.local'], 'test usage')

      expect(result.host).toBe('myserver.local')
    } finally {
      Object.defineProperty(process, 'platform', original)
    }
  })

  it('Scenario: Parse custom IP host', async () => {
    // Given command line arguments with custom IP host
    const args = ['https://example.com/sse', '--host', '127.0.0.1']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the custom IP host should be correctly set
    expect(result.host).toBe('127.0.0.1')
  })

  it('Scenario: Parse custom domain host', async () => {
    // Given command line arguments with custom domain host
    const args = ['https://example.com/sse', '--host', 'myserver.local']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the custom domain host should be correctly set
    expect(result.host).toBe('myserver.local')
  })

  it('Scenario: Handle host with multiple other arguments', async () => {
    // Given command line arguments with host, port, and transport strategy
    const args = ['https://example.com/sse', '3000', '--host', 'custom.host.com', '--transport', 'sse-only']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then all arguments should be correctly parsed including the host
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.callbackPort).toBe(3000)
    expect(result.host).toBe('custom.host.com')
    expect(result.transportStrategy).toBe('sse-only')
  })

  it('Scenario: Return empty ignored tools array when none specified', async () => {
    // Given command line arguments without --ignore-tool flags
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the ignored tools array should be empty
    expect(result.ignoredTools).toEqual([])
  })

  it('Scenario: Parse single ignored tool', async () => {
    // Given command line arguments with one --ignore-tool flag
    const args = ['https://example.com/sse', '--ignore-tool', 'foo']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the ignored tools array should contain the specified tool
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.ignoredTools).toEqual(['foo'])
  })

  it('Scenario: Parse multiple ignored tools', async () => {
    // Given command line arguments with multiple --ignore-tool flags
    const args = ['https://example.com/sse', '--ignore-tool', 'foo', '--ignore-tool', 'bar', '--ignore-tool', 'baz']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the ignored tools array should contain all specified tools
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.ignoredTools).toEqual(['foo', 'bar', 'baz'])
  })

  it('Scenario: Handle ignored tools with other arguments', async () => {
    // Given command line arguments with ignored tools mixed with other arguments
    const args = [
      'https://example.com/sse',
      '4000',
      '--ignore-tool',
      'tool1',
      '--host',
      'localhost',
      '--ignore-tool',
      'tool2',
      '--transport',
      'sse-only',
    ]
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then all arguments should be correctly parsed including ignored tools
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.callbackPort).toBe(4000)
    expect(result.host).toBe('localhost')
    expect(result.transportStrategy).toBe('sse-only')
    expect(result.ignoredTools).toEqual(['tool1', 'tool2'])
  })

  it('Scenario: Use default auth timeout when not specified', async () => {
    // Given command line arguments without --auth-timeout flag
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default auth timeout should be 30000ms
    expect(result.authTimeoutMs).toBe(30000)
  })

  it('Scenario: Parse valid auth timeout in seconds and convert to milliseconds', async () => {
    // Given command line arguments with valid --auth-timeout
    const args = ['https://example.com/sse', '--auth-timeout', '60']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the timeout should be converted to milliseconds
    expect(result.authTimeoutMs).toBe(60000)
  })

  it('Scenario: Use default timeout when invalid auth timeout value is provided', async () => {
    // Given command line arguments with invalid --auth-timeout value
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', 'invalid']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default timeout should be used and warning logged
    expect(result.authTimeoutMs).toBe(30000)
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: Ignoring invalid auth timeout value: invalid. Must be a positive number.'),
    )

    consoleSpy.mockRestore()
  })

  it('Scenario: Use default timeout when negative auth timeout value is provided', async () => {
    // Given command line arguments with negative --auth-timeout value
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', '-30']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default timeout should be used and warning logged
    expect(result.authTimeoutMs).toBe(30000)
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: Ignoring invalid auth timeout value: -30. Must be a positive number.'),
    )

    consoleSpy.mockRestore()
  })

  it('Scenario: Use default timeout when zero auth timeout value is provided', async () => {
    // Given command line arguments with zero --auth-timeout value
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', '0']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default timeout should be used and warning logged
    expect(result.authTimeoutMs).toBe(30000)
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: Ignoring invalid auth timeout value: 0. Must be a positive number.'),
    )

    consoleSpy.mockRestore()
  })

  it('Scenario: Log when using custom auth timeout', async () => {
    // Given command line arguments with custom --auth-timeout value
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', '45']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the custom timeout should be used and logged
    expect(result.authTimeoutMs).toBe(45000)
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Using auth callback timeout: 45 seconds'))

    consoleSpy.mockRestore()
  })

  it('Scenario: Suppresses LOG when using --silent', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', '45', '--silent']
    const usage = 'test usage'

    const result = await parseCommandLineArgs(args, usage)

    expect(result.authTimeoutMs).toBe(45000)
    expect(consoleSpy).not.toHaveBeenCalled()

    consoleSpy.mockRestore()
  })
})

/**
 * A minimal MCP endpoint that records the standard request headers it is sent.
 *
 * Only enough of the protocol is implemented to get a client through `initialize`
 * and a single `tools/call`.
 */
function createHeaderRecordingServer() {
  const seen: Array<{ method: string; mcpMethod?: string; mcpName?: string }> = []

  const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value)

  const server = createServer((request, response) => {
    if (request.method !== 'POST') {
      response.writeHead(405)
      response.end()
      return
    }

    let body = ''
    request.setEncoding('utf8')
    request.on('data', (chunk: string) => {
      body += chunk
    })
    request.on('end', () => {
      const message = JSON.parse(body) as { id?: string | number; method: string; params?: { name?: string } }
      seen.push({
        method: message.method,
        mcpMethod: first(request.headers['mcp-method']),
        mcpName: first(request.headers['mcp-name']),
      })

      // Notifications get an empty 202, per the Streamable HTTP transport.
      if (message.id === undefined) {
        response.writeHead(202)
        response.end()
        return
      }

      const result =
        message.method === 'initialize'
          ? {
              protocolVersion: '2025-03-26',
              capabilities: { tools: {} },
              serverInfo: { name: 'test-server', version: '1.0.0' },
            }
          : { content: [{ type: 'text', text: 'ok' }] }

      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }))
    })
  })

  return {
    seen,
    async start() {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject)
        server.listen(0, '127.0.0.1', resolve)
      })
      const address = server.address()
      if (!address || typeof address === 'string') throw new Error('test server did not expose a port')
      return `http://127.0.0.1:${address.port}/mcp`
    },
    async stop() {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
    },
  }
}

const noAuth = async () => {
  throw new Error('the test server should not request OAuth')
}

describe('Feature: Method-aware MCP HTTP gateways', () => {
  it('Scenario: The JSON-RPC method is mirrored into Mcp-Method', async () => {
    // Given a server that records the headers it receives
    const gateway = createHeaderRecordingServer()
    const url = await gateway.start()

    try {
      // When a client connects and sends a further message
      const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} })
      const transport = await connectToRemoteServer(client, url, undefined as unknown as OAuthClientProvider, {}, noAuth, 'http-only')

      await transport.send({ jsonrpc: '2.0', method: 'server/discover', params: {} })

      // Then every POST carries the method it is actually sending
      expect(gateway.seen[0]).toMatchObject({ method: 'initialize', mcpMethod: 'initialize' })
      expect(gateway.seen).toContainEqual(expect.objectContaining({ method: 'server/discover', mcpMethod: 'server/discover' }))
      await transport.close()
    } finally {
      await gateway.stop()
    }
  })

  it('Scenario: tools/call also carries the tool name in Mcp-Name', async () => {
    // Given a server that records the headers it receives
    const gateway = createHeaderRecordingServer()
    const url = await gateway.start()

    try {
      // When the client calls a tool
      const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} })
      const transport = await connectToRemoteServer(client, url, undefined as unknown as OAuthClientProvider, {}, noAuth, 'http-only')
      await client.callTool({ name: 'get_weather', arguments: { location: 'Seattle, WA' } })

      // Then the call is routable on both headers without parsing the body.
      // Sending Mcp-Method alone here would itself be a -32020 HeaderMismatch.
      expect(gateway.seen).toContainEqual({ method: 'tools/call', mcpMethod: 'tools/call', mcpName: 'get_weather' })

      // And a method that has no Mcp-Name source does not invent one
      expect(gateway.seen[0]).toEqual({ method: 'initialize', mcpMethod: 'initialize', mcpName: undefined })
      await transport.close()
    } finally {
      await gateway.stop()
    }
  })

  it('Scenario: resources/read sources Mcp-Name from params.uri', async () => {
    // Given a server that records the headers it receives
    const gateway = createHeaderRecordingServer()
    const url = await gateway.start()

    try {
      const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} })
      const transport = await connectToRemoteServer(client, url, undefined as unknown as OAuthClientProvider, {}, noAuth, 'http-only')

      // When a resources/read and a prompts/get go out
      await transport.send({ jsonrpc: '2.0', method: 'resources/read', params: { uri: 'file:///app/config.json' } })
      await transport.send({ jsonrpc: '2.0', method: 'prompts/get', params: { name: 'summarize' } })
      // A URI RFC 9110 cannot carry verbatim has to survive the trip encoded
      await transport.send({ jsonrpc: '2.0', method: 'resources/read', params: { uri: 'file:///projects/世界.json' } })

      // Then each takes its name from the field SEP-2243 assigns it
      expect(gateway.seen).toContainEqual({
        method: 'resources/read',
        mcpMethod: 'resources/read',
        mcpName: 'file:///app/config.json',
      })
      expect(gateway.seen).toContainEqual({ method: 'prompts/get', mcpMethod: 'prompts/get', mcpName: 'summarize' })
      expect(gateway.seen).toContainEqual({
        method: 'resources/read',
        mcpMethod: 'resources/read',
        mcpName: encodeMcpHeaderValue('file:///projects/世界.json'),
      })
      await transport.close()
    } finally {
      await gateway.stop()
    }
  })

  it('Scenario: An explicitly passed header is not overwritten', async () => {
    // Given a server that records the headers it receives
    const gateway = createHeaderRecordingServer()
    const url = await gateway.start()

    try {
      // When the user pins Mcp-Method themselves via --header
      const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} })
      const transport = await connectToRemoteServer(
        client,
        url,
        undefined as unknown as OAuthClientProvider,
        { 'Mcp-Method': 'pinned-by-user' },
        noAuth,
        'http-only',
      )

      // Then their value survives
      expect(gateway.seen[0]).toMatchObject({ method: 'initialize', mcpMethod: 'pinned-by-user' })
      await transport.close()
    } finally {
      await gateway.stop()
    }
  })

  it('Scenario: The http-first probe carries the headers too', async () => {
    // Given a server that records the headers it receives
    const gateway = createHeaderRecordingServer()
    const url = await gateway.start()

    try {
      // When connecting in proxy mode (client=null), where a one-off probe transport
      // sends the first initialize
      const transport = await connectToRemoteServer(null, url, undefined as unknown as OAuthClientProvider, {}, noAuth, 'http-first')

      // Then the probe - the very request a method-aware gateway routes on - is labelled
      expect(gateway.seen[0]).toMatchObject({ method: 'initialize', mcpMethod: 'initialize' })
      await transport.close()
    } finally {
      await gateway.stop()
    }
  })
})

/**
 * A server standing in for one behind a sticky load balancer: it plants a routing cookie on the
 * first response and records what every later request sends back.
 */
function createStickyServer() {
  const cookiesSeen: Array<string | undefined> = []
  let responses = 0

  const server = createServer((request, response) => {
    let body = ''
    request.setEncoding('utf8')
    request.on('data', (chunk: string) => {
      body += chunk
    })
    request.on('end', () => {
      cookiesSeen.push(request.headers.cookie)

      const headers: Record<string, string | string[]> = { 'content-type': 'application/json' }
      if (++responses === 1) {
        headers['set-cookie'] = ['AWSALB=node-1; Path=/', 'AWSALBCORS=node-1; Path=/; SameSite=None']
      }

      // Closing the transport sends a bodyless DELETE to end the session, and it carries a
      // cookie like everything else - there is just nothing to answer.
      const message = body ? (JSON.parse(body) as { id?: string | number; method: string }) : undefined
      if (!message || message.id === undefined) {
        response.writeHead(202, headers)
        response.end()
        return
      }

      response.writeHead(200, headers)
      response.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: message.id,
          result:
            message.method === 'initialize'
              ? { protocolVersion: '2025-03-26', capabilities: {}, serverInfo: { name: 'sticky', version: '1.0.0' } }
              : {},
        }),
      )
    })
  })

  return {
    cookiesSeen,
    async start() {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject)
        server.listen(0, '127.0.0.1', resolve)
      })
      const address = server.address()
      if (!address || typeof address === 'string') throw new Error('test server did not expose a port')
      return `http://127.0.0.1:${address.port}/mcp`
    },
    async stop() {
      server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
    },
  }
}

describe('Feature: Load balancer session stickiness', () => {
  it('Scenario: A cookie the server sets is sent back on every later request', async () => {
    // Given a server behind a balancer that pins this client to one node
    const sticky = createStickyServer()
    const url = await sticky.start()

    try {
      const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} })
      const transport = await connectToRemoteServer(client, url, undefined as unknown as OAuthClientProvider, {}, noAuth, 'http-only')
      await transport.send({ jsonrpc: '2.0', method: 'server/discover', id: 2, params: {} })

      // Then the first request could not have carried one, and everything after it does -
      // without which each request lands on whichever node the balancer feels like, and the
      // session is on none of them (issue #168)
      expect(sticky.cookiesSeen[0]).toBeUndefined()
      expect(sticky.cookiesSeen.length).toBeGreaterThan(1)
      for (const cookie of sticky.cookiesSeen.slice(1)) {
        expect(cookie).toBe('AWSALB=node-1; AWSALBCORS=node-1')
      }

      await transport.close()
    } finally {
      await sticky.stop()
    }
  }, 15_000)

  it('Scenario: A header the user pinned is not overwritten by the jar', async () => {
    // Given someone sending their own Cookie via --header
    const sticky = createStickyServer()
    const url = await sticky.start()

    try {
      const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} })
      const transport = await connectToRemoteServer(
        client,
        url,
        undefined as unknown as OAuthClientProvider,
        { Cookie: 'pinned=by-the-user' },
        noAuth,
        'http-only',
      )
      await transport.send({ jsonrpc: '2.0', method: 'server/discover', id: 2, params: {} })

      // Then theirs is what the server sees, throughout
      for (const cookie of sticky.cookiesSeen) {
        expect(cookie).toBe('pinned=by-the-user')
      }

      await transport.close()
    } finally {
      await sticky.stop()
    }
  }, 15_000)
})

/**
 * A minimal MCP SSE server: it hands every stream it serves a POST endpoint carrying a session id
 * of its own, which is what the Python SDK does and what makes a reconnect lose the lifecycle.
 * The test drops the stream to make the client's EventSource come back for another.
 */
function createSseServer() {
  let streamsServed = 0
  let openStream: ServerResponse | undefined

  const postCookies: Array<string | undefined> = []

  const server = createServer((request, response) => {
    if (!request.url?.startsWith('/sse')) {
      postCookies.push(request.headers.cookie)
      response.writeHead(202)
      response.end()
      return
    }

    streamsServed += 1
    response.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
      // A balancer plants its cookie on the stream; the POSTs have to carry it back
      'set-cookie': `AWSALB=node-${streamsServed}; Path=/`,
    })
    // Without this the EventSource waits out its own default before trying again
    response.write('retry: 10\n\n')
    response.write(`event: endpoint\ndata: /messages/?session_id=${streamsServed}\n\n`)
    openStream = response
  })

  return {
    postCookies,
    get streamsServed() {
      return streamsServed
    },
    dropStream() {
      openStream?.end()
    },
    async start() {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject)
        server.listen(0, '127.0.0.1', resolve)
      })
      const address = server.address()
      if (!address || typeof address === 'string') throw new Error('test server did not expose a port')
      return `http://127.0.0.1:${address.port}/sse`
    },
    async stop() {
      server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
    },
  }
}

describe('Feature: Noticing an SSE stream come back', () => {
  it('Scenario: A stream that drops and reconnects is reported to the proxy', async () => {
    // Given a connected SSE transport
    const sse = createSseServer()
    const url = await sse.start()
    let transport: Transport | undefined

    try {
      transport = await connectToRemoteServer(null, url, undefined as unknown as OAuthClientProvider, {}, noAuth, 'sse-only')
      const reconnected = vi.fn()
      ;(transport as any).onStreamReconnect = reconnected

      // When the server drops the stream and the EventSource opens another
      sse.dropStream()

      // Then it is reported. The SDK raises no event for this, so it is inferred from the
      // stream being opened a second time - which is the whole basis of the recovery in
      // mcpProxy, and the reason issue #269 went unnoticed at this layer.
      await vi.waitFor(() => expect(reconnected).toHaveBeenCalled(), { timeout: 5_000 })
      expect(sse.streamsServed).toBeGreaterThan(1)
    } finally {
      await transport?.close()
      await sse.stop()
    }
  }, 15_000)

  it('Scenario: A cookie set on the stream rides the POSTs that follow it', async () => {
    // Given a balancer that pins the stream to a node, while the POSTs go out separately
    const sse = createSseServer()
    const url = await sse.start()
    let transport: Transport | undefined

    try {
      transport = await connectToRemoteServer(null, url, undefined as unknown as OAuthClientProvider, {}, noAuth, 'sse-only')
      await transport.send({ jsonrpc: '2.0', method: 'notifications/initialized' })

      // Then the POST reaches the node holding the session, rather than whichever one the
      // balancer picks next (issue #168)
      expect(sse.postCookies).toEqual(['AWSALB=node-1'])
    } finally {
      await transport?.close()
      await sse.stop()
    }
  }, 15_000)

  it('Scenario: The first connection is not a reconnection', async () => {
    const sse = createSseServer()
    const url = await sse.start()
    let transport: Transport | undefined

    try {
      const reconnected = vi.fn()
      transport = await connectToRemoteServer(null, url, undefined as unknown as OAuthClientProvider, {}, noAuth, 'sse-only')
      ;(transport as any).onStreamReconnect = reconnected

      // Then nothing is announced for the stream we asked for ourselves
      await sleep(100)
      expect(reconnected).not.toHaveBeenCalled()
      expect(sse.streamsServed).toBe(1)
    } finally {
      await transport?.close()
      await sse.stop()
    }
  }, 15_000)
})

describe('Feature: Encoding MCP header values', () => {
  it('Scenario: Plain ASCII values are sent as-is', () => {
    expect(encodeMcpHeaderValue('get_weather')).toBe('get_weather')
    expect(encodeMcpHeaderValue('file:///projects/myapp/config.json')).toBe('file:///projects/myapp/config.json')
  })

  it('Scenario: Values RFC 9110 cannot carry are Base64 encoded', () => {
    // Non-ASCII
    expect(encodeMcpHeaderValue('Hello, 世界')).toBe('=?base64?SGVsbG8sIOS4lueVjA==?=')
    // Leading/trailing whitespace
    expect(encodeMcpHeaderValue(' padded ')).toBe('=?base64?IHBhZGRlZCA=?=')
    // Embedded newline - the header-injection case
    expect(encodeMcpHeaderValue('line1\nline2')).toBe('=?base64?bGluZTEKbGluZTI=?=')
  })

  it('Scenario: A literal that looks like the sentinel is itself encoded', () => {
    // Otherwise a server would decode a value that was never encoded
    expect(encodeMcpHeaderValue('=?base64?literal?=')).toBe('=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=')
  })

  it('Scenario: Encoded values round-trip back to the body value', () => {
    for (const original of ['Hello, 世界', ' padded ', 'line1\nline2', '=?base64?literal?=']) {
      const encoded = encodeMcpHeaderValue(original)
      const decoded = Buffer.from(encoded.slice('=?base64?'.length, -'?='.length), 'base64').toString('utf8')
      expect(decoded).toBe(original)
    }
  })
})

describe('Feature: Tool Filtering with Ignore Patterns', () => {
  it('Scenario: Single wildcard pattern ignores matching tools', () => {
    // Given ignore patterns with create* wildcard
    const ignorePatterns = ['create*']

    // When checking if createTask should be included
    const result1 = shouldIncludeTool(ignorePatterns, 'createTask')
    // Then it should be excluded (return false)
    expect(result1).toBe(false)

    // When checking if getTask should be included
    const result2 = shouldIncludeTool(ignorePatterns, 'getTask')
    // Then it should be included (return true)
    expect(result2).toBe(true)
  })

  it('Scenario: Multiple wildcard patterns ignore matching tools', () => {
    // Given ignore patterns with create* and put* wildcards
    const ignorePatterns = ['create*', 'put*']

    // When checking if createTask should be included
    const result1 = shouldIncludeTool(ignorePatterns, 'createTask')
    // Then it should be excluded (return false)
    expect(result1).toBe(false)

    // When checking if infoTask should be included
    const result2 = shouldIncludeTool(ignorePatterns, 'infoTask')
    // Then it should be included (return true)
    expect(result2).toBe(true)
  })

  it('Scenario: Suffix wildcard pattern ignores matching tools', () => {
    // Given ignore patterns with *account suffix wildcard
    const ignorePatterns = ['*account']

    // When checking various account-related tools
    const result1 = shouldIncludeTool(ignorePatterns, 'getAccount')
    const result2 = shouldIncludeTool(ignorePatterns, 'putAccount')
    const result3 = shouldIncludeTool(ignorePatterns, 'account')

    // Then all should be excluded (return false)
    expect(result1).toBe(false)
    expect(result2).toBe(false)
    expect(result3).toBe(false)
  })

  it('Scenario: Empty ignore patterns include all tools', () => {
    // Given empty ignore patterns
    const ignorePatterns: string[] = []

    // When checking any tool
    const result = shouldIncludeTool(ignorePatterns, 'anyTool')

    // Then it should be included (return true)
    expect(result).toBe(true)
  })

  it('Scenario: Non-matching patterns include tools', () => {
    // Given ignore patterns that don't match the tool
    const ignorePatterns = ['delete*', 'remove*']

    // When checking a tool that doesn't match any pattern
    const result = shouldIncludeTool(ignorePatterns, 'createTask')

    // Then it should be included (return true)
    expect(result).toBe(true)
  })

  it('Scenario: Exact match without wildcards', () => {
    // Given ignore patterns with exact tool names
    const ignorePatterns = ['exactTool', 'anotherTool']

    // When checking the exact tool name
    const result1 = shouldIncludeTool(ignorePatterns, 'exactTool')
    // Then it should be excluded (return false)
    expect(result1).toBe(false)

    // When checking a different tool name
    const result2 = shouldIncludeTool(ignorePatterns, 'differentTool')
    // Then it should be included (return true)
    expect(result2).toBe(true)
  })
})

describe('Feature: MCP Proxy', () => {
  const mockTransport = () =>
    ({
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    }) as unknown as Transport

  it('Scenario: Proxy initialize message from client to server', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when client sends an initialize message
    const initializeMessage = {
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: {
        clientInfo: {
          name: 'Test Client',
          version: '1.0.0',
        },
      },
    }

    // Simulate client sending a message by calling the message handler directly
    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(initializeMessage)
    }

    // Then the message should be forwarded to the server
    expect(mockTransportToServer.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        method: 'initialize',
        id: '1',
        params: expect.objectContaining({
          clientInfo: expect.objectContaining({
            name: expect.stringContaining('Test Client'),
            version: '1.0.0',
          }),
        }),
      }),
    )
  })

  it('Scenario: Negotiated protocol version is set on the remote transport', async () => {
    // Given mock transports where the remote one records the negotiated version
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const setProtocolVersion = vi.fn()
    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      setProtocolVersion,
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client initializes and the server answers with a protocol version
    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)

    mockTransportToServer.onmessage?.({
      jsonrpc: '2.0' as const,
      id: '1',
      result: { protocolVersion: '2025-11-25', capabilities: {}, serverInfo: { name: 'Test Server', version: '1.0.0' } },
    } as any)

    // Then the remote transport is told which version was negotiated, so later
    // requests carry the MCP-Protocol-Version header
    expect(setProtocolVersion).toHaveBeenCalledWith('2025-11-25')
  })

  it('Scenario: A later response carrying a protocolVersion does not change the negotiated version', async () => {
    // Given a proxy that has already completed the initialize handshake
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const setProtocolVersion = vi.fn()
    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      setProtocolVersion,
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)
    mockTransportToServer.onmessage?.({
      jsonrpc: '2.0' as const,
      id: '1',
      result: { protocolVersion: '2025-11-25' },
    } as any)
    setProtocolVersion.mockClear()

    // When an unrelated tool result happens to carry a protocolVersion field
    mockTransportToServer.onmessage?.({
      jsonrpc: '2.0' as const,
      id: '2',
      result: { protocolVersion: 'not-a-negotiated-version' },
    } as any)

    // Then it is ignored
    expect(setProtocolVersion).not.toHaveBeenCalled()
  })

  it('Scenario: Proxy server response back to client', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // First simulate client sending a request (so there's a pending request)
    const clientRequest = {
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: {
        clientInfo: {
          name: 'Test Client',
          version: '1.0.0',
        },
      },
    }

    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(clientRequest)
    }

    // Clear the previous call
    vi.clearAllMocks()

    // Now simulate server sending a response message
    const serverResponse = {
      jsonrpc: '2.0' as const,
      id: '1',
      result: {
        capabilities: {
          tools: {
            listChanged: true,
          },
        },
        serverInfo: {
          name: 'Atlassian MCP',
          version: '1.0.0',
        },
      },
    }

    // Simulate server sending a response by calling the message handler directly
    if (mockTransportToServer.onmessage) {
      mockTransportToServer.onmessage(serverResponse)
    }

    // Then the response should be forwarded to the client
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: '1',
        result: {
          capabilities: {
            tools: {
              listChanged: true,
            },
          },
          serverInfo: {
            name: 'Atlassian MCP',
            version: '1.0.0',
          },
        },
      }),
    )
  })

  it('Scenario: Close server transport when client transport closes', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when client transport closes
    if (mockTransportToClient.onclose) {
      mockTransportToClient.onclose()
    }

    // Then server transport should also be closed
    expect(mockTransportToServer.close).toHaveBeenCalled()
  })

  it('Scenario: Close client transport when server transport closes', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when server transport closes
    if (mockTransportToServer.onclose) {
      mockTransportToServer.onclose()
    }

    // Then client transport should also be closed
    expect(mockTransportToClient.close).toHaveBeenCalled()
  })

  it('Scenario: Filter tools in tools/list response when ignoredTools is configured', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy with ignored tools
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*', 'remove*'],
    })

    // First simulate client sending a tools/list request
    const toolsListRequest = {
      jsonrpc: '2.0' as const,
      method: 'tools/list',
      id: '2',
      params: {},
    }

    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(toolsListRequest)
    }

    // Clear the previous call
    vi.clearAllMocks()

    // Now simulate server sending a tools/list response with various tools
    const serverToolsResponse = {
      jsonrpc: '2.0' as const,
      id: '2',
      result: {
        tools: [
          { name: 'createTask', description: 'Create a new task' },
          { name: 'deleteTask', description: 'Delete a task' },
          { name: 'updateTask', description: 'Update a task' },
          { name: 'removeUser', description: 'Remove a user' },
          { name: 'listTasks', description: 'List all tasks' },
        ],
      },
    }

    // Simulate server sending a response
    if (mockTransportToServer.onmessage) {
      mockTransportToServer.onmessage(serverToolsResponse)
    }

    // Then the response should be forwarded to the client with filtered tools
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: '2',
        result: {
          tools: [
            { name: 'createTask', description: 'Create a new task' },
            { name: 'updateTask', description: 'Update a task' },
            { name: 'listTasks', description: 'List all tasks' },
          ],
        },
      }),
    )
  })

  it('Scenario: Forward an error response to tools/list instead of dropping it', async () => {
    // Given a proxy between mock transports
    const mockTransportToClient = mockTransport()
    const mockTransportToServer = mockTransport()

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*'],
    })

    // And a tools/list request from the client
    mockTransportToClient.onmessage!({ jsonrpc: '2.0', id: 2, method: 'tools/list' } as any)

    // When the server answers it with a JSON-RPC error rather than a result
    mockTransportToServer.onmessage!({
      jsonrpc: '2.0',
      id: 2,
      error: { code: -32600, message: 'Session not initialized' },
    } as any)

    // Then the error reaches the client, rather than the request going unanswered
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 2,
        error: { code: -32600, message: 'Session not initialized' },
      }),
    )
  })

  it('Scenario: Forward a tools/list result that carries no tools', async () => {
    // Given a proxy between mock transports
    const mockTransportToClient = mockTransport()
    const mockTransportToServer = mockTransport()

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*'],
    })

    // And a tools/list request from the client
    mockTransportToClient.onmessage!({ jsonrpc: '2.0', id: 3, method: 'tools/list' } as any)

    // When the server answers with a result that omits the tools array
    mockTransportToServer.onmessage!({ jsonrpc: '2.0', id: 3, result: {} } as any)

    // Then the result is forwarded untouched
    expect(mockTransportToClient.send).toHaveBeenCalledWith(expect.objectContaining({ id: 3, result: {} }))
  })

  it('Scenario: A server-initiated request does not consume a pending request with the same id', async () => {
    // Given a proxy between mock transports
    const mockTransportToClient = mockTransport()
    const mockTransportToServer = mockTransport()

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*'],
    })

    // And an in-flight tools/list request from the client
    mockTransportToClient.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/list' } as any)

    // When the server sends a request of its own that happens to reuse id 1, the two directions
    // numbering their requests independently
    mockTransportToServer.onmessage!({ jsonrpc: '2.0', id: 1, method: 'ping' } as any)

    // Then the ping reaches the client untouched
    expect(mockTransportToClient.send).toHaveBeenCalledWith(expect.objectContaining({ id: 1, method: 'ping' }))

    // And the client's request is still pending, so its real answer is filtered as configured
    mockTransportToServer.onmessage!({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'deleteTask' }, { name: 'listTasks' }] },
    } as any)

    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 1,
        result: { tools: [{ name: 'listTasks' }] },
      }),
    )
  })

  it('Scenario: Requests wait for the initialized notification to be delivered', async () => {
    // Given a server that takes a moment to accept the initialized notification
    const mockTransportToClient = mockTransport()
    const sent: string[] = []
    let releaseInitialized: () => void = () => {}
    const mockTransportToServer = {
      ...mockTransport(),
      send: vi.fn().mockImplementation(async (message: any) => {
        if (message.method === 'notifications/initialized') {
          await new Promise<void>((resolve) => {
            releaseInitialized = resolve
          })
        }
        sent.push(message.method ?? String(message.id))
      }),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client sends the notification and its first requests back to back
    mockTransportToClient.onmessage!({ jsonrpc: '2.0', method: 'notifications/initialized' } as any)
    mockTransportToClient.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/list' } as any)
    mockTransportToClient.onmessage!({ jsonrpc: '2.0', id: 2, method: 'resources/list' } as any)
    await new Promise((resolve) => setTimeout(resolve, 10))

    // Then neither request has been sent yet
    expect(sent).toEqual([])

    // And once the notification lands, they follow in the order the client sent them
    releaseInitialized()
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(sent).toEqual(['notifications/initialized', 'tools/list', 'resources/list'])
  })

  it('Scenario: Block tools/call for ignored tools with delete* filter', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy with delete* filter
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*'],
    })

    // And when client tries to call a deleteTask tool
    const toolsCallMessage = {
      jsonrpc: '2.0' as const,
      method: 'tools/call',
      id: '3',
      params: {
        name: 'deleteTask',
        arguments: {
          taskId: '1',
        },
        _meta: {
          progressToken: 1,
        },
      },
    }

    // Simulate client sending the tools/call message
    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(toolsCallMessage)
    }

    // Then the call should NOT be forwarded to the server
    expect(mockTransportToServer.send).not.toHaveBeenCalled()

    // And an error response should be sent back to the client
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: '3',
        error: expect.objectContaining({
          code: expect.any(Number),
          message: expect.stringContaining('Tool "deleteTask" is not available'),
        }),
      }),
    )
  })

  it('Scenario: Handle server-initiated requests (without corresponding client request)', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when server sends a ping message (server-initiated, no corresponding client request)
    const serverPingMessage = {
      jsonrpc: '2.0' as const,
      method: 'ping',
      id: 'server-ping-1',
    }

    // Simulate server sending the message
    if (mockTransportToServer.onmessage) {
      mockTransportToServer.onmessage(serverPingMessage)
    }

    // Then the message should be forwarded to the client without errors
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        method: 'ping',
        id: 'server-ping-1',
      }),
    )
  })

  it('Scenario: Handle server-initiated response messages without corresponding request', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when server sends a response with an ID that has no corresponding request
    const orphanedResponse = {
      jsonrpc: '2.0' as const,
      id: 'unknown-request-id',
      result: {},
    }

    // Simulate server sending a response without a matching request
    if (mockTransportToServer.onmessage) {
      mockTransportToServer.onmessage(orphanedResponse)
    }

    // Then the response should still be forwarded to the client
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: 'unknown-request-id',
        result: {},
      }),
    )
  })

  it('Scenario: Re-establish the session when the server has expired it', async () => {
    // Given a client transport
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // And a server transport that 404s the first tools/call, as a server does
    // once it has dropped the session, then answers the fresh handshake
    const sent: any[] = []
    let expireNextCall = true
    const mockTransportToServer = {
      send: vi.fn(async (message: any) => {
        sent.push(message)
        if (typeof message.id === 'string' && message.id.startsWith('mcp-remote-reinit-')) {
          setTimeout(
            () =>
              (mockTransportToServer as any).onmessage?.({
                jsonrpc: '2.0',
                id: message.id,
                result: { protocolVersion: '2025-11-25' },
              }),
            0,
          )
          return
        }
        if (expireNextCall && message.method === 'tools/call') {
          expireNextCall = false
          throw new SdkHttpError(SdkErrorCode.ClientHttpNotImplemented, 'Error POSTing to endpoint: Session terminated', { status: 404 })
        }
      }),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
      setProtocolVersion: vi.fn(),
      sessionId: 'session-2',
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client initializes and then calls a tool
    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)
    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'tools/call',
      id: '2',
      params: { name: 'ping', arguments: {} },
    } as any)

    await vi.waitFor(() => expect(sent.map((m) => m.method)).toContain('notifications/initialized'))

    // Then a fresh initialize was sent, carrying the client's own parameters
    const reinitialize = sent.find((m) => typeof m.id === 'string' && m.id.startsWith('mcp-remote-reinit-'))
    expect(reinitialize).toBeDefined()
    expect(reinitialize.method).toBe('initialize')
    expect(reinitialize.params.clientInfo.name).toContain('Test Client')

    // And the version the new session negotiated is what later requests announce
    expect((mockTransportToServer as any).setProtocolVersion).toHaveBeenCalledWith('2025-11-25')

    // And the call that triggered it was retried on the new session
    expect(sent.filter((m) => m.method === 'tools/call' && m.id === '2')).toHaveLength(2)

    // And the handshake response was consumed by the proxy, never shown to the client
    expect(mockTransportToClient.send).not.toHaveBeenCalledWith(expect.objectContaining({ id: reinitialize.id }))
  })

  it('Scenario: Concurrent requests hitting a dead session share one new session', async () => {
    // Given a client transport
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // And a server that 404s every tools/call until the session is re-established
    const sent: any[] = []
    let sessionAlive = false
    const mockTransportToServer = {
      send: vi.fn(async (message: any) => {
        sent.push(message)
        if (typeof message.id === 'string' && message.id.startsWith('mcp-remote-reinit-')) {
          // Answer on a later tick, so a second caller can arrive while this is in flight
          setTimeout(() => {
            sessionAlive = true
            ;(mockTransportToServer as any).onmessage?.({ jsonrpc: '2.0', id: message.id, result: {} })
          }, 5)
          return
        }
        if (!sessionAlive && message.method === 'tools/call') {
          throw new SdkHttpError(SdkErrorCode.ClientHttpNotImplemented, 'Error POSTing to endpoint: Session terminated', { status: 404 })
        }
      }),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
      sessionId: 'expired-session',
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)

    // When two requests are in flight when the session dies
    mockTransportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '2', params: { name: 'a' } } as any)
    mockTransportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '3', params: { name: 'b' } } as any)

    await vi.waitFor(() => expect(sent.filter((m) => m.method === 'tools/call')).toHaveLength(4))

    // Then they share a single handshake instead of opening a session each. Racing
    // handshakes would also blank the session id under a retry already in flight,
    // and a server that requires one answers that with 400.
    const handshakes = sent.filter((m) => typeof m.id === 'string' && m.id.startsWith('mcp-remote-reinit-'))
    expect(handshakes).toHaveLength(1)
    expect(sent.filter((m) => m.method === 'notifications/initialized')).toHaveLength(1)

    // And both requests were retried on it
    expect(sent.filter((m) => m.method === 'tools/call' && m.params.name === 'a')).toHaveLength(2)
    expect(sent.filter((m) => m.method === 'tools/call' && m.params.name === 'b')).toHaveLength(2)
  })

  it('Scenario: A 404 without a session id is not treated as an expired session', async () => {
    // Given a client transport
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // And a stateless server that never issued a session id, 404ing a bad endpoint
    const sent: any[] = []
    const mockTransportToServer = {
      send: vi.fn(async (message: any) => {
        sent.push(message)
        if (message.method === 'tools/call') {
          throw new SdkHttpError(SdkErrorCode.ClientHttpNotImplemented, 'Error POSTing to endpoint: Not Found', { status: 404 })
        }
      }),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
      sessionId: undefined,
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)
    mockTransportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '2', params: { name: 'ping' } } as any)

    // Then the failure goes straight back to the client, with no pointless handshake
    await vi.waitFor(() => expect(mockTransportToClient.send).toHaveBeenCalledWith(expect.objectContaining({ id: '2' })))
    expect(sent.filter((m) => typeof m.id === 'string' && m.id.startsWith('mcp-remote-reinit-'))).toHaveLength(0)
    expect(sent.filter((m) => m.method === 'tools/call')).toHaveLength(1)
  })
  describe('Feature: A reconnected SSE stream', () => {
    const OLD_ENDPOINT = 'http://server.example/messages/?session_id=old'
    const NEW_ENDPOINT = 'http://server.example/messages/?session_id=new'

    /**
     * An SSE transport: no session id of its own, a private `_endpoint` that moves when the
     * stream comes back, and a server that answers a handshake but refuses anything sent
     * against a session that never had one.
     */
    const sseServerTransport = (sent: any[]) => {
      const transport = {
        send: vi.fn(async (message: any) => {
          sent.push({ ...message, sentTo: transport._endpoint.href })
          if (typeof message.id === 'string' && message.id.startsWith('mcp-remote-reinit-')) {
            setTimeout(() => transport.onmessage?.({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: '2025-11-25' } }), 0)
          }
        }),
        close: vi.fn().mockResolvedValue(undefined),
        start: vi.fn().mockResolvedValue(undefined),
        setProtocolVersion: vi.fn(),
        onmessage: vi.fn(),
        onclose: vi.fn(),
        onerror: vi.fn(),
        _endpoint: new URL(OLD_ENDPOINT),
      } as any
      return transport
    }

    const clientTransport = () =>
      ({
        send: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockResolvedValue(undefined),
        start: vi.fn().mockResolvedValue(undefined),
        onmessage: vi.fn(),
        onclose: vi.fn(),
        onerror: vi.fn(),
      }) as unknown as Transport

    it('Scenario: Hand the new session the handshake the old one had', async () => {
      // Given a proxy that has completed the lifecycle against one session
      const sent: any[] = []
      const transportToClient = clientTransport()
      const transportToServer = sseServerTransport(sent)
      mcpProxy({ transportToClient, transportToServer, ignoredTools: [] })

      transportToClient.onmessage?.({
        jsonrpc: '2.0' as const,
        method: 'initialize',
        id: '1',
        params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
      } as any)
      await vi.waitFor(() => expect(sent).toHaveLength(1))

      // When the stream drops and comes back on a session the server has just created
      transportToServer.onStreamReconnect()
      setTimeout(() => (transportToServer._endpoint = new URL(NEW_ENDPOINT)), 10)

      // Then the lifecycle is replayed against it, unprompted, carrying the client's own
      // parameters - rather than waiting for a request to be refused (issue #269)
      await vi.waitFor(() => expect(sent.map((m) => m.method)).toContain('notifications/initialized'))
      const handshake = sent.find((m) => typeof m.id === 'string' && m.id.startsWith('mcp-remote-reinit-'))
      expect(handshake.method).toBe('initialize')
      expect(handshake.params.clientInfo.name).toContain('Test Client')

      // And it went to the new session, not the one that went away
      expect(handshake.sentTo).toBe(NEW_ENDPOINT)

      // And the client never saw any of it
      expect(transportToClient.send).not.toHaveBeenCalledWith(expect.objectContaining({ id: handshake.id }))
    })

    it('Scenario: Hold a request that arrives mid-handshake', async () => {
      const sent: any[] = []
      const transportToClient = clientTransport()
      const transportToServer = sseServerTransport(sent)
      mcpProxy({ transportToClient, transportToServer, ignoredTools: [] })

      transportToClient.onmessage?.({
        jsonrpc: '2.0' as const,
        method: 'initialize',
        id: '1',
        params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
      } as any)
      await vi.waitFor(() => expect(sent).toHaveLength(1))

      // When a tool call is made while the stream is still coming back
      transportToServer.onStreamReconnect()
      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '2', params: { name: 'ping' } } as any)
      setTimeout(() => (transportToServer._endpoint = new URL(NEW_ENDPOINT)), 10)

      // Then it waits for the handshake rather than racing it onto the dead session
      await vi.waitFor(() => expect(sent.some((m) => m.method === 'tools/call')).toBe(true))
      const call = sent.find((m) => m.method === 'tools/call')
      expect(call.sentTo).toBe(NEW_ENDPOINT)
      expect(sent.indexOf(call)).toBeGreaterThan(sent.findIndex((m) => m.method === 'notifications/initialized'))
    })

    it('Scenario: Re-handshake once, however many requests are waiting', async () => {
      const sent: any[] = []
      const transportToClient = clientTransport()
      const transportToServer = sseServerTransport(sent)
      mcpProxy({ transportToClient, transportToServer, ignoredTools: [] })

      transportToClient.onmessage?.({
        jsonrpc: '2.0' as const,
        method: 'initialize',
        id: '1',
        params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
      } as any)
      await vi.waitFor(() => expect(sent).toHaveLength(1))

      transportToServer.onStreamReconnect()
      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '2', params: { name: 'a' } } as any)
      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '3', params: { name: 'b' } } as any)
      setTimeout(() => (transportToServer._endpoint = new URL(NEW_ENDPOINT)), 10)

      await vi.waitFor(() => expect(sent.filter((m) => m.method === 'tools/call')).toHaveLength(2))
      expect(sent.filter((m) => typeof m.id === 'string' && m.id.startsWith('mcp-remote-reinit-'))).toHaveLength(1)
      expect(sent.filter((m) => m.method === 'notifications/initialized')).toHaveLength(1)
    })

    it('Scenario: Answer requests the vanished session can no longer answer', async () => {
      // Given a request the server accepted and never answered, because the stream carrying its
      // answer went away
      const sent: any[] = []
      const transportToClient = clientTransport()
      const transportToServer = sseServerTransport(sent)
      mcpProxy({ transportToClient, transportToServer, ignoredTools: [] })

      transportToClient.onmessage?.({
        jsonrpc: '2.0' as const,
        method: 'initialize',
        id: '1',
        params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
      } as any)
      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '2', params: { name: 'ping' } } as any)
      await vi.waitFor(() => expect(sent.some((m) => m.method === 'tools/call')).toBe(true))

      // When the stream comes back on a new session
      transportToServer.onStreamReconnect()
      setTimeout(() => (transportToServer._endpoint = new URL(NEW_ENDPOINT)), 10)

      // Then the client is told, rather than holding the request open for the life of the process
      await vi.waitFor(() =>
        expect(transportToClient.send).toHaveBeenCalledWith(
          expect.objectContaining({ id: '2', error: expect.objectContaining({ code: -32001 }) }),
        ),
      )
    })

    it('Scenario: Leave answered requests, and requests still queued, alone', async () => {
      const sent: any[] = []
      const transportToClient = clientTransport()
      const transportToServer = sseServerTransport(sent)
      mcpProxy({ transportToClient, transportToServer, ignoredTools: [] })

      transportToClient.onmessage?.({
        jsonrpc: '2.0' as const,
        method: 'initialize',
        id: '1',
        params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
      } as any)
      await vi.waitFor(() => expect(sent).toHaveLength(1))
      transportToServer.onmessage?.({ jsonrpc: '2.0', id: '1', result: { protocolVersion: '2025-11-25' } } as any)

      // Given one request already answered
      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '2', params: { name: 'done' } } as any)
      await vi.waitFor(() => expect(sent.some((m) => m.id === '2')).toBe(true))
      transportToServer.onmessage?.({ jsonrpc: '2.0', id: '2', result: {} } as any)

      // And one arriving while the stream is still coming back, so it was never sent
      transportToServer.onStreamReconnect()
      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '3', params: { name: 'queued' } } as any)
      setTimeout(() => (transportToServer._endpoint = new URL(NEW_ENDPOINT)), 10)

      // Then neither is failed: one is settled, and the other is waiting to go to the new session
      await vi.waitFor(() => expect(sent.some((m) => m.id === '3' && m.sentTo === NEW_ENDPOINT)).toBe(true))
      expect(transportToClient.send).not.toHaveBeenCalledWith(expect.objectContaining({ error: expect.anything() }))
    })

    it('Scenario: Leave a stream that has never dropped alone', async () => {
      // Given a proxy nobody has told about a reconnect
      const sent: any[] = []
      const transportToClient = clientTransport()
      const transportToServer = sseServerTransport(sent)
      mcpProxy({ transportToClient, transportToServer, ignoredTools: [] })

      transportToClient.onmessage?.({
        jsonrpc: '2.0' as const,
        method: 'initialize',
        id: '1',
        params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
      } as any)
      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '2', params: { name: 'ping' } } as any)

      await vi.waitFor(() => expect(sent.filter((m) => m.method === 'tools/call')).toHaveLength(1))
      expect(sent.filter((m) => typeof m.id === 'string' && m.id.startsWith('mcp-remote-reinit-'))).toHaveLength(0)
    })
  })

  describe('Feature: A token the server refuses after issuing it', () => {
    const clientTransport = () =>
      ({
        send: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockResolvedValue(undefined),
        start: vi.fn().mockResolvedValue(undefined),
        onmessage: vi.fn(),
        onclose: vi.fn(),
        onerror: vi.fn(),
      }) as unknown as Transport

    /** The SDK's own circuit breaker: it refuses to authorize again once it already has. */
    const rejectedAfterAuthorizing = () =>
      new SdkHttpError(SdkErrorCode.ClientHttpAuthentication, 'Server returned 401 after re-authentication', { status: 401 })

    it('Scenario: Discard it and retry, rather than presenting it again', async () => {
      // Given a server that refuses the token it just issued, until it is thrown away
      const sent: any[] = []
      let credentialIsDead = true
      const transportToClient = clientTransport()
      const transportToServer = {
        send: vi.fn(async (message: any) => {
          sent.push(message)
          if (credentialIsDead) throw rejectedAfterAuthorizing()
        }),
        close: vi.fn().mockResolvedValue(undefined),
        start: vi.fn().mockResolvedValue(undefined),
        onmessage: vi.fn(),
        onclose: vi.fn(),
        onerror: vi.fn(),
      } as unknown as Transport

      const forgetRejectedAuthorization = vi.fn(async () => {
        credentialIsDead = false
      })

      mcpProxy({ transportToClient, transportToServer, ignoredTools: [], forgetRejectedAuthorization })

      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '1', params: { name: 'ping' } } as any)

      // Then the dead credential is dropped and the request goes again, instead of the client
      // being handed an error it can do nothing about
      await vi.waitFor(() => expect(sent).toHaveLength(2))
      expect(forgetRejectedAuthorization).toHaveBeenCalledTimes(1)
      expect(transportToClient.send).not.toHaveBeenCalled()
    })

    it('Scenario: Give up after one discard rather than churning credentials', async () => {
      // Given a server that refuses every token, however fresh
      const sent: any[] = []
      const transportToClient = clientTransport()
      const transportToServer = {
        send: vi.fn(async (message: any) => {
          sent.push(message)
          throw rejectedAfterAuthorizing()
        }),
        close: vi.fn().mockResolvedValue(undefined),
        start: vi.fn().mockResolvedValue(undefined),
        onmessage: vi.fn(),
        onclose: vi.fn(),
        onerror: vi.fn(),
      } as unknown as Transport

      const forgetRejectedAuthorization = vi.fn().mockResolvedValue(undefined)
      mcpProxy({ transportToClient, transportToServer, ignoredTools: [], forgetRejectedAuthorization })

      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '1', params: { name: 'ping' } } as any)

      // Then the client is told, once, and no third token is asked for
      await vi.waitFor(() => expect(transportToClient.send).toHaveBeenCalledWith(expect.objectContaining({ id: '1' })))
      expect(forgetRejectedAuthorization).toHaveBeenCalledTimes(1)
      expect(sent).toHaveLength(2)
    })

    it('Scenario: An ordinary 401 is left to the SDK', async () => {
      // Given a challenge the SDK has not already tried to authorize past
      const transportToClient = clientTransport()
      const transportToServer = {
        send: vi.fn().mockRejectedValue(new UnauthorizedError()),
        close: vi.fn().mockResolvedValue(undefined),
        start: vi.fn().mockResolvedValue(undefined),
        onmessage: vi.fn(),
        onclose: vi.fn(),
        onerror: vi.fn(),
      } as unknown as Transport

      const forgetRejectedAuthorization = vi.fn().mockResolvedValue(undefined)
      const reauthorize = vi.fn().mockResolvedValue(undefined)
      mcpProxy({ transportToClient, transportToServer, ignoredTools: [], forgetRejectedAuthorization, reauthorize })

      transportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '1', params: { name: 'ping' } } as any)

      // Then a sign-in is what answers it, and no credential is thrown away
      await vi.waitFor(() => expect(reauthorize).toHaveBeenCalled())
      expect(forgetRejectedAuthorization).not.toHaveBeenCalled()
    })
  })

  it('Scenario: Answer the client when a request cannot be delivered', async () => {
    // Given a server transport that fails for a reason a new session cannot fix
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockRejectedValue(new Error('connection reset')),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client sends a request
    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'tools/call',
      id: '7',
      params: { name: 'ping', arguments: {} },
    } as any)

    // Then it gets an error rather than waiting forever for a reply
    await vi.waitFor(() =>
      expect(mockTransportToClient.send).toHaveBeenCalledWith(
        expect.objectContaining({
          jsonrpc: '2.0',
          id: '7',
          error: expect.objectContaining({ code: -32001 }),
        }),
      ),
    )
  })

  it('Scenario: Failed forward of a notification does not produce a response', async () => {
    // Given a server transport whose send() rejects
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockRejectedValue(new Error('Error POSTing to endpoint (HTTP 404): Session not found')),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client sends a notification (no id)
    const clientNotification = {
      jsonrpc: '2.0' as const,
      method: 'notifications/initialized',
    }
    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(clientNotification)
    }

    // Then no response is sent back — JSON-RPC forbids replies to notifications
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(mockTransportToClient.send).not.toHaveBeenCalled()
  })

  it('Scenario: Failed forward of a client response does not produce a response', async () => {
    // Given a server transport whose send() rejects
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockRejectedValue(new Error('Error POSTing to endpoint (HTTP 404): Session not found')),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client answers a server-initiated request (an id, but no method)
    const clientResponse = {
      jsonrpc: '2.0' as const,
      id: 7,
      result: {},
    }
    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(clientResponse)
    }

    // Then no error response is sent back. Answering a response would make the
    // local SDK raise "Received a response for an unknown message ID"
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(mockTransportToClient.send).not.toHaveBeenCalled()
  })
})

describe('setupOAuthCallbackServerWithLongPoll', () => {
  let server: any
  let events: EventEmitter

  beforeEach(() => {
    events = new EventEmitter()
  })

  afterEach(() => {
    if (server) {
      server.close()
      server = null
    }
  })

  it('should use custom timeout when authTimeoutMs is provided', async () => {
    const customTimeout = 5000
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0, // Use any available port
      path: '/oauth/callback',
      events,
      authTimeoutMs: customTimeout,
      serverUrlHash: 'test-hash',
    })

    server = result.server

    // Test that the server was created
    expect(server).toBeDefined()
    expect(typeof result.waitForAuthCode).toBe('function')
  })

  it('should use default timeout when authTimeoutMs is not provided', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0, // Use any available port
      path: '/oauth/callback',
      events,
      serverUrlHash: 'test-hash',
    })

    server = result.server

    // Test that the server was created with defaults
    expect(server).toBeDefined()
    expect(typeof result.waitForAuthCode).toBe('function')
  })

  it('should return actualPort matching the bound port on success', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/oauth/callback',
      events,
      serverUrlHash: 'test-hash',
    })

    server = result.server
    const boundPort = (server.address() as net.AddressInfo).port
    expect(result.actualPort).toBe(boundPort)
    expect(result.actualPort).toBeGreaterThan(0)
  })

  it('surfaces EADDRINUSE instead of moving to a random port', async () => {
    // The deterministic port is what lets concurrent instances agree on one owner. An instance
    // that quietly moved elsewhere would advertise a redirect_uri no browser can deliver a code
    // to, so a taken port has to be reported rather than worked around.
    const blocker = net.createServer()
    const blockedPort = await new Promise<number>((resolve) => {
      blocker.listen(0, '127.0.0.1', () => resolve((blocker.address() as net.AddressInfo).port))
    })

    try {
      await expect(
        setupOAuthCallbackServerWithLongPoll({
          port: blockedPort,
          path: '/oauth/callback',
          events,
          serverUrlHash: 'test-hash',
        }),
      ).rejects.toMatchObject({ code: 'EADDRINUSE', requestedPort: blockedPort })
    } finally {
      await new Promise<void>((resolve) => blocker.close(() => resolve()))
    }
  })

  it('reports a denied authorization instead of waiting for a code that is not coming', async () => {
    // ?error= is how "the user clicked Deny", an org policy block or invalid_scope arrives. Waiting
    // for a code holds the callback port for the life of the process and tells the user nothing.
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/oauth/callback',
      events,
      serverUrlHash: 'test-hash',
    })
    server = result.server
    // A handler is attached synchronously: the callback arrives during the await below, and a
    // rejection with nothing attached yet is reported as unhandled even though it is asserted on
    const settled = result.waitForAuthCode().then(
      () => new Error('expected no authorization code'),
      (error: Error) => error,
    )

    const response = await fetch(`http://127.0.0.1:${result.actualPort}/oauth/callback?error=access_denied&error_description=User%20denied`)

    expect(response.status).toBe(400)
    await expect(response.text()).resolves.toContain('User denied')
    expect((await settled).message).toMatch(/access_denied/)
  })

  it('answers an identity probe, so a losing instance can tell a sibling from a stranger', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/oauth/callback',
      events,
      serverUrlHash: 'a-particular-server',
    })
    server = result.server

    const response = await fetch(`http://127.0.0.1:${result.actualPort}/.mcp-remote/id`)

    await expect(response.json()).resolves.toEqual({ mcpRemote: true, serverUrlHash: 'a-particular-server' })
  })

  it('should serve the callback on the configured path', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/custom/callback',
      events,
      serverUrlHash: 'test-hash',
    })

    server = result.server

    const response = await fetch(`http://127.0.0.1:${result.actualPort}/custom/callback?code=test-code`)
    expect(response.status).toBe(200)
    await expect(result.waitForAuthCode()).resolves.toEqual({ code: 'test-code', state: undefined })

    // The default path must not be served when it was overridden, otherwise the redirect URI
    // we advertise and the endpoint we listen on can silently disagree
    const defaultPath = await fetch(`http://127.0.0.1:${result.actualPort}/oauth/callback?code=test-code`)
    expect(defaultPath.status).toBe(404)
  })

  it('hands each sign-in its own code, so a used one is never replayed', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({ port: 0, path: '/oauth/callback', events, serverUrlHash: 'h' })
    server = result.server
    const base = `http://127.0.0.1:${result.actualPort}/oauth/callback`

    // Given a first sign-in, redeemed by whoever asked for it
    await fetch(`${base}?code=first&state=s1`)
    expect(await result.waitForAuthCode()).toEqual({ code: 'first', state: 's1' })

    // When the user signs in again later, because the tokens were revoked
    await fetch(`${base}?code=second&state=s2`)

    // Then the second code is handed over. Returning `first` again would be replaying a
    // single-use code, which the authorization server refuses with invalid_grant.
    expect(await result.waitForAuthCode()).toEqual({ code: 'second', state: 's2' })
  })

  it('holds a code that arrives before anyone is waiting for it', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({ port: 0, path: '/oauth/callback', events, serverUrlHash: 'h' })
    server = result.server

    // The browser reaches the callback before the flow gets round to asking; both orders happen
    await fetch(`http://127.0.0.1:${result.actualPort}/oauth/callback?code=early`)

    expect(await result.waitForAuthCode()).toEqual({ code: 'early', state: undefined })
  })

  it('still tells a sibling the sign-in finished after the code has been taken', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({ port: 0, path: '/oauth/callback', events, serverUrlHash: 'h' })
    server = result.server

    await fetch(`http://127.0.0.1:${result.actualPort}/oauth/callback?code=taken`)
    await result.waitForAuthCode()

    // Draining the queue must not make "has the user finished?" go back to no
    const poll = await fetch(`http://127.0.0.1:${result.actualPort}/wait-for-auth?poll=false`)
    expect(poll.status).toBe(200)
  })

  it('should reject with EADDRINUSE error when strictPort is true and port is already in use', async () => {
    const blocker = net.createServer()
    const blockedPort = await new Promise<number>((resolve) => {
      blocker.listen(0, '127.0.0.1', () => resolve((blocker.address() as net.AddressInfo).port))
    })

    try {
      await expect(
        setupOAuthCallbackServerWithLongPoll({
          port: blockedPort,
          path: '/oauth/callback',
          events,
          serverUrlHash: 'test-hash',
        }),
      ).rejects.toMatchObject({
        code: 'EADDRINUSE',
        requestedPort: blockedPort,
      })
    } finally {
      await new Promise<void>((resolve) => blocker.close(() => resolve()))
    }
  })
})

describe('Feature: Merging headers for the SSE request', () => {
  it('Scenario: Keep the headers the SDK set, whichever Headers class built them', () => {
    // Given headers from the SDK, which builds them with the global class rather than undici's
    const fromSdk = new globalThis.Headers({ 'mcp-protocol-version': '2025-06-18' })

    // When they are merged
    const merged = mergeHeaders(fromSdk, { Accept: 'text/event-stream' })

    // Then they survive, rather than being spread away to nothing
    expect(merged).toEqual({ 'mcp-protocol-version': '2025-06-18', Accept: 'text/event-stream' })
  })

  it('Scenario: Accept undici Headers just the same', () => {
    const merged = mergeHeaders(new UndiciHeaders({ 'x-from-undici': 'yes' }))

    expect(merged).toEqual({ 'x-from-undici': 'yes' })
  })

  it('Scenario: One header per name, however its writers spelled it', () => {
    // Given the same header arriving in two cases, as it does when the SDK's lowercased
    // `authorization` meets the `Authorization` added alongside it
    const merged = mergeHeaders(new globalThis.Headers({ authorization: 'Bearer stale' }), { Authorization: 'Bearer fresh' })

    // Then only the later one is sent. Emitting both would have fetch join them into
    // "Bearer stale, Bearer fresh", which no server accepts.
    expect(Object.keys(merged)).toEqual(['Authorization'])
    expect(merged.Authorization).toBe('Bearer fresh')
  })

  it('Scenario: A custom header keeps the case it was written in', () => {
    // Given a server that matches its header names case-sensitively
    const merged = mergeHeaders(new globalThis.Headers({ accept: 'text/event-stream' }), { Company: 'ACME', TenantId: 'abc' })

    // Then --header values are passed on spelled the way the user spelled them
    expect(merged.Company).toBe('ACME')
    expect(merged.TenantId).toBe('abc')
  })

  it('Scenario: Accept the other shapes fetch allows', () => {
    expect(mergeHeaders(undefined)).toEqual({})
    expect(mergeHeaders({ a: '1' }, undefined, { b: '2' })).toEqual({ a: '1', b: '2' })
    // An array of pairs, whose own `entries()` would yield [index, pair] if it were treated as iterable
    expect(mergeHeaders([['x-pair', 'value']])).toEqual({ 'x-pair': 'value' })
  })
})

describe('Feature: Network Tuning Options', () => {
  it('Scenario: Read a duration in seconds as milliseconds', () => {
    expect(parseSecondsOption(['--connect-timeout', '30'], '--connect-timeout')).toBe(30000)
    expect(parseSecondsOption(['--connect-timeout', '2.5'], '--connect-timeout')).toBe(2500)
  })

  it('Scenario: Absent flag leaves the setting alone', () => {
    // Undefined rather than a default, so an unset flag never installs a dispatcher of its own
    expect(parseSecondsOption(['--transport', 'sse-only'], '--connect-timeout')).toBeUndefined()
    expect(parseSecondsOption(['--connect-timeout'], '--connect-timeout')).toBeUndefined()
  })

  it('Scenario: Zero disables a timeout, but only where that is meaningful', () => {
    // `--body-timeout 0` is how you keep undici from tearing down an idle SSE stream
    expect(parseSecondsOption(['--body-timeout', '0'], '--body-timeout', { allowZero: true })).toBe(0)
    // A zero connect timeout would just mean "never connect", so it is rejected
    expect(parseSecondsOption(['--connect-timeout', '0'], '--connect-timeout')).toBeUndefined()
  })

  it('Scenario: Reject values that are not durations', () => {
    expect(parseSecondsOption(['--connect-timeout', 'soon'], '--connect-timeout')).toBeUndefined()
    expect(parseSecondsOption(['--connect-timeout', '-5'], '--connect-timeout')).toBeUndefined()
    expect(parseSecondsOption(['--body-timeout', 'Infinity'], '--body-timeout', { allowZero: true })).toBeUndefined()
  })

  it('Scenario: Accept the network flags alongside the server URL', async () => {
    // Given every network flag set at once
    const result = await parseCommandLineArgs(
      ['https://example.remote/server', '--connect-timeout', '20', '--body-timeout', '0', '--headers-timeout', '90', '--ipv4'],
      'Usage: mcp-remote <url>',
    )

    // Then they are consumed as options rather than mistaken for the URL or the callback port
    expect(result.serverUrl).toBe('https://example.remote/server')
  })
})

describe('Feature: Completing a sign-in the server asked for mid-session', () => {
  const mockTransport = () =>
    ({
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    }) as unknown as Transport

  /** A server transport that refuses the first `refusals` sends as unauthorized. */
  const refusingTransport = (refusals: number) => {
    const transport = mockTransport()
    let refused = 0
    ;(transport.send as any).mockImplementation(async () => {
      if (refused++ < refusals) throw new Error('Error POSTing to endpoint (HTTP 401): Unauthorized')
    })
    return transport
  }

  it('Scenario: A refused request is retried once the sign-in completes', async () => {
    // Given a server that refuses until somebody signs in
    const client = mockTransport()
    const server = refusingTransport(1)
    const reauthorize = vi.fn().mockResolvedValue(undefined)
    mcpProxy({ transportToClient: client, transportToServer: server, reauthorize })

    // When a request is refused
    client.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'x' } } as any)
    await new Promise((resolve) => setTimeout(resolve, 20))

    // Then the sign-in runs and the request is delivered, rather than answered with an error
    expect(reauthorize).toHaveBeenCalledTimes(1)
    expect(server.send).toHaveBeenCalledTimes(2)
    expect(client.send).not.toHaveBeenCalled()
  })

  it('Scenario: Requests refused together share one sign-in', async () => {
    const client = mockTransport()
    const server = refusingTransport(3)
    let signIns = 0
    const reauthorize = vi.fn().mockImplementation(async () => {
      signIns++
      await new Promise((resolve) => setTimeout(resolve, 10))
    })
    mcpProxy({ transportToClient: client, transportToServer: server, reauthorize })

    // When three requests are refused at once
    for (const id of [1, 2, 3]) {
      client.onmessage!({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'x' } } as any)
    }
    await new Promise((resolve) => setTimeout(resolve, 60))

    // Then the user is asked to sign in once, not three times
    expect(signIns).toBe(1)
  })

  it('Scenario: Still refused after signing in, the client is told', async () => {
    // Given a server that refuses even the token just obtained
    const client = mockTransport()
    const server = refusingTransport(Number.MAX_SAFE_INTEGER)
    const reauthorize = vi.fn().mockResolvedValue(undefined)
    mcpProxy({ transportToClient: client, transportToServer: server, reauthorize })

    client.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'x' } } as any)
    await new Promise((resolve) => setTimeout(resolve, 30))

    // Then it stops after one attempt and answers, rather than signing in forever
    expect(reauthorize).toHaveBeenCalledTimes(1)
    expect(client.send).toHaveBeenCalledWith(expect.objectContaining({ id: 1, error: expect.anything() }))
  })

  it('Scenario: Without a way to sign in, the refusal is answered as before', async () => {
    const client = mockTransport()
    const server = refusingTransport(1)
    mcpProxy({ transportToClient: client, transportToServer: server })

    client.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'x' } } as any)
    await new Promise((resolve) => setTimeout(resolve, 20))

    expect(client.send).toHaveBeenCalledWith(expect.objectContaining({ id: 1, error: expect.anything() }))
  })
})

describe('Feature: Server URL Hash Generation', () => {
  it('Scenario: Generate consistent hash for same config', () => {
    const hash1 = getServerUrlHash('https://example.com', 'resource1', { Auth: 'token' })
    const hash2 = getServerUrlHash('https://example.com', 'resource1', { Auth: 'token' })
    expect(hash1).toBe(hash2)
  })

  it('Scenario: Generate different hash for different resources', () => {
    const hash1 = getServerUrlHash('https://example.com', 'resource1')
    const hash2 = getServerUrlHash('https://example.com', 'resource2')
    expect(hash1).not.toBe(hash2)
  })

  it('Scenario: Generate different hash for different headers', () => {
    const hash1 = getServerUrlHash('https://example.com', '', { Auth: 'token1' })
    const hash2 = getServerUrlHash('https://example.com', '', { Auth: 'token2' })
    expect(hash1).not.toBe(hash2)
  })

  it('Scenario: Handle header key ordering consistently', () => {
    const hash1 = getServerUrlHash('https://example.com', '', { B: '2', A: '1' })
    const hash2 = getServerUrlHash('https://example.com', '', { A: '1', B: '2' })
    expect(hash1).toBe(hash2)
  })

  it('Scenario: Backward compatible with no resource or headers', () => {
    const hash1 = getServerUrlHash('https://example.com')
    const hash2 = getServerUrlHash('https://example.com', '', {})
    expect(hash1).toBe(hash2)
  })

  it('Scenario: Empty string resource same as undefined', () => {
    const hash1 = getServerUrlHash('https://example.com', '')
    const hash2 = getServerUrlHash('https://example.com')
    expect(hash1).toBe(hash2)
  })
})

describe('Feature: Stale Client Registration Invalidation', () => {
  const originalConfigDir = process.env.MCP_REMOTE_CONFIG_DIR
  let baseDir: string
  let versionDir: string

  const clientInfoPath = (serverUrl: string, headers: Record<string, string> = {}) =>
    path.join(versionDir, `${getServerUrlHash(serverUrl, undefined, headers)}_client_info.json`)

  const writeRegistration = (serverUrl: string, redirectUris: string[]) => {
    fs.mkdirSync(versionDir, { recursive: true })
    fs.writeFileSync(clientInfoPath(serverUrl), JSON.stringify({ client_id: 'registered-id', redirect_uris: redirectUris }))
  }

  beforeEach(() => {
    baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-remote-test-'))
    process.env.MCP_REMOTE_CONFIG_DIR = baseDir
    // Asked for rather than rebuilt here, so the store layout can be renamed without these lying
    versionDir = getConfigDir()
  })

  afterEach(() => {
    if (originalConfigDir === undefined) delete process.env.MCP_REMOTE_CONFIG_DIR
    else process.env.MCP_REMOTE_CONFIG_DIR = originalConfigDir
    fs.rmSync(baseDir, { recursive: true, force: true })
  })

  it('Scenario: Reuse a registration whose redirect_uri still matches', async () => {
    // Given a registration made against the port this server derives
    const serverUrl = 'https://reuse.example.com/mcp'
    const derivedPort = calculateDefaultPort(getServerUrlHash(serverUrl))
    writeRegistration(serverUrl, [`http://localhost:${derivedPort}/oauth/callback`])

    // When starting with no port override
    const result = await parseCommandLineArgs([serverUrl], 'test usage')

    // Then the derived port is used and the registration is kept
    expect(result.callbackPort).toBe(derivedPort)
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(true)
  })

  it('Scenario: Every instance derives the same port, so none is taken from a cached registration', async () => {
    // A registration left behind on some other port must not pull this instance off the port its
    // siblings will derive - agreeing on one port is what lets them agree on one owner.
    const serverUrl = 'https://derived.example.com/mcp'
    writeRegistration(serverUrl, ['http://localhost:5599/oauth/callback'])

    const result = await parseCommandLineArgs([serverUrl], 'test usage')

    expect(result.callbackPort).toBe(calculateDefaultPort(getServerUrlHash(serverUrl)))
    expect(result.callbackPort).not.toBe(5599)
    // and the registration that named the other port is discarded rather than reused
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(false)
  })

  it('Scenario: Discard a registration whose redirect_uri is not reachable locally', async () => {
    // Given a registration pointing at a reverse proxy - no local port can be derived from it.
    // This used to throw "Cannot find localhost callback URI" and kill the process.
    const serverUrl = 'https://proxied.example.com/mcp'
    writeRegistration(serverUrl, ['https://proxy.example.com/oauth/callback'])

    // When starting
    const result = await parseCommandLineArgs([serverUrl], 'test usage')

    // Then it does not throw, and the unusable registration is gone so the next request
    // re-registers with a redirect_uri the authorization server will actually accept
    expect(result.callbackPort).toBeGreaterThan(0)
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(false)
  })

  it('Scenario: Discard a registration when the callback host changes', async () => {
    // Given a registration made against localhost
    const serverUrl = 'https://hostchange.example.com/mcp'
    writeRegistration(serverUrl, ['http://localhost:5599/oauth/callback'])

    // When the same server is started with a different callback host
    const result = await parseCommandLineArgs([serverUrl, '--host', '127.0.0.1'], 'test usage')

    // Then the registration is discarded - 127.0.0.1 and localhost are distinct redirect_uris
    expect(result.callbackPort).toBe(calculateDefaultPort(getServerUrlHash(serverUrl)))
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(false)
  })

  it('Scenario: Discard a registration when an explicit port conflicts', async () => {
    // Given a registration on one port
    const serverUrl = 'https://portconflict.example.com/mcp'
    writeRegistration(serverUrl, ['http://localhost:5599/oauth/callback'])

    // When a different port is demanded
    const result = await parseCommandLineArgs([serverUrl, '7788'], 'test usage')

    // Then the stale registration is discarded
    expect(result.callbackPort).toBe(7788)
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(false)
  })

  it('Scenario: Never discard a user-pinned static client registration', async () => {
    // Given a registration that does not match, but static client info was supplied
    const serverUrl = 'https://static.example.com/mcp'
    writeRegistration(serverUrl, ['https://proxy.example.com/oauth/callback'])

    // When starting with --static-oauth-client-info
    await parseCommandLineArgs(
      [serverUrl, '--static-oauth-client-info', '{"client_id":"pinned","redirect_uris":["https://proxy.example.com/oauth/callback"]}'],
      'test usage',
    )

    // Then it is left alone - the user pinned it deliberately
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(true)
  })
})

describe('Feature: Resource Indicator Flags', () => {
  it('Scenario: Parse --resource', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp', '--resource', 'https://tenant.example.com/'], 'test usage')
    expect(result.authorizeResource).toBe('https://tenant.example.com/')
    expect(result.skipResourceParameter).toBe(false)
  })

  it('Scenario: Reject a --resource value that is not an absolute URI', async () => {
    // RFC 8707 requires an absolute URI; failing here beats an opaque error from the server
    await expect(parseCommandLineArgs(['https://example.com/mcp', '--resource', 'not-a-uri'], 'test usage')).rejects.toThrow(/absolute URI/)
  })

  it('Scenario: Disable the resource parameter', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp', '--disable-resource-parameter'], 'test usage')
    expect(result.skipResourceParameter).toBe(true)
    expect(result.authorizeResource).toBeUndefined()
  })

  it('Scenario: Treat an empty --resource as disabling it', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp', '--resource', ''], 'test usage')
    expect(result.skipResourceParameter).toBe(true)
    expect(result.authorizeResource).toBeUndefined()
  })

  it('Scenario: Disabling wins over an explicit resource, without splitting the cache', async () => {
    const withBoth = await parseCommandLineArgs(
      ['https://example.com/mcp', '--resource', 'https://tenant.example.com/', '--disable-resource-parameter'],
      'test usage',
    )
    const withDisableOnly = await parseCommandLineArgs(['https://example.com/mcp', '--disable-resource-parameter'], 'test usage')

    expect(withBoth.skipResourceParameter).toBe(true)
    expect(withBoth.authorizeResource).toBeUndefined()
    // Both send identical requests, so they must share one credential cache
    expect(withBoth.serverUrlHash).toBe(withDisableOnly.serverUrlHash)
  })

  it('Scenario: Existing caches are unaffected when no resource flags are used', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp'], 'test usage')
    expect(result.serverUrlHash).toBe(getServerUrlHash('https://example.com/mcp', undefined, {}))
  })
})

describe('Feature: Keeping an idle connection alive', () => {
  const mockTransport = () =>
    ({
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    }) as unknown as Transport

  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('Scenario: Pings the server once per interval while the connection is open', async () => {
    // Given a proxy set up to keep the connection alive every 30 seconds
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    mcpProxy({ transportToClient, transportToServer, keepAlive: { enabled: true, intervalMs: 30_000 } })

    // When two intervals elapse with no other traffic
    await vi.advanceTimersByTimeAsync(60_000)

    // Then the server has been pinged twice
    const pings = (transportToServer.send as any).mock.calls.filter(([m]: any[]) => m.method === 'ping')
    expect(pings).toHaveLength(2)
    expect(pings[0][0]).toMatchObject({ jsonrpc: '2.0', method: 'ping' })
  })

  it('Scenario: Without the flag, nothing is sent', async () => {
    // Given a proxy with no keep-alive configured
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    mcpProxy({ transportToClient, transportToServer })

    // When a long time passes
    await vi.advanceTimersByTimeAsync(10 * 60_000)

    // Then the proxy has sent nothing of its own
    expect(transportToServer.send).not.toHaveBeenCalled()
  })

  it('Scenario: The answer to our own ping is consumed, not forwarded to the client', async () => {
    // Given a proxy that has sent a keep-alive ping
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    mcpProxy({ transportToClient, transportToServer, keepAlive: { enabled: true, intervalMs: 30_000 } })
    await vi.advanceTimersByTimeAsync(30_000)

    const [ping] = (transportToServer.send as any).mock.calls.find(([m]: any[]) => m.method === 'ping')

    // When the server answers it
    transportToServer.onmessage?.({ jsonrpc: '2.0', id: ping.id, result: {} } as any)

    // Then the client is never handed a response to a request it did not send
    expect(transportToClient.send).not.toHaveBeenCalled()
  })

  it("Scenario: A response to the client's own request is still forwarded", async () => {
    // Given a proxy with keep-alive enabled
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    mcpProxy({ transportToClient, transportToServer, keepAlive: { enabled: true, intervalMs: 30_000 } })
    await vi.advanceTimersByTimeAsync(30_000)

    // When the server answers something the client actually asked for
    transportToServer.onmessage?.({ jsonrpc: '2.0', id: 'client-1', result: { tools: [] } } as any)

    // Then it reaches the client untouched
    expect(transportToClient.send).toHaveBeenCalledWith(expect.objectContaining({ id: 'client-1' }))
  })

  it('Scenario: A ping answer is only swallowed once, so a reused id still reaches the client', async () => {
    // Given a proxy whose first ping has already been answered
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    mcpProxy({ transportToClient, transportToServer, keepAlive: { enabled: true, intervalMs: 30_000 } })
    await vi.advanceTimersByTimeAsync(30_000)
    const [ping] = (transportToServer.send as any).mock.calls.find(([m]: any[]) => m.method === 'ping')
    transportToServer.onmessage?.({ jsonrpc: '2.0', id: ping.id, result: {} } as any)

    // When a later message arrives carrying that same id
    transportToServer.onmessage?.({ jsonrpc: '2.0', id: ping.id, result: { second: true } } as any)

    // Then it is treated as the client's, because our ping is no longer outstanding
    expect(transportToClient.send).toHaveBeenCalledWith(expect.objectContaining({ id: ping.id }))
  })

  it('Scenario: Pinging stops once the connection closes', async () => {
    // Given a proxy that has been pinging
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    mcpProxy({ transportToClient, transportToServer, keepAlive: { enabled: true, intervalMs: 30_000 } })
    await vi.advanceTimersByTimeAsync(30_000)
    const before = (transportToServer.send as any).mock.calls.length

    // When the remote end closes
    transportToServer.onclose?.()
    await vi.advanceTimersByTimeAsync(5 * 60_000)

    // Then no further pings are sent
    expect((transportToServer.send as any).mock.calls.length).toBe(before)
  })

  it('Scenario: A failed ping is reported without taking the proxy down', async () => {
    // Given a server that refuses the ping
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    ;(transportToServer.send as any).mockRejectedValue(new Error('socket hang up'))
    mcpProxy({ transportToClient, transportToServer, keepAlive: { enabled: true, intervalMs: 30_000 } })

    // When intervals elapse
    await vi.advanceTimersByTimeAsync(60_000)

    // Then it keeps trying rather than giving up after the first failure
    expect((transportToServer.send as any).mock.calls.length).toBe(2)
  })
})

describe('Feature: Timing out an unanswered initialize', () => {
  const mockTransport = () =>
    ({
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    }) as unknown as Transport

  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('Scenario: A server that opens a response and never answers is reported, not left hanging', async () => {
    // Given a remote transport whose send() resolves (the stream opened) without ever calling onmessage
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    mcpProxy({ transportToClient, transportToServer, ignoredTools: [] })

    // When the client initializes and the remote server never answers
    transportToClient.onmessage?.({ jsonrpc: '2.0', method: 'initialize', id: 'init-1', params: {} } as any)
    await vi.advanceTimersByTimeAsync(30_000)

    // Then the client is given an error for that request instead of waiting forever
    expect(transportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'init-1', error: expect.objectContaining({ code: -32001 }) }),
    )
  })

  it('Scenario: A late answer within the window cancels the timeout', async () => {
    // Given a proxy waiting on the client's initialize
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    mcpProxy({ transportToClient, transportToServer, ignoredTools: [] })
    transportToClient.onmessage?.({ jsonrpc: '2.0', method: 'initialize', id: 'init-1', params: {} } as any)

    // When the server answers just before the deadline
    await vi.advanceTimersByTimeAsync(29_000)
    transportToServer.onmessage?.({ jsonrpc: '2.0', id: 'init-1', result: { protocolVersion: '2025-11-25' } } as any)
    await vi.advanceTimersByTimeAsync(30_000)

    // Then the client sees the real answer, and only that one answer
    const answers = (transportToClient.send as any).mock.calls.filter(([m]: any[]) => m.id === 'init-1')
    expect(answers).toHaveLength(1)
    expect(answers[0][0]).toMatchObject({ result: { protocolVersion: '2025-11-25' } })
  })

  it('Scenario: A slow tools/call is left alone', async () => {
    // Given a proxy waiting on a request that is not initialize
    const transportToClient = mockTransport()
    const transportToServer = mockTransport()
    mcpProxy({ transportToClient, transportToServer, ignoredTools: [] })
    transportToClient.onmessage?.({ jsonrpc: '2.0', method: 'tools/call', id: 'call-1', params: { name: 'slow-tool' } } as any)

    // When far more than the initialize window passes with no answer
    await vi.advanceTimersByTimeAsync(5 * 60_000)

    // Then nothing is reported - only initialize is bounded, so a legitimately long tool call is untouched
    expect(transportToClient.send).not.toHaveBeenCalled()
  })
})

describe('Feature: Keep-alive command line flags', () => {
  it('Scenario: Off unless asked for', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp'], 'usage')
    expect(result.keepAlive.enabled).toBe(false)
  })

  it('Scenario: --keep-alive pings every 30 seconds by default', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp', '--keep-alive'], 'usage')
    expect(result.keepAlive).toEqual({ enabled: true, intervalMs: 30_000 })
  })

  it('Scenario: --ping-interval sets the interval and implies --keep-alive', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp', '--ping-interval', '10'], 'usage')
    expect(result.keepAlive).toEqual({ enabled: true, intervalMs: 10_000 })
  })

  it('Scenario: An unusable interval falls back to the default rather than disabling the flag', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp', '--keep-alive', '--ping-interval', 'soon'], 'usage')
    expect(result.keepAlive).toEqual({ enabled: true, intervalMs: 30_000 })
  })
})

describe('Feature: Extra authorization parameters', () => {
  it('Scenario: Collects repeated key=value flags', async () => {
    // Given a server that wants Google's offline-access parameters
    const args = ['https://example.com/mcp', '--authorize-param', 'access_type=offline', '--authorize-param', 'prompt=consent']

    // When the arguments are parsed
    const result = await parseCommandLineArgs(args, 'usage')

    // Then both are collected
    expect(result.authorizeParams).toEqual({ access_type: 'offline', prompt: 'consent' })
  })

  it('Scenario: Only the first = separates key from value', () => {
    // Given a value that itself contains '=', as a JWT or base64 padding does
    const params = parseAuthorizeParams(['--authorize-param', 'audience=https://api.example.com/?a=b'])

    // Then the value survives intact
    expect(params).toEqual({ audience: 'https://api.example.com/?a=b' })
  })

  it('Scenario: Refuses parameters the flow derives per request', () => {
    // Given an attempt to pin the PKCE challenge
    // Then it is refused, rather than surfacing later as an opaque server error
    expect(() => parseAuthorizeParams(['--authorize-param', 'code_challenge=abc'])).toThrow(/part of the authorization flow itself/)
    expect(() => parseAuthorizeParams(['--authorize-param', 'state=abc'])).toThrow(/part of the authorization flow itself/)
    expect(() => parseAuthorizeParams(['--authorize-param', 'client_id=abc'])).toThrow(/part of the authorization flow itself/)
  })

  it('Scenario: Rejects a value that is not key=value', () => {
    expect(() => parseAuthorizeParams(['--authorize-param', 'audience'])).toThrow(/Expected key=value/)
    expect(() => parseAuthorizeParams(['--authorize-param', '=orphaned'])).toThrow(/Expected key=value/)
  })

  it('Scenario: No flags means no parameters', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp'], 'usage')
    expect(result.authorizeParams).toEqual({})
  })

  it('Scenario: Differing parameters do not share stored credentials', () => {
    // Given the same server authorized for two different APIs
    const a = getServerUrlHash('https://example.com/mcp', undefined, undefined, { audience: 'https://api-a.example.com' })
    const b = getServerUrlHash('https://example.com/mcp', undefined, undefined, { audience: 'https://api-b.example.com' })

    // Then a token issued for one is never reused for the other
    expect(a).not.toBe(b)
  })

  it('Scenario: Parameter order does not change the credential key', () => {
    // Given the same parameters supplied in either order
    const a = getServerUrlHash('https://example.com/mcp', undefined, undefined, { access_type: 'offline', prompt: 'consent' })
    const b = getServerUrlHash('https://example.com/mcp', undefined, undefined, { prompt: 'consent', access_type: 'offline' })

    // Then the sign-in is reused rather than silently repeated
    expect(a).toBe(b)
  })

  it('Scenario: Adding no parameters leaves existing credentials addressable', () => {
    // Given the hash a previous release computed for this server
    const before = getServerUrlHash('https://example.com/mcp')

    // When the new argument is threaded through empty
    const after = getServerUrlHash('https://example.com/mcp', undefined, undefined, {})

    // Then nobody is signed out by the upgrade
    expect(after).toBe(before)
  })
})

/**
 * The SDK reads an OAuth error body only when the response satisfies `instanceof Response` against
 * the *global* class. We hand it undici's `fetch` from a bundled copy, whose `Response` is a
 * different class, so every OAuth failure used to be rendered as the literal `[object Response]` -
 * hiding exactly the `invalid_grant` that made issue #353 so hard to place.
 */
describe('Feature: OAuth failures report what the server said', () => {
  it('Scenario: A refused token exchange carries its OAuth error, not [object Response]', async () => {
    // Given a token endpoint refusing an exchange the way RFC 6749 says to
    const server = createServer((_req, res) => {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'code_verifier does not match' }))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const { port } = server.address() as net.AddressInfo

    try {
      // When the SDK renders that failure, from a response fetched the way it fetches them
      const response = await fetchWithMcpHeaders(`http://127.0.0.1:${port}/token`, { method: 'POST' })
      const error = await parseErrorResponse(response)

      // Then it is the server's own error, not the shape of the object that carried it
      expect(error).toBeInstanceOf(OAuthError)
      expect(error.code).toBe(OAuthErrorCode.InvalidGrant)
      expect(error.message).toBe('code_verifier does not match')
      expect(error.message).not.toContain('[object Response]')
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })

  it('Scenario: A failed response still reads as a response everywhere else', async () => {
    // Given a server refusing with a status that carries no body
    const server = createServer((_req, res) => {
      res.writeHead(304, { 'x-served-by': 'node-1' })
      res.end()
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const { port } = server.address() as net.AddressInfo

    try {
      // When it comes back through our fetch
      const response = await fetchWithMcpHeaders(`http://127.0.0.1:${port}/`, {})

      // Then rebuilding it kept everything a caller reads off it - a status the `Response`
      // constructor refuses a body for must not throw on the way through
      expect(response.status).toBe(304)
      expect(response.headers.get('x-served-by')).toBe('node-1')
      expect(response.url).toBe(`http://127.0.0.1:${port}/`)
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })
})
