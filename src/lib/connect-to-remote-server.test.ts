import { describe, it, expect, vi, beforeEach } from 'vitest'

// Shared state for the mocked SDK transports/clients. `vi.hoisted` lets the `vi.mock`
// factories (which are hoisted above imports) reference this safely.
const mockState = vi.hoisted(() => ({
  // Every StreamableHTTPClientTransport constructed, in order.
  httpTransports: [] as Array<{
    start: ReturnType<typeof vi.fn>
    finishAuth: ReturnType<typeof vi.fn>
    close: ReturnType<typeof vi.fn>
  }>,
  // Number of remaining `Client.connect` calls that should fail with an auth error.
  connectFailuresRemaining: 1,
  // Number of remaining connects that should fail the way the SDK reports a refused fresh token.
  rejectedTokenFailuresRemaining: 0,
  // Every authorization code handed to `finishAuth`, in order.
  finishAuthCalls: [] as string[],
}))

vi.mock('@modelcontextprotocol/client', async (importOriginal) => {
  // Partial mock: `utils.ts` imports more than the three classes stubbed below from this module
  // (UnauthorizedError among them), and a bare factory would leave every one of those undefined.
  const actual = await importOriginal<typeof import('@modelcontextprotocol/client')>()
  const { SdkErrorCode } = actual

  // Mirrors the real class: the HTTP status rides in `data`, and `code` is an SdkErrorCode string.
  // Reversing them here would typecheck against the real signature and then build the wrong error.
  class SdkHttpError extends Error {
    constructor(
      public code: string,
      message: string,
      public data: { status: number; statusText?: string },
    ) {
      super(message)
    }
    get status() {
      return this.data.status
    }
  }
  class StreamableHTTPClientTransport {
    start = vi.fn().mockResolvedValue(undefined)
    finishAuth = vi.fn(async (code: string, _iss?: string) => {
      mockState.finishAuthCalls.push(code)
    })
    close = vi.fn().mockResolvedValue(undefined)
    constructor(
      public url: URL,
      public opts: unknown,
    ) {
      mockState.httpTransports.push(this)
    }
  }
  class SSEClientTransport {
    start = vi.fn().mockResolvedValue(undefined)
    finishAuth = vi.fn().mockResolvedValue(undefined)
    close = vi.fn().mockResolvedValue(undefined)
    constructor(
      public url: URL,
      public opts: unknown,
    ) {}
  }
  class Client {
    constructor(
      public info: unknown,
      public caps: unknown,
    ) {}
    async connect() {
      // The one-off "fallback test" client is what actually probes the server. Simulate the
      // server answering that probe with a 401, so the *test* transport is the one that receives
      // (and stores) the challenge — exactly as happens in real proxy mode.
      if (mockState.rejectedTokenFailuresRemaining > 0) {
        mockState.rejectedTokenFailuresRemaining--
        throw new SdkHttpError(SdkErrorCode.ClientHttpAuthentication, 'Server returned 401 after re-authentication', { status: 401 })
      }
      if (mockState.connectFailuresRemaining > 0) {
        mockState.connectFailuresRemaining--
        throw new Error('Unauthorized')
      }
    }
  }
  return { ...actual, StreamableHTTPClientTransport, SSEClientTransport, Client, SdkHttpError }
})

// Import after mocks are registered.
import { connectToRemoteServer } from './utils'
import type { AuthCodeResult } from './types'

describe('connectToRemoteServer', () => {
  beforeEach(() => {
    mockState.httpTransports.length = 0
    mockState.finishAuthCalls.length = 0
    mockState.connectFailuresRemaining = 1
    mockState.rejectedTokenFailuresRemaining = 0
    // Keep test output quiet; connectToRemoteServer logs to stderr.
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('completes auth on the transport that received the 401 challenge in proxy mode (regression: #270)', async () => {
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => ({ code: 'auth-code-123' }),
      skipBrowserAuth: false,
    })

    // Proxy mode passes `client = null`, which drives the throwaway test-transport probe path.
    await connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')

    // Instances, in construction order:
    //   [0] first attempt's main transport   (never sees the 401)
    //   [1] first attempt's test transport    (receives the 401 -> stores resource_metadata)
    //   [2] second attempt's main transport   (connects successfully after auth)
    //   [3] second attempt's test transport
    const [mainTransport, testTransport] = mockState.httpTransports
    expect(mockState.httpTransports.length).toBeGreaterThanOrEqual(2)

    // The fix: finishAuth must run on the transport that actually handled the challenge,
    // so the stored resource_metadata URL drives token_endpoint discovery.
    expect(testTransport.finishAuth).toHaveBeenCalledTimes(1)
    expect(testTransport.finishAuth).toHaveBeenCalledWith('auth-code-123', undefined)

    // Regression guard: it must NOT be called on the main transport (which never saw the 401).
    expect(mainTransport.finishAuth).not.toHaveBeenCalled()
  })

  it('discards a token the server refused after issuing it, then signs in again', async () => {
    // Given a server that refuses the cached token even though the SDK just authorized with it,
    // and takes the next one. Nothing else clears that credential, so without this the same
    // failure repeats on every run.
    mockState.rejectedTokenFailuresRemaining = 1
    mockState.connectFailuresRemaining = 0
    const invalidateCredentials = vi.fn().mockResolvedValue(undefined)
    const authProvider = { invalidateCredentials } as any
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => ({ code: 'auth-code-789' }),
      skipBrowserAuth: false,
    })

    await connectToRemoteServer(null, 'https://mcp.example.com/mcp', authProvider, {}, authInitializer, 'http-first')

    // Then the refused token is thrown away
    expect(invalidateCredentials).toHaveBeenCalledWith('tokens')

    // And it reconnected rather than failing at startup. Nothing has to be reset on the transport
    // for that: the SDK scopes its "already tried authorizing" flag to a single send, so the
    // reconnect starts willing to authorize again on its own.
    expect(mockState.httpTransports.length).toBeGreaterThanOrEqual(3)
  })

  it('gives up when the token it signed in for is refused as well', async () => {
    // Given a server that refuses every token, however fresh
    mockState.rejectedTokenFailuresRemaining = 5
    mockState.connectFailuresRemaining = 0
    const authProvider = { invalidateCredentials: vi.fn().mockResolvedValue(undefined) } as any
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => ({ code: 'auth-code-789' }),
      skipBrowserAuth: false,
    })

    // Then it stops rather than churning credentials against a server that will never accept one
    await expect(
      connectToRemoteServer(null, 'https://mcp.example.com/mcp', authProvider, {}, authInitializer, 'http-first'),
    ).rejects.toThrow('401 after re-authentication')

    expect(authProvider.invalidateCredentials).toHaveBeenCalledTimes(1)
  })

  it('completes auth on the main transport in with-client mode (parity with the working standalone client path)', async () => {
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => ({ code: 'auth-code-456' }),
      skipBrowserAuth: false,
    })

    // The standalone `mcp-remote-client` binary passes a real Client, so `client.connect(transport)`
    // sends the request through the *main* transport, which receives the 401 itself. This path
    // already works (per #270); this test guards against regressing it. The first connect attempt
    // fails with an auth error (the 401), the retry after auth succeeds.
    let clientConnectCalls = 0
    const client = {
      connect: async () => {
        if (clientConnectCalls++ === 0) throw new Error('Unauthorized')
      },
    } as any

    await connectToRemoteServer(client, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')

    // No throwaway test transport is created in with-client mode, so the first (and only auth-time)
    // transport is the main one, and finishAuth must run on it.
    const [mainTransport] = mockState.httpTransports
    expect(mainTransport.finishAuth).toHaveBeenCalledTimes(1)
    expect(mainTransport.finishAuth).toHaveBeenCalledWith('auth-code-456', undefined)
  })

  it('forwards the callback iss to finishAuth for RFC 9207 validation (regression: IssuerMismatchError)', async () => {
    // A server advertising `authorization_response_iss_parameter_supported: true` sends `iss` on
    // the callback, and the SDK client rejects the exchange if it never reaches `finishAuth`.
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => ({ code: 'auth-code-iss', iss: 'https://mcp.example.com' }),
      skipBrowserAuth: false,
    })

    await connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')

    const [, testTransport] = mockState.httpTransports
    expect(testTransport.finishAuth).toHaveBeenCalledWith('auth-code-iss', 'https://mcp.example.com')
  })

  // What `coordinateAuth` hands a secondary instance once a sibling has finished the browser flow:
  // there is no code to wait for, so awaiting one blocks until the MCP host times the server out.
  const secondaryInstanceAuth = () => ({
    waitForAuthCode: vi.fn(() => new Promise<AuthCodeResult>(() => {})),
    skipBrowserAuth: true,
  })

  it('reconnects instead of awaiting a code when a sibling completed the sign-in (regression: #322)', async () => {
    const authState = secondaryInstanceAuth()
    const authInitializer = vi.fn().mockResolvedValue(authState)

    const connecting = connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')
    const HUNG = Symbol('hung')
    const outcome = await Promise.race([
      connecting.then(() => 'connected'),
      new Promise((resolve) => setTimeout(() => resolve(HUNG), 1000)),
    ])

    expect(outcome).toBe('connected')

    // The sibling already redeemed the authorization code, so there is nothing to exchange here
    expect(authState.waitForAuthCode).not.toHaveBeenCalled()
    expect(mockState.finishAuthCalls).toEqual([])
  })

  it('gives up rather than looping when a sibling instance tokens still do not work (regression: #322)', async () => {
    const authInitializer = vi.fn().mockResolvedValue(secondaryInstanceAuth())
    // Server keeps rejecting even after reading the sibling's tokens
    mockState.connectFailuresRemaining = Number.MAX_SAFE_INTEGER

    // It still stops, and now says which of the two things went wrong rather than reporting a
    // spent retry budget the user cannot act on (issue #352)
    await expect(connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')).rejects.toThrow(
      'the remote server refused the tokens it wrote',
    )
  })

  it('looks again rather than trusting a handover verdict its tokens were refused for (regression: #352)', async () => {
    // Given a sibling that had finished signing in, whose tokens the server then refused
    const authInitializer = vi.fn(async (options?: { forceRefresh?: boolean }) =>
      // On the second look the sibling has released the port, so this instance signs in itself
      options?.forceRefresh
        ? { waitForAuthCode: async () => ({ code: 'auth-code-352' }), skipBrowserAuth: false }
        : secondaryInstanceAuth(),
    )
    mockState.connectFailuresRemaining = Number.MAX_SAFE_INTEGER

    // It ends on its own sign-in's budget, not on one spent waiting for the sibling
    await expect(connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')).rejects.toThrow(
      'Already attempted reconnection',
    )

    // Then the handover was not the end of it: a fresh verdict was asked for, and the sign-in this
    // instance was entitled to ran rather than being spent on the handover
    expect(authInitializer).toHaveBeenCalledWith({ forceRefresh: true })
    expect(mockState.finishAuthCalls).toEqual(['auth-code-352'])
  })

  it('does not re-exchange a spent authorization code when the retry also fails (regression: #322)', async () => {
    // A real callback server retains the code it received, so a second call yields the same one
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => ({ code: 'auth-code-789' }),
      skipBrowserAuth: false,
    })
    mockState.connectFailuresRemaining = Number.MAX_SAFE_INTEGER

    // Without the guard ordering, the second exchange of 'auth-code-789' fails with invalid_grant,
    // masking the real reason the connection is being abandoned.
    await expect(connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')).rejects.toThrow(
      'Already attempted reconnection',
    )

    expect(mockState.finishAuthCalls).toEqual(['auth-code-789'])
  })
})
