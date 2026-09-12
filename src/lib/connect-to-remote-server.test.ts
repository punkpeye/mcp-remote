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
  // Every authorization code handed to `finishAuth`, in order (extracted from the params).
  finishAuthCalls: [] as string[],
  // The `iss` parameter passed to `finishAuth` alongside each code, parallel to finishAuthCalls.
  finishAuthIssCalls: [] as Array<string | undefined>,
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
    finishAuth = vi.fn(async (params: URLSearchParams | string) => {
      // Accept both URLSearchParams (RFC 9207-aware path) and plain string (legacy path).
      const code = params instanceof URLSearchParams ? (params.get('code') ?? '') : params
      const iss = params instanceof URLSearchParams ? (params.get('iss') ?? undefined) : undefined
      mockState.finishAuthCalls.push(code)
      mockState.finishAuthIssCalls.push(iss)
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
    mockState.finishAuthIssCalls.length = 0
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
    // The argument is now URLSearchParams; check the extracted code via the mock's own capture.
    expect(mockState.finishAuthCalls).toEqual(['auth-code-123'])

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
    // The argument is now URLSearchParams; check the extracted code via the mock's own capture.
    expect(mockState.finishAuthCalls).toEqual(['auth-code-456'])
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

// =============================================================================
// RFC 9207 Authorization Server Issuer Identification — regression tests
// =============================================================================
// RFC 9207 (OAuth 2.0 Authorization Server Issuer Identification) requires that
// authorization servers SHOULD include an `iss` parameter in the authorization
// response. The MCP SDK v2 validates this parameter inside `finishAuth`, and
// throws `IssuerMismatchError` when the `iss` it receives does not match the
// server it sent the request to. mcp-remote was dropping `iss` from the OAuth
// loopback callback, so `finishAuth` saw no issuer and raised IssuerMismatchError
// even when the server supplied a perfectly correct one.

describe('RFC 9207 – iss propagation through the OAuth loopback callback', () => {
  beforeEach(() => {
    mockState.httpTransports.length = 0
    mockState.finishAuthCalls.length = 0
    mockState.finishAuthIssCalls.length = 0
    mockState.connectFailuresRemaining = 1
    mockState.rejectedTokenFailuresRemaining = 0
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('preserves iss from the authorization response and passes it to finishAuth (RFC 9207)', async () => {
    // Simulate an authorization response that includes `iss` as required by RFC 9207.
    // Real servers (e.g. api.sutra.sudarshanai.com) append `?code=...&state=...&iss=https%3A%2F%2F...`
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async (): Promise<AuthCodeResult> => ({
        code: 'auth-code-rfc9207',
        state: 'opaque-state-value',
        iss: 'https://api.sutra.sudarshanai.com',
      }),
      skipBrowserAuth: false,
    })

    await connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')

    // The code was passed through correctly.
    expect(mockState.finishAuthCalls).toEqual(['auth-code-rfc9207'])

    // The iss was preserved and forwarded – without this, IssuerMismatchError would be thrown
    // by the SDK's RFC 9207 validation even when the issuer is correct.
    expect(mockState.finishAuthIssCalls).toEqual(['https://api.sutra.sudarshanai.com'])
  })

  it('finishAuth receives a URLSearchParams with both code and iss set', async () => {
    // The MCP SDK's preferred form for finishAuth is URLSearchParams.
    // Verify the raw argument shape rather than just the captured scalars.
    let capturedParams: unknown

    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async (): Promise<AuthCodeResult> => ({
        code: 'auth-code-urlparams',
        iss: 'https://api.sutra.sudarshanai.com',
      }),
      skipBrowserAuth: false,
    })

    await connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')

    // The test transport (index 1) is the one that receives the challenge and finishAuth
    const [, testTransport] = mockState.httpTransports
    const call = (testTransport.finishAuth as ReturnType<typeof vi.fn>).mock.calls[0]
    capturedParams = call[0]

    expect(capturedParams).toBeInstanceOf(URLSearchParams)
    expect((capturedParams as URLSearchParams).get('code')).toBe('auth-code-urlparams')
    expect((capturedParams as URLSearchParams).get('iss')).toBe('https://api.sutra.sudarshanai.com')
  })

  it('does not set iss in URLSearchParams when authorization response omits it (backward compat)', async () => {
    // Servers that predate RFC 9207 (or that choose not to include iss) must still work.
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async (): Promise<AuthCodeResult> => ({
        code: 'auth-code-no-iss',
        // iss deliberately absent
      }),
      skipBrowserAuth: false,
    })

    await connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')

    expect(mockState.finishAuthCalls).toEqual(['auth-code-no-iss'])
    // iss must be absent (undefined), not an empty string, so the SDK treats it as missing.
    expect(mockState.finishAuthIssCalls).toEqual([undefined])

    // Confirm the URLSearchParams did NOT include an `iss` key at all.
    const [, testTransport] = mockState.httpTransports
    const call = (testTransport.finishAuth as ReturnType<typeof vi.fn>).mock.calls[0]
    const params = call[0] as URLSearchParams
    expect(params.has('iss')).toBe(false)
  })

  it('state handling remains intact when iss is also present (no regression)', async () => {
    // The existing state-based PKCE flow must still work when iss is added alongside state.
    const useAuthorizationState = vi.fn()
    const authProvider = { useAuthorizationState } as any

    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async (): Promise<AuthCodeResult> => ({
        code: 'auth-code-with-state',
        state: 'csrf-protection-token',
        iss: 'https://api.sutra.sudarshanai.com',
      }),
      skipBrowserAuth: false,
    })

    await connectToRemoteServer(null, 'https://mcp.example.com/mcp', authProvider, {}, authInitializer, 'http-first')

    // State is still forwarded to the provider for PKCE / CSRF validation.
    expect(useAuthorizationState).toHaveBeenCalledWith('csrf-protection-token')

    // And iss is still forwarded to finishAuth for RFC 9207 validation.
    expect(mockState.finishAuthIssCalls).toEqual(['https://api.sutra.sudarshanai.com'])
    expect(mockState.finishAuthCalls).toEqual(['auth-code-with-state'])
  })
})
