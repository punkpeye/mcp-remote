import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocked = vi.hoisted(() => {
  const completeAuthorization = vi.fn()
  const finishAuth = vi.fn()
  const useAuthorizationState = vi.fn()
  const initializeAuth = vi.fn()
  const createLazyAuthCoordinator = vi.fn(() => ({ initializeAuth }))
  return {
    completeAuthorization,
    finishAuth,
    useAuthorizationState,
    initializeAuth,
    createLazyAuthCoordinator,
    remoteTransport: { finishAuth } as { finishAuth?: typeof finishAuth },
    reauthorize: undefined as (() => Promise<void>) | undefined,
  }
})

vi.mock('@modelcontextprotocol/client', () => ({ createFetchWithInit: vi.fn(() => vi.fn()) }))
vi.mock('@modelcontextprotocol/server/stdio', () => ({
  StdioServerTransport: class {
    start = vi.fn().mockResolvedValue(undefined)
  },
}))
vi.mock('./lib/node-oauth-client-provider', () => ({
  NodeOAuthClientProvider: class {
    useAuthorizationState = mocked.useAuthorizationState
  },
}))
vi.mock('./lib/coordination', () => ({
  createLazyAuthCoordinator: mocked.createLazyAuthCoordinator,
  hasUsableTokens: vi.fn().mockResolvedValue(true),
  serverIssuesAuthChallenge: vi.fn(),
}))
vi.mock('./lib/utils', () => ({
  parseCommandLineArgs: vi.fn().mockResolvedValue({
    serverUrl: 'https://mcp.example.com/mcp',
    callbackPath: '/custom/callback',
    callbackPort: 3600,
    specifiedPort: 3600,
    headers: {},
    authTimeoutMs: 1000,
    serverUrlHash: 'proxy-completion',
    authSuccessUrl: 'https://app.example.com/cli-connected',
  }),
  connectToRemoteServer: vi.fn(async () => mocked.remoteTransport),
  discoverOAuthServerInfo: vi.fn().mockResolvedValue({ authorizationServerUrl: 'https://issuer.example.com' }),
  mcpProxy: vi.fn((options: { reauthorize: () => Promise<void> }) => {
    mocked.reauthorize = options.reauthorize
  }),
  setupSignalHandlers: vi.fn(),
  fetchWithMcpHeaders: vi.fn(),
  forgetRejectedAuthorization: vi.fn(),
  debugLog: vi.fn(),
  log: vi.fn(),
}))

describe('proxy OAuth browser completion', () => {
  beforeEach(async () => {
    vi.resetModules()
    vi.clearAllMocks()
    mocked.reauthorize = undefined
    mocked.remoteTransport = { finishAuth: mocked.finishAuth }
    mocked.finishAuth.mockReset().mockResolvedValue(undefined)
    mocked.useAuthorizationState.mockReset()
    mocked.initializeAuth.mockResolvedValue({
      actualPort: 3600,
      server: {},
      skipBrowserAuth: false,
      waitForAuthCode: async () => ({
        code: 'mid-session-code',
        state: 'mid-session-state',
        iss: 'https://issuer.example.com',
        completeAuthorization: mocked.completeAuthorization,
      }),
    })
    await import('./proxy')
    await vi.waitUntil(() => mocked.reauthorize !== undefined)
  })

  it('forwards the CLI option without changing the callback path or port', () => {
    expect(mocked.createLazyAuthCoordinator).toHaveBeenCalledWith(
      'proxy-completion',
      '/custom/callback',
      3600,
      expect.anything(),
      1000,
      true,
      'https://app.example.com/cli-connected',
    )
  })

  it('completes a mid-session browser response only after tokens have been exchanged', async () => {
    let finishExchange!: () => void
    mocked.finishAuth.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finishExchange = resolve
        }),
    )
    const reauthorizing = mocked.reauthorize!()
    await vi.waitFor(() => expect(finishExchange).toBeDefined())
    expect(mocked.completeAuthorization).not.toHaveBeenCalled()
    expect(mocked.useAuthorizationState).toHaveBeenCalledWith('mid-session-state')
    expect(mocked.finishAuth).toHaveBeenCalledWith('mid-session-code', 'https://issuer.example.com')
    finishExchange()
    await reauthorizing
    expect(mocked.completeAuthorization).toHaveBeenCalledExactlyOnceWith(true)
  })

  it('fails the browser response when the mid-session exchange rejects', async () => {
    mocked.finishAuth.mockRejectedValue(new Error('invalid grant'))
    await expect(mocked.reauthorize!()).rejects.toThrow('invalid grant')
    expect(mocked.completeAuthorization).toHaveBeenCalledExactlyOnceWith(false)
  })

  it('fails the browser response when state validation rejects', async () => {
    mocked.useAuthorizationState.mockImplementation(() => {
      throw new Error('invalid state')
    })
    await expect(mocked.reauthorize!()).rejects.toThrow('invalid state')
    expect(mocked.finishAuth).not.toHaveBeenCalled()
    expect(mocked.completeAuthorization).toHaveBeenCalledExactlyOnceWith(false)
  })

  it('fails the browser response if the active transport cannot exchange a code', async () => {
    delete mocked.remoteTransport.finishAuth
    await expect(mocked.reauthorize!()).rejects.toThrow('cannot complete an authorization')
    expect(mocked.completeAuthorization).toHaveBeenCalledExactlyOnceWith(false)
  })

  it('leaves follower authentication to the owner without waiting for a code', async () => {
    const waitForAuthCode = vi.fn()
    mocked.initializeAuth.mockResolvedValue({ actualPort: 3600, server: {}, skipBrowserAuth: true, waitForAuthCode })
    await mocked.reauthorize!()
    expect(waitForAuthCode).not.toHaveBeenCalled()
    expect(mocked.completeAuthorization).not.toHaveBeenCalled()
  })
})
