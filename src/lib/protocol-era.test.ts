import { describe, it, expect } from 'vitest'
import {
  discoverRequest,
  readEraFromDiscoverResponse,
  stampModernMeta,
  synthesizeInitializeResult,
  translateModernResult,
} from './protocol-era'

const IDENTITY = {
  protocolVersion: '2025-11-25',
  capabilities: { roots: {} },
  clientInfo: { name: 'desktop-host', version: '0.1.0' },
}

const DISCOVER = {
  supportedVersions: ['2026-07-28'],
  capabilities: { tools: {} },
}

describe('Feature: Deciding which protocol era a server belongs to', () => {
  it('Scenario: A DiscoverResult is a modern server', () => {
    const verdict = readEraFromDiscoverResponse({ result: DISCOVER })

    expect(verdict).toMatchObject({ era: 'modern', version: '2026-07-28' })
  })

  it('Scenario: An unknown method is a server still expecting a handshake', () => {
    // -32601 is what a 2025-era server says about `server/discover`, and it is not a modern code
    const verdict = readEraFromDiscoverResponse({ error: { code: -32601 } })

    expect(verdict.era).toBe('legacy')
  })

  it('Scenario: Anything that is not a DiscoverResult is a server still expecting a handshake', () => {
    const verdict = readEraFromDiscoverResponse({ result: { tools: [] } })

    expect(verdict.era).toBe('legacy')
  })

  it('Scenario: A modern error code is a modern server, not a reason to fall back', () => {
    // The spec makes a recognised modern error the proof that a modern server answered, so falling
    // back to `initialize` here would send a handshake to a server that cannot answer one
    const verdict = readEraFromDiscoverResponse({
      error: { code: -32022, data: { supported: ['2027-01-01'] } },
    })

    expect(verdict.era).toBe('incompatible')
    expect((verdict as { reason: string }).reason).toContain('2027-01-01')
  })

  it('Scenario: A modern server offering only revisions this proxy cannot speak is reported, not bridged', () => {
    const verdict = readEraFromDiscoverResponse({ result: { ...DISCOVER, supportedVersions: ['2027-01-01'] } })

    expect(verdict.era).toBe('incompatible')
  })
})

describe('Feature: Writing requests a 2026-07-28 server will accept', () => {
  it('Scenario: Every request carries the version and capabilities the spec makes mandatory', () => {
    const stamped = stampModernMeta({ method: 'tools/list', params: {} }, IDENTITY, '2026-07-28')

    expect(stamped.params._meta).toEqual({
      'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      'io.modelcontextprotocol/clientCapabilities': { roots: {} },
      'io.modelcontextprotocol/clientInfo': { name: 'desktop-host', version: '0.1.0' },
    })
  })

  it('Scenario: Metadata the caller already set is left alone', () => {
    const stamped = stampModernMeta(
      { method: 'tools/call', params: { _meta: { progressToken: 'p1', 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } } },
      IDENTITY,
      '2026-07-28',
    )

    expect(stamped.params._meta.progressToken).toBe('p1')
  })

  it('Scenario: The probe itself is written the same way as everything after it', () => {
    // The probe is a modern request too - a server that validates `_meta` would reject it otherwise
    const request = discoverRequest('probe-1', IDENTITY)

    expect(request.method).toBe('server/discover')
    expect(request.params._meta['io.modelcontextprotocol/protocolVersion']).toBe('2026-07-28')
    expect(request.params._meta['io.modelcontextprotocol/clientCapabilities']).toEqual({ roots: {} })
  })

  it('Scenario: A client that declared no capabilities still sends the field, because it is required', () => {
    const stamped = stampModernMeta({ method: 'tools/list', params: {} }, { protocolVersion: '2025-11-25' }, '2026-07-28')

    expect(stamped.params._meta['io.modelcontextprotocol/clientCapabilities']).toEqual({})
    expect(stamped.params._meta).not.toHaveProperty('io.modelcontextprotocol/clientInfo')
  })
})

describe('Feature: Answering the handshake the modern server no longer offers', () => {
  it("Scenario: The client is told its own protocol version, not the remote server's", () => {
    const result = synthesizeInitializeResult(DISCOVER, IDENTITY)

    expect(result.protocolVersion).toBe('2025-11-25')
    expect(result.capabilities).toEqual({ tools: {} })
  })

  it('Scenario: A client asking for a version nobody knows is answered with the newest legacy one', () => {
    const result = synthesizeInitializeResult(DISCOVER, { ...IDENTITY, protocolVersion: '1999-01-01' })

    expect(result.protocolVersion).toBe('2025-11-25')
  })

  it('Scenario: The server identifies itself through the metadata it advertised', () => {
    const result = synthesizeInitializeResult(
      { ...DISCOVER, _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'cipp', version: '2.0.0' } }, instructions: 'be careful' },
      IDENTITY,
    )

    expect(result.serverInfo).toEqual({ name: 'cipp', version: '2.0.0' })
    expect(result.instructions).toBe('be careful')
  })
})

describe('Feature: Handing a modern result to a client that predates it', () => {
  it('Scenario: The result type tag is dropped, because no 2025-era client knows it', () => {
    const translated = translateModernResult({ resultType: 'complete', tools: [] })

    expect(translated).toEqual({ result: { tools: [] } })
  })

  it('Scenario: A result with no type at all is already in terms the client understands', () => {
    const translated = translateModernResult({ tools: [] })

    expect(translated).toEqual({ result: { tools: [] } })
  })

  it('Scenario: A request for more input is reported, not passed off as an answer', () => {
    // Multi-round-trip requests have no 2025 equivalent; silently forwarding one would have the
    // client read a question as a result
    const translated = translateModernResult({ resultType: 'input_required', inputRequests: [] })

    expect(translated).toMatchObject({ error: { code: -32603 } })
    expect((translated as { error: { message: string } }).error.message).toContain('multi-round-trip')
  })

  it('Scenario: A result type from a future revision is reported rather than guessed at', () => {
    const translated = translateModernResult({ resultType: 'something-new' })

    expect(translated).toMatchObject({ error: { code: -32603 } })
  })
})
