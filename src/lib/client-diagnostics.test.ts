import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Server } from '@modelcontextprotocol/server'
import { Client, InMemoryTransport } from '@modelcontextprotocol/client'
import { attachClientDiagnostics } from './client-diagnostics'

const TOOLS = [{ name: 'search', description: 'Search', inputSchema: { type: 'object' as const } }]

/** A client and server talking over a linked in-memory pair, connected the way the CLI connects them. */
async function connectedPair() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()

  const server = new Server({ name: 'stub', version: '1.0.0' }, { capabilities: { tools: {} } })
  server.setRequestHandler('tools/list', async () => ({ tools: TOOLS }))
  await server.connect(serverTransport)

  const client = new Client({ name: 'mcp-remote', version: '0.0.0' }, { capabilities: {} })
  await client.connect(clientTransport)

  return { client, server, clientTransport }
}

describe('Feature: Client diagnostics', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('Scenario: A request still resolves once the diagnostics are attached', async () => {
    // Given a connected client
    const { client, clientTransport } = await connectedPair()

    // When the diagnostics are attached after the connection is established
    attachClientDiagnostics(client, clientTransport, () => {})

    // Then a request still settles, rather than waiting out the SDK's request timeout
    const tools = await client.request({ method: 'tools/list' })
    expect(tools.tools.map((tool) => tool.name)).toEqual(['search'])

    await client.close()
  })

  it('Scenario: Received messages are logged', async () => {
    // Given a connected client with diagnostics attached
    const { client, clientTransport } = await connectedPair()
    attachClientDiagnostics(client, clientTransport, () => {})

    // When a request is answered
    await client.request({ method: 'tools/list' })

    // Then the response was narrated as well as delivered
    const logged = vi.mocked(console.error).mock.calls.map((call) => call.join(' '))
    expect(logged.some((line) => line.includes('Received message:') && line.includes('search'))).toBe(true)

    await client.close()
  })

  it('Scenario: Closing the connection reports it once', async () => {
    // Given a connected client with diagnostics attached
    const { client, server, clientTransport } = await connectedPair()
    const onClose = vi.fn()
    attachClientDiagnostics(client, clientTransport, onClose)

    // When the other end goes away
    await server.close()
    await new Promise((resolve) => setTimeout(resolve, 10))

    // Then the caller is told exactly once
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
