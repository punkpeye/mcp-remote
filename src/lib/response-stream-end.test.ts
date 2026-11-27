import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { StreamableHTTPClientTransport, type Transport } from '@modelcontextprotocol/client'
import { mcpProxy } from './utils'

const serverUrl = 'https://mcp.example.test/mcp'

const toolsListResult = { tools: [{ name: 'echo', inputSchema: { type: 'object' } }] }

/** How the server's answer to `tools/list` arrives on the stream its POST opened. */
type StreamEnding = 'answered' | 'closed' | 'broken'

/**
 * A streamable HTTP server that answers every request on an SSE stream, the way servers do that
 * hold the POST open while they work. What happens to the `tools/list` stream is up to the test.
 */
const fakeServer = (ending: StreamEnding) => {
  const encoder = new TextEncoder()
  return (async (input, init) => {
    const request = new Request(input, init)
    // No stream of its own for server-initiated messages
    if (request.method !== 'POST') return new Response(null, { status: 405 })
    const message = (await request.json()) as { id?: number; method: string }
    if (message.id === undefined) return new Response(null, { status: 202 })

    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        if (ending === 'answered') {
          const answer = { jsonrpc: '2.0', id: message.id, result: toolsListResult }
          controller.enqueue(encoder.encode(`event: message\ndata: ${JSON.stringify(answer)}\n\n`))
          controller.close()
        } else if (ending === 'closed') {
          controller.close()
        } else {
          // What undici reports when the connection under a response body goes away
          controller.error(new TypeError('terminated'))
        }
      },
    })
    return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
  }) as typeof fetch
}

describe('Feature: A response stream that ends without the answer', () => {
  let transport: StreamableHTTPClientTransport
  let clientTransport: Transport
  let sendToClient: ReturnType<typeof vi.fn>

  const connect = async (ending: StreamEnding) => {
    transport = new StreamableHTTPClientTransport(new URL(serverUrl), { fetch: fakeServer(ending) })
    await transport.start()
    sendToClient = vi.fn().mockResolvedValue(undefined)
    clientTransport = {
      send: sendToClient,
      start: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
    } as unknown as Transport
    mcpProxy({ transportToClient: clientTransport, transportToServer: transport })
  }

  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(async () => {
    await transport.close()
    vi.restoreAllMocks()
  })

  it('Scenario: a stream cut off before the answer fails the request', async () => {
    // Given a server whose connection drops while the client waits for its tool list
    await connect('broken')

    // When the client asks for the tool list
    clientTransport.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/list' } as never)

    // Then the client is told the request failed, instead of waiting on it forever
    await vi.waitFor(() => expect(sendToClient).toHaveBeenCalled(), { timeout: 2000 })
    expect(sendToClient).toHaveBeenCalledWith(
      expect.objectContaining({ jsonrpc: '2.0', id: 1, error: expect.objectContaining({ code: -32001 }) }),
    )
  })

  it('Scenario: a stream the server closes without the answer fails the request', async () => {
    // Given a server that ends the stream without ever answering
    await connect('closed')

    // When the client asks for the tool list
    clientTransport.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/list' } as never)

    // Then the client is told the request failed
    await vi.waitFor(() => expect(sendToClient).toHaveBeenCalled(), { timeout: 2000 })
    expect(sendToClient).toHaveBeenCalledWith(
      expect.objectContaining({ jsonrpc: '2.0', id: 1, error: expect.objectContaining({ code: -32001 }) }),
    )
  })

  it('Scenario: a stream that carries the answer before it ends is answered once', async () => {
    // Given a server that answers on the stream and then ends it
    await connect('answered')

    // When the client asks for the tool list
    clientTransport.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/list' } as never)

    // Then the client gets the tool list
    await vi.waitFor(() => expect(sendToClient).toHaveBeenCalled(), { timeout: 2000 })
    expect(sendToClient).toHaveBeenCalledWith(expect.objectContaining({ jsonrpc: '2.0', id: 1, result: toolsListResult }))

    // And the end of the stream that follows does not answer it a second time
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(sendToClient).toHaveBeenCalledTimes(1)
  })
})
