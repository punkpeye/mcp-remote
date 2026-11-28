import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { StreamableHTTPClientTransport, type Transport } from '@modelcontextprotocol/client'
import { mcpProxy } from './utils'

const serverUrl = 'https://mcp.example.test/mcp'

const toolsListResult = { tools: [{ name: 'echo', inputSchema: { type: 'object' } }] }

type Rpc = { jsonrpc: '2.0'; id?: number | string; method?: string }

const encoder = new TextEncoder()
const sseEvent = (fields: string) => encoder.encode(fields + '\n\n')

/** An SSE response whose stream the test ends when, and however, it chooses. */
const heldStream = () => {
  let controller!: ReadableStreamDefaultController<Uint8Array>
  const body = new ReadableStream<Uint8Array>({ start: (c) => void (controller = c) })
  return {
    response: new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } }),
    answer: (id: Rpc['id'], result: unknown) =>
      controller.enqueue(sseEvent(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id, result })}`)),
    /** An event with an id and no data, which makes the stream one the client may resume. */
    prime: (eventId: string) => controller.enqueue(sseEvent(`id: ${eventId}\ndata:`)),
    close: () => controller.close(),
    // What undici reports when the connection under a response body goes away
    cut: () => controller.error(new TypeError('terminated')),
  }
}

const jsonAnswer = (id: Rpc['id'], result: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), { status: 200, headers: { 'content-type': 'application/json', ...headers } })

/**
 * A streamable HTTP server whose requests are answered by the test. Notifications are accepted and
 * there is no stream for server-initiated messages, which is all the proxy needs besides.
 */
const fakeServer = (answer: (message: Rpc, request: Request) => Response | Promise<Response>) =>
  (async (input, init) => {
    const request = new Request(input, init)
    if (request.method !== 'POST') return new Response(null, { status: 405 })
    const message = (await request.json()) as Rpc
    if (message.id === undefined) return new Response(null, { status: 202 })
    return await answer(message, request)
  }) as typeof fetch

describe('Feature: A response stream that ends without the answer', () => {
  let transport: StreamableHTTPClientTransport | undefined
  let clientTransport: Transport
  let sendToClient: ReturnType<typeof vi.fn>
  /** Requests whose stream the SDK has reported ended, in the order it did. */
  let streamsEnded: Rpc[]

  const connect = (answer: Parameters<typeof fakeServer>[0], options: { reconnectQuickly?: boolean } = {}) => {
    transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
      fetch: fakeServer(answer),
      ...(options.reconnectQuickly
        ? { reconnectionOptions: { initialReconnectionDelay: 1, maxReconnectionDelay: 1, reconnectionDelayGrowFactor: 1, maxRetries: 2 } }
        : {}),
    })
    // Records when the SDK reports a stream's end, so a test can wait for that rather than a clock
    const send = transport.send.bind(transport)
    transport.send = (message, sendOptions) =>
      send(
        message,
        sendOptions?.onRequestStreamEnd
          ? {
              ...sendOptions,
              onRequestStreamEnd: () => {
                streamsEnded.push(message as Rpc)
                sendOptions.onRequestStreamEnd!()
              },
            }
          : sendOptions,
      )
    sendToClient = vi.fn().mockResolvedValue(undefined)
    clientTransport = {
      send: sendToClient,
      start: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
    } as unknown as Transport
    mcpProxy({ transportToClient: clientTransport, transportToServer: transport })
  }

  const fromClient = (message: object) => clientTransport.onmessage!({ jsonrpc: '2.0', ...message } as never)
  const answersTo = (id: Rpc['id']) => sendToClient.mock.calls.map(([message]) => message).filter((message) => message.id === id)

  beforeEach(async () => {
    streamsEnded = []
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(async () => {
    await transport?.close()
    transport = undefined
    vi.restoreAllMocks()
  })

  it('Scenario: a stream cut off before the answer fails the request', async () => {
    // Given a server whose connection drops while the client waits for its tool list
    connect(() => {
      const stream = heldStream()
      queueMicrotask(stream.cut)
      return stream.response
    })

    // When the client asks for the tool list
    fromClient({ id: 1, method: 'tools/list' })

    // Then the client is told the request failed, once, instead of waiting on it forever
    await vi.waitFor(() => expect(streamsEnded).toHaveLength(1))
    expect(answersTo(1)).toEqual([expect.objectContaining({ error: expect.objectContaining({ code: -32001 }) })])
  })

  it('Scenario: a stream the server closes without the answer fails the request', async () => {
    // Given a server that ends the stream without ever answering
    connect(() => {
      const stream = heldStream()
      queueMicrotask(stream.close)
      return stream.response
    })

    // When the client asks for the tool list
    fromClient({ id: 1, method: 'tools/list' })

    // Then the client is told the request failed, once
    await vi.waitFor(() => expect(streamsEnded).toHaveLength(1))
    expect(answersTo(1)).toEqual([expect.objectContaining({ error: expect.objectContaining({ code: -32001 }) })])
  })

  it('Scenario: a stream that carries the answer before it ends is answered once', async () => {
    // Given a server that answers on the stream and then ends it
    connect((message) => {
      const stream = heldStream()
      queueMicrotask(() => {
        stream.answer(message.id, toolsListResult)
        stream.close()
      })
      return stream.response
    })

    // When the client asks for the tool list
    fromClient({ id: 1, method: 'tools/list' })

    // Then the client gets the tool list, and the end of the stream does not answer it again
    await vi.waitFor(() => expect(streamsEnded).toHaveLength(1))
    expect(answersTo(1)).toEqual([expect.objectContaining({ result: toolsListResult })])
  })

  it('Scenario: a resumable stream fails the request once it cannot be resumed', async () => {
    // Given a server whose stream can be resumed, but which ends it and then refuses to resume it
    connect(
      () => {
        const stream = heldStream()
        queueMicrotask(() => {
          stream.prime('event-1')
          stream.close()
        })
        return stream.response
      },
      { reconnectQuickly: true },
    )

    // When the client asks for the tool list
    fromClient({ id: 1, method: 'tools/list' })

    // Then the client is told the request failed once resuming is given up
    await vi.waitFor(() => expect(streamsEnded).toHaveLength(1))
    expect(answersTo(1)).toEqual([expect.objectContaining({ error: expect.objectContaining({ code: -32001 }) })])
  })

  it('Scenario: the end of an answered stream does not fail a later request that reuses its id', async () => {
    // Given a server that answers the first request but keeps its stream open a while longer, and
    // takes its time over the next one
    const streams: ReturnType<typeof heldStream>[] = []
    connect((message) => {
      const stream = heldStream()
      streams.push(stream)
      if (streams.length === 1) queueMicrotask(() => stream.answer(message.id, { ...toolsListResult, attempt: 1 }))
      return stream.response
    })
    fromClient({ id: 1, method: 'tools/list' })
    await vi.waitFor(() => expect(answersTo(1)).toHaveLength(1))

    // When the client reuses the id for its next request, and the first stream ends while that
    // request is still waiting on its answer
    fromClient({ id: 1, method: 'tools/list' })
    await vi.waitFor(() => expect(streams).toHaveLength(2))
    streams[0]!.close()
    await vi.waitFor(() => expect(streamsEnded).toHaveLength(1))
    streams[1]!.answer(1, { ...toolsListResult, attempt: 2 })
    streams[1]!.close()
    await vi.waitFor(() => expect(streamsEnded).toHaveLength(2))

    // Then each request is answered once, by the server, and nothing fails the second one
    expect(answersTo(1)).toEqual([
      expect.objectContaining({ result: { ...toolsListResult, attempt: 1 } }),
      expect.objectContaining({ result: { ...toolsListResult, attempt: 2 } }),
    ])
  })

  it('Scenario: a request the client cancelled is not failed when its stream ends', async () => {
    // Given a server still working on a request whose stream it keeps open
    const streams: ReturnType<typeof heldStream>[] = []
    const cancelled = vi.fn()
    connect(() => {
      const stream = heldStream()
      streams.push(stream)
      return stream.response
    })
    transport!.send = ((send) => (message, options) => {
      if ((message as Rpc).method === 'notifications/cancelled') cancelled()
      return send(message, options)
    })(transport!.send)
    fromClient({ id: 1, method: 'tools/list' })
    await vi.waitFor(() => expect(streams).toHaveLength(1))

    // When the client cancels it, and the server then ends the stream without an answer
    fromClient({ method: 'notifications/cancelled', params: { requestId: 1 } })
    await vi.waitFor(() => expect(cancelled).toHaveBeenCalled())
    streams[0]!.close()
    await vi.waitFor(() => expect(streamsEnded).toHaveLength(1))

    // Then the client, which has stopped waiting, is not sent an answer it can match to nothing
    expect(answersTo(1)).toEqual([])
  })

  it('Scenario: the retry after an expired session fails if its stream ends without the answer', async () => {
    // Given a session the server has expired, whose replacement then drops the retried request
    let sessions = 0
    let listsSeen = 0
    connect((message) => {
      if (message.method === 'initialize') {
        sessions++
        return jsonAnswer(
          message.id,
          { protocolVersion: '2025-11-25', capabilities: {}, serverInfo: { name: 'test', version: '1' } },
          {
            'mcp-session-id': `session-${sessions}`,
          },
        )
      }
      listsSeen++
      if (listsSeen === 1) return new Response('session expired', { status: 404 })
      const stream = heldStream()
      queueMicrotask(stream.cut)
      return stream.response
    })
    fromClient({
      id: 0,
      method: 'initialize',
      params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'host', version: '1' } },
    })
    await vi.waitFor(() => expect(answersTo(0)).toHaveLength(1))
    fromClient({ method: 'notifications/initialized' })

    // When the client asks for the tool list
    fromClient({ id: 1, method: 'tools/list' })

    // Then the session is re-established and the request retried there
    await vi.waitFor(() => expect(streamsEnded.filter((message) => message.id === 1)).toHaveLength(1))
    expect(sessions).toBe(2)

    // And the client is told the retry failed, once, instead of waiting on it forever
    expect(answersTo(1)).toEqual([expect.objectContaining({ error: expect.objectContaining({ code: -32001 }) })])
  })
})
