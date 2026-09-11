import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { createMcpHandler, inputRequired, McpServer } from '@modelcontextprotocol/server'
import * as z from 'zod/v4'
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'
import { Client } from '@modelcontextprotocol/client'
import { fileURLToPath } from 'node:url'
import { dirname, resolve as resolvePath } from 'node:path'
import { createMCPClient, listTools } from './utils.js'
import type { MCPClient } from './utils.js'

/**
 * The failure from https://github.com/punkpeye/mcp-remote/issues/356, reproduced against a real
 * 2026-07-28 server rather than a mock.
 *
 * `legacy: 'reject'` is what makes this the reporter's situation: the server serves the modern era
 * only, so the `initialize` a desktop host still sends has nothing to answer it. The spec's
 * compatibility matrix calls that pair a failure with no fall-forward, and names the fix - a
 * dual-era client - which is what `--protocol auto` turns this proxy into.
 */
describe('bridging a legacy stdio client to a 2026-07-28 server', () => {
  let httpServer: Server
  let modernHandler: ReturnType<typeof createMcpHandler>
  let serverUrl: string
  let client: MCPClient | null = null

  beforeAll(async () => {
    const handler = createMcpHandler(
      ({ era }) => {
        const server = new McpServer({ name: 'modern-only', version: '1.0.0' })
        server.registerTool(
          'echo_era',
          { description: 'Reports the era it was called in', inputSchema: z.object({ text: z.string() }) },
          async ({ text }) => ({ content: [{ type: 'text', text: `${text} (${era} era)` }] }),
        )
        server.registerTool('needs_input', { description: 'Asks the client something first' }, async (ctx: any) => {
          const answered = ctx?.mcpReq?.inputResponses?.ask
          if (answered) return { content: [{ type: 'text', text: `answered: ${answered.content?.text}` }] }
          return inputRequired({
            inputRequests: { ask: { method: 'sampling/createMessage', params: { messages: [], maxTokens: 16 } } as any },
            requestState: 'st-1',
          })
        })
        return server
      },
      // The whole point: no 2025-era traffic is served at all
      { legacy: 'reject' },
    )
    modernHandler = handler

    httpServer = createServer(async (req, res) => {
      const chunks: Buffer[] = []
      for await (const chunk of req) chunks.push(chunk as Buffer)
      const request = new Request(`http://${req.headers.host}${req.url}`, {
        method: req.method,
        headers: req.headers as Record<string, string>,
        body: chunks.length ? Buffer.concat(chunks) : undefined,
      })

      const response = await handler.fetch(request)
      const headers: Record<string, string> = {}
      response.headers.forEach((value, key) => {
        headers[key] = value
      })
      res.writeHead(response.status, headers)
      if (response.body) {
        for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) res.write(chunk)
      }
      res.end()
    })

    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve))
    serverUrl = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}/mcp`
  })

  afterAll(async () => {
    if (client) await client.cleanup()
    await new Promise<void>((resolve) => httpServer.close(() => resolve()))
  })

  it('fails without the bridge, the way the issue reported it', async () => {
    // Given the default: the handshake goes straight through to a server that retired it
    // The proxy gives up and exits, so the stdio client watching it sees the pipe go
    await expect(createMCPClient(serverUrl, ['--transport', 'http-only'])).rejects.toThrow('Connection closed')
  }, 40000)

  it('connects, lists and calls through the bridge', async () => {
    // When the proxy is allowed to look for a modern server first
    client = await createMCPClient(serverUrl, ['--transport', 'http-only', '--protocol', 'auto'])

    // Then the legacy client gets the handshake it expects, answered from server/discover
    const tools = await listTools(client.client)
    expect(tools.map((tool) => tool.name)).toContain('echo_era')

    // And the tool call reaches the server written in the era the server actually speaks
    const result: any = await client.client.callTool({ name: 'echo_era', arguments: { text: 'hello' } })
    expect(result.content[0].text).toBe('hello (modern era)')
  }, 40000)

  it('delivers a change notification the client never subscribed for', async () => {
    const subscriber = await createMCPClient(serverUrl, ['--transport', 'http-only', '--protocol', 'auto'])
    try {
      const seen: string[] = []
      subscriber.client.setNotificationHandler('notifications/tools/list_changed' as any, async () => {
        seen.push('tools')
      })

      // A 2025-era client never opens a subscriptions/listen stream, so without the bridge this
      // notification has nowhere to go
      await new Promise((settle) => setTimeout(settle, 500))
      modernHandler.notify.toolsChanged()

      await vi.waitFor(() => expect(seen).toEqual(['tools']), { timeout: 10000 })
    } finally {
      await subscriber.cleanup()
    }
  }, 40000)

  it('answers a mid-request question and completes the call', async () => {
    // A client that can answer sampling, which is what the server asks for mid-request
    const transport = new StdioClientTransport({
      command: 'node',
      args: [
        resolvePath(dirname(fileURLToPath(import.meta.url)), '../dist/proxy.js'),
        serverUrl,
        '--transport',
        'http-only',
        '--protocol',
        'auto',
      ],
      env: process.env as Record<string, string>,
    })
    const sampling = new Client({ name: 'sampling-host', version: '1.0.0' }, { capabilities: { sampling: {} } })
    sampling.setRequestHandler('sampling/createMessage' as any, async () => ({
      role: 'assistant',
      content: { type: 'text', text: 'from-client' },
      model: 'test-model',
    }))

    await sampling.connect(transport)
    try {
      const result: any = await sampling.callTool({ name: 'needs_input', arguments: {} })
      expect(result.content[0].text).toBe('answered: from-client')
    } finally {
      await sampling.close()
    }
  }, 40000)
})
