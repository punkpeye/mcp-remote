import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'
import { Client } from '@modelcontextprotocol/client'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

export interface MCPClient {
  client: Client
  cleanup: () => Promise<void>
}

/**
 * Spawns the mcp-remote proxy and connects via stdio
 */
export async function createMCPClient(serverUrl: string, args: string[] = []): Promise<MCPClient> {
  const transport = new StdioClientTransport({
    command: 'node',
    args: [resolve(__dirname, '../dist/proxy.js'), serverUrl, ...args],
    env: process.env as Record<string, string>,
  })

  const client = new Client(
    {
      name: 'mcp-remote-test-client',
      version: '1.0.0',
    },
    {
      capabilities: {},
    },
  )

  await client.connect(transport)

  const cleanup = async () => {
    try {
      await client.close()
    } catch {
      // Ignore cleanup errors
    }
  }

  return { client, cleanup }
}

/**
 * Safely lists tools from a server, handling servers that don't support tools
 */
export async function listTools(client: Client) {
  try {
    const response = await client.request({ method: 'tools/list' })
    return response.tools || []
  } catch (err: any) {
    if (err.message?.includes('not supported') || err.code === -32601) {
      return []
    }
    throw err
  }
}
