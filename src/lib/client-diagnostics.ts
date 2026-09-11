import type { Client, Transport } from '@modelcontextprotocol/client'
import { log } from './utils'

/**
 * Makes a connected client narrate what it receives, without breaking what it receives it with.
 *
 * `client.connect()` installs the handler that settles `client.request()` on `transport.onmessage`,
 * so assigning a logger there afterwards silently removes it: responses still arrive and are still
 * printed, but nothing resolves the pending request, and every call fails on the SDK's 60 second
 * timeout while the answer sits in the log (see https://github.com/geelen/mcp-remote/issues/324).
 * Delegating to the handler that is already there keeps both.
 *
 * Errors and closes need no such care - `Protocol` exposes hooks of its own for those, and using
 * them leaves its transport wiring alone.
 *
 * @param client The connected client
 * @param transport The transport it was connected with
 * @param onClose Called after the connection closes and the client has been told
 */
export function attachClientDiagnostics(client: Client, transport: Transport, onClose: () => void): void {
  const dispatch = transport.onmessage
  transport.onmessage = (message, extra) => {
    log('Received message:', JSON.stringify(message, null, 2))
    dispatch?.(message, extra)
  }

  client.onerror = (error) => {
    log('Transport error:', error)
  }

  client.onclose = () => {
    log('Connection closed.')
    onClose()
  }
}
