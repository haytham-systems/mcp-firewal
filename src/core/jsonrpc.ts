import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

export type { JSONRPCMessage };
export type RpcId = string | number;

export interface RpcRequest { jsonrpc: '2.0'; id: RpcId; method: string; params?: Record<string, unknown> }
export interface RpcResponse { jsonrpc: '2.0'; id: RpcId; result: Record<string, unknown> }
export interface RpcErrorResponse { jsonrpc: '2.0'; id: RpcId; error: { code: number; message: string; data?: unknown } }

export const isRequest = (m: JSONRPCMessage): m is JSONRPCMessage & RpcRequest =>
  'method' in m && 'id' in m && m.id !== undefined && m.id !== null;
export const isNotification = (m: JSONRPCMessage): boolean => 'method' in m && !('id' in m && m.id !== undefined);
export const isResponse = (m: JSONRPCMessage): m is JSONRPCMessage & (RpcResponse | RpcErrorResponse) =>
  !('method' in m) && 'id' in m && ('result' in m || 'error' in m);

/**
 * Strict shape of `tools/call` params. Anything the firewall cannot parse is rejected rather
 * than forwarded: an unparseable call is either a client bug or an evasion attempt.
 */
export const ToolCallParamsSchema = z.object({
  name: z.string().min(1).max(128).regex(/^[A-Za-z0-9_.:/-]+$/, 'tool name contains disallowed characters'),
  arguments: z.record(z.string(), z.unknown()).optional().default({}),
  _meta: z.record(z.string(), z.unknown()).optional(),
}).loose();
export type ToolCallParams = z.infer<typeof ToolCallParamsSchema>;

export const JSONRPC_INVALID_PARAMS = -32602;
export const JSONRPC_INTERNAL_ERROR = -32603;

export function errorResponse(id: RpcId, code: number, message: string, data?: unknown): JSONRPCMessage {
  return { jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } } as JSONRPCMessage;
}

/**
 * Firewall verdicts on tools/call are returned as *tool results* with isError=true (not JSON-RPC
 * errors), so the model sees the refusal in-band and can explain it instead of crashing the loop.
 */
export function toolErrorResult(id: RpcId, text: string, structured: Record<string, unknown>): JSONRPCMessage {
  return {
    jsonrpc: '2.0',
    id,
    result: { isError: true, content: [{ type: 'text', text }], structuredContent: { firewall: structured } },
  } as JSONRPCMessage;
}
