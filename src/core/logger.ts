/**
 * JSON-lines logger that writes to STDERR only. In stdio mode STDOUT *is* the MCP protocol
 * channel; a single stray console.log would corrupt the agent's JSON-RPC stream.
 */
export interface Logger {
  debug(msg: string, data?: Record<string, unknown>): void;
  info(msg: string, data?: Record<string, unknown>): void;
  warn(msg: string, data?: Record<string, unknown>): void;
  error(msg: string, data?: Record<string, unknown>): void;
}

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 } as const;
type Level = keyof typeof LEVELS;

function serializable(data: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!data) return undefined;
  return Object.fromEntries(Object.entries(data).map(([k, v]) => [k, v instanceof Error ? { name: v.name, message: v.message } : v]));
}

export function createLogger(minLevel: Level = (process.env['MCP_FW_LOG_LEVEL'] as Level | undefined) ?? 'info'): Logger {
  const write = (level: Level, msg: string, data?: Record<string, unknown>) => {
    if (LEVELS[level] < LEVELS[minLevel]) return;
    process.stderr.write(`${JSON.stringify({ t: new Date().toISOString(), level, msg, ...serializable(data) })}\n`);
  };
  return {
    debug: (m, d) => write('debug', m, d),
    info: (m, d) => write('info', m, d),
    warn: (m, d) => write('warn', m, d),
    error: (m, d) => write('error', m, d),
  };
}
