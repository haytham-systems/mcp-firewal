import { spawn } from 'node:child_process';
import mysql, { type Pool, type PoolConnection } from 'mysql2/promise';
import { fileURLToPath } from 'node:url';

export type { Pool };

export function createPool(uri: string, connectionLimit = 16): Pool {
  return mysql.createPool({
    uri,
    connectionLimit,
    timezone: 'Z',            // DATETIME is UTC end-to-end; audit hashes cover ISO-UTC timestamps
    supportBigNumbers: true,
    enableKeepAlive: true,
    waitForConnections: true,
    queueLimit: 500,
  });
}

export const toMysqlDatetime = (d: Date): string => d.toISOString().slice(0, 23).replace('T', ' ');

export const isDupKey = (e: unknown): boolean =>
  typeof e === 'object' && e !== null && (e as { code?: string }).code === 'ER_DUP_ENTRY';

export async function withTx<T>(pool: Pool, fn: (c: PoolConnection) => Promise<T>): Promise<T> {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const out = await fn(conn);
    await conn.commit();
    return out;
  } catch (err) {
    await conn.rollback().catch(() => undefined);
    throw err;
  } finally {
    conn.release();
  }
}

/** Runs pending Sequelize CLI migrations. */
export async function migrate(uri: string): Promise<void> {
  const projectRoot = fileURLToPath(new URL('../../', import.meta.url));
  const sequelizeCli = fileURLToPath(new URL('../../node_modules/sequelize-cli/lib/sequelize', import.meta.url));
  await new Promise<void>((resolve, reject) => {
    const child = spawn(process.execPath, [sequelizeCli, 'db:migrate'], {
      cwd: projectRoot,
      env: { ...process.env, MCP_FW_DATABASE_URL: uri },
      stdio: 'inherit',
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`sequelize-cli db:migrate failed${signal ? ` with signal ${signal}` : ` with exit code ${code}`}`));
    });
  });
}
