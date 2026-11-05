import { readFile } from 'node:fs/promises';
import mysql, { type Pool, type PoolConnection } from 'mysql2/promise';

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

/** Applies sql/schema.sql (idempotent). */
export async function migrate(uri: string): Promise<void> {
  const sql = await readFile(new URL('../../sql/schema.sql', import.meta.url), 'utf8');
  const conn = await mysql.createConnection({ uri, multipleStatements: true });
  try {
    await conn.query(sql);
  } finally {
    await conn.end();
  }
}
