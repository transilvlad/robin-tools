import pg from 'pg';
import { config } from '../config.js';
import { logger } from '../logger.js';

const { Pool } = pg;

export const pool = new Pool({
  host: config.postgres.host,
  port: config.postgres.port,
  database: config.postgres.database,
  user: config.postgres.user,
  password: config.postgres.password,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  logger.error('Unexpected database pool error', { error: err.message });
});

export async function query<T extends pg.QueryResultRow>(
  text: string,
  params?: unknown[]
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params);
}

export async function testConnection(): Promise<boolean> {
  try {
    await query('SELECT 1');
    return true;
  } catch (error) {
    logger.error('Database connection failed', { error: (error as Error).message });
    return false;
  }
}

export async function closePool(): Promise<void> {
  await pool.end();
}
