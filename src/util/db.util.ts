import { QueryArrayResult, QueryResult } from 'pg';
import PgClient from 'serverless-postgres';
import { LogLevel } from 'src/types/system.types';

const TLS_DISABLED = process.env.TLS_DISABLED === 'true';
const LOG_LEVEL = process.env.LOG_LEVEL;

/*********************** SERVERLESS PG *************************/

export const client = new PgClient({
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  debug: LOG_LEVEL === LogLevel.DEBUG,
  maxConnections: Number(process.env.DB_MAX_CONNECTIONS),
  delayMs: 3000,
  ...(!TLS_DISABLED && {
    ssl: {
      rejectUnauthorized: false
    }
  })
});

export async function getConnection(): Promise<PgClient> {
  await client.connect();
  return client;
}
