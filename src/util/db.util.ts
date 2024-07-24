import PgClient from 'serverless-postgres';
import { LogLevel } from 'src/types/system.types';

const RDS_ROOT_CERTIFICATE = process.env.RDS_ROOT_CERTIFICATE || '';
const DB_PROXY_ENABLED = process.env.DB_PROXY_ENABLED === 'true';
const DB_TLS_DISABLED = process.env.DB_TLS_DISABLED === 'true';
const LOG_LEVEL = process.env.LOG_LEVEL;

/*********************** SERVERLESS PG *************************/

const ssl = {
  rejectUnauthorized: true,
  ...(!DB_PROXY_ENABLED && { ca: RDS_ROOT_CERTIFICATE })
};

export const client = new PgClient({
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  debug: LOG_LEVEL === LogLevel.DEBUG,
  maxConnections: Number(process.env.DB_MAX_CONNECTIONS),
  delayMs: 3000,
  ...(!DB_TLS_DISABLED && ssl)
});

export async function getConnection(): Promise<PgClient> {
  await client.connect();
  return client;
}
