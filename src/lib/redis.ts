import { getLogger } from '@/util/logger.util';

const logger = getLogger('redis');

const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = process.env.REDIS_PORT;
const REDIS_AUTH_TOKEN = process.env.REDIS_AUTH_TOKEN;
const REDIS_TLS_DISABLED = process.env.REDIS_TLS_DISABLED === 'true';
// const REDIS_AUTH_TOKEN = getRedisAuthToken();

const tlsConnectionOptions = {
  tls: true,
  rejectUnauthorized: true
};

const tlsConnectionOptionsIo = {
  password: REDIS_AUTH_TOKEN,
  tls: tlsConnectionOptions
};

// function getRedisAuthToken(): string {
//   if (!REDIS_AUTH) {
//     logger.warn('Redis auth token for TLS connection not defined');
//     return '';
//   }

//   return JSON.parse(REDIS_AUTH).authToken;
// }

export const connectionOptionsIo = {
  host: REDIS_HOST!,
  port: Number(REDIS_PORT)!,
  ...(!REDIS_TLS_DISABLED && tlsConnectionOptionsIo)
};
