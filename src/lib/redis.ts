const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = process.env.REDIS_PORT;
const REDIS_AUTH_TOKEN = process.env.REDIS_AUTH_TOKEN;
const REDIS_TLS_DISABLED = process.env.REDIS_TLS_DISABLED === 'true';

const tlsConnectionOptions = {
  tls: true,
  rejectUnauthorized: true
};

const tlsConnectionOptionsIo = {
  password: REDIS_AUTH_TOKEN,
  tls: tlsConnectionOptions
};

export const connectionOptionsIo = {
  host: REDIS_HOST!,
  port: Number(REDIS_PORT)!,
  ...(!REDIS_TLS_DISABLED && tlsConnectionOptionsIo)
};
