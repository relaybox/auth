import { RedisClientType, createClient as createRedisClient } from 'redis';

let connection: RedisClientType;

interface RedisOptions {
  host: string;
  port: number;
}

function reconnectStrategy(retries: number) {
  return Math.min(retries * 50, 1000);
}

export function createClient({ host, port }: RedisOptions) {
  if (connection) {
    return connection;
  }

  connection = createRedisClient({
    socket: {
      host,
      port,
      reconnectStrategy
    }
  });

  connection.on('error', (err: any) => {
    console.log(err);
  });

  return connection;
}
