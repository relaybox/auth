import { RedisClientType } from 'redis';
import { KeyPrefix, KeySuffix } from 'src/types/cache.types';

const SECRET_KEY_CACHE_TTL = 300; // 5 mins

/**
 * Retrieves a cached secret key associated with an app key from Redis.
 *
 * @param {string} appPid - The application key to query the secret key for.
 * @returns {Promise<string | null>} The secret key if it exists, otherwise null.
 */
export function getCachedSecretKey(
  redisClient: RedisClientType,
  appPid: string
): Promise<string | null> {
  return redisClient.get(`${KeyPrefix.APPLICATION}:${appPid}:${KeySuffix.SECRET}`);
}

/**
 * Caches a secret key in Redis associated with an app key, with a set expiration time.
 *
 * @param {string} appPid - The app key corresponding to the secret key.
 * @param {string} secretKey - The secret key to cache.
 * @returns {Promise<string | null>} The result of the Redis SET operation, null if unsuccessful.
 */
export function setCachedSecretKey(
  redisClient: RedisClientType,
  appPid: string,
  secretKey: string
): Promise<string | null> {
  return redisClient.set(`${KeyPrefix.APPLICATION}:${appPid}:${KeySuffix.SECRET}`, secretKey, {
    NX: true,
    EX: SECRET_KEY_CACHE_TTL
  });
}
