import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import PgClient from 'serverless-postgres';
import { setupDb } from '../db/setup';
import { getLogger } from '@/util/logger.util';
import { getPgClient } from '@/lib/postgres';
import { teardownDb } from '../db/teardown';

const logger = getLogger('test');

describe('/users', () => {
  let pgClient: PgClient;
  let apiKey: string;
  let publicKey: string;

  beforeAll(async () => {
    pgClient = await getPgClient();

    const credentials = await setupDb(logger, pgClient);

    apiKey = credentials.apiKey;
    publicKey = credentials.publicKey;
  });

  afterAll(async () => {
    await teardownDb(logger, pgClient);
    await pgClient.clean();
  });

  describe('POST /users/create', () => {
    it('should create a new user', async () => {
      const body = {
        email: 'test@test.com',
        password: 'password'
      };

      const headers = {
        'X-Ds-Public-Key': publicKey
      };

      const response = await fetch('http://localhost:40060/dev/users/create', {
        method: 'POST',
        headers,
        body: JSON.stringify(body)
      });

      const data = await response.json();

      expect(response.status).toBe(200);
    });
  });

  describe('GET /users/id', () => {
    it('should return a user by id', async () => {
      const response = await fetch('http://localhost:40060/dev/users/id');
      const data = await response.json();

      expect(response.status).toBe(401);
    });
  });

  describe('GET /users/me', () => {
    it('should return the current user', async () => {
      const response = await fetch('http://localhost:40060/dev/users/me');
      const data = await response.json();

      expect(response.status).toBe(401);
    });
  });

  describe('GET /users/session', () => {
    it('should return the current user session', async () => {
      const response = await fetch('http://localhost:40060/dev/users/session');
      const data = await response.json();

      expect(response.status).toBe(401);
    });
  });
});
