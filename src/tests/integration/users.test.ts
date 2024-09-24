import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import PgClient from 'serverless-postgres';
import { setupDb } from '../db/setup';
import { getLogger } from '@/util/logger.util';
import { getPgClient } from '@/lib/postgres';

const logger = getLogger('test');
let pgClient: PgClient;

beforeAll(async () => {
  pgClient = await getPgClient();
  await setupDb(logger, pgClient);
});

afterAll(async () => {
  await pgClient.clean();
});

describe('/users', () => {
  describe('GET /users/id', () => {
    it('should return a user by id', async () => {
      const response = await fetch('http://localhost:4006/dev/users/id');
      const data = await response.json();

      expect(response.status).toBe(401);
    });
  });

  describe('GET /users/me', () => {
    it('should return the current user', async () => {
      const response = await fetch('http://localhost:4006/dev/users/me');
      const data = await response.json();

      expect(response.status).toBe(401);
    });
  });

  describe('GET /users/session', () => {
    it('should return the current user session', async () => {
      const response = await fetch('http://localhost:4006/dev/users/session');
      const data = await response.json();

      expect(response.status).toBe(401);
    });
  });
});
