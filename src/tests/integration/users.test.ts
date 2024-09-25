import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import PgClient from 'serverless-postgres';
import { setupDb } from '../db/setup';
import { getLogger } from '@/util/logger.util';
import { getPgClient } from '@/lib/postgres';
import { teardownDb } from '../db/teardown';
import { getUserByEmail } from '@/modules/users/users.service';
import { request } from '../http/request';

const logger = getLogger('test');

describe('/users', () => {
  let pgClient: PgClient;
  let headers: Record<string, string>;
  let mockAppData: {
    orgId: string;
    appId: string;
    apiKey: string;
    publicKey: string;
  };

  beforeAll(async () => {
    pgClient = await getPgClient();

    mockAppData = await setupDb(logger, pgClient);

    headers = {
      'X-Ds-Public-Key': mockAppData.publicKey
    };
  });

  afterAll(async () => {
    await teardownDb(logger, pgClient);
    await pgClient.clean();
  });

  describe('POST /users/create', () => {
    const email = 'test@test.com';
    const password = 'Password$100';

    describe('2xx', () => {
      it('should create a new user with email and password', async () => {
        const body = {
          email,
          password
        };

        const { orgId, appId } = mockAppData;

        const { status, data } = await request<{ message: string; id: string; clientId: string }>(
          '/users/create',
          {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
          }
        );

        const user = await getUserByEmail(logger, pgClient, orgId, appId, email);

        expect(status).toEqual(200);
        expect(user.id).toEqual(data.id);
        expect(user.clientId).toEqual(data.clientId);
        expect(user.password).toBeUndefined();
        expect(user.verifiedAt).toBeNull();
      });
    });

    describe('4xx', () => {
      it('should return 400 Bad Request if schema validation fails', async () => {
        const body = {
          email
        };

        const { status, data } = await request<{ message: string; id: string; clientId: string }>(
          '/users/create',
          {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
          }
        );

        expect(status).toEqual(400);
      });

      it('should return 400 Bad Request if password validation fails', async () => {
        const body = {
          email,
          password: 'weak-password'
        };

        const { status, data } = await request<{ message: string; id: string; clientId: string }>(
          '/users/create',
          {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
          }
        );

        expect(status).toEqual(400);
      });

      it('should return 401 Unauthorized with generic error message if user already exists', async () => {
        const body = {
          email,
          password
        };

        const { status, data } = await request<{ message: string; id: string; clientId: string }>(
          '/users/create',
          {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
          }
        );

        expect(status).toEqual(401);
        expect(data.message).toEqual('Registration failed');
      });
    });
  });

  describe('GET /users/id', () => {
    it('should return a user by id', async () => {
      const response = await request('/users/id');

      expect(response.status).toBe(401);
    });
  });

  describe('GET /users/me', () => {
    it('should return the current user', async () => {
      const response = await request('/users/me');

      expect(response.status).toBe(401);
    });
  });

  describe('GET /users/session', () => {
    it('should return the current user session', async () => {
      const response = await request('/users/session');

      expect(response.status).toBe(401);
    });
  });
});
