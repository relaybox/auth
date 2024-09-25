import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import PgClient from 'serverless-postgres';
import { setupDb } from '../db/setup';
import { getLogger } from '@/util/logger.util';
import { getPgClient } from '@/lib/postgres';
import { teardownDb } from '../db/teardown';
import { getUserByEmail } from '@/modules/users/users.service';
import { request } from '../http/request';
import { createMockUser, getVerificationCode } from '../db/helpers';
import { AuthUser } from '@/types/auth.types';

const logger = getLogger('test');

const email = 'test@test.com';
const password = 'Password$100';

interface CreateUserResponse {
  message: string;
  id: string;
  clientId: string;
}

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
    describe('2xx', () => {
      it('should create a new user with email and password', async () => {
        const body = {
          email,
          password
        };

        const { status, data } = await request<CreateUserResponse>('/users/create', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        const { orgId, appId } = mockAppData;

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

        const { status } = await request<CreateUserResponse>('/users/create', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(400);
      });

      it('should return 400 Bad Request if password validation fails', async () => {
        const body = {
          email,
          password: 'weak-password'
        };

        const { status } = await request<CreateUserResponse>('/users/create', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(400);
      });

      it('should return 401 Unauthorized with generic error message if user already exists', async () => {
        const body = {
          email,
          password
        };

        const { status, data } = await request<CreateUserResponse>('/users/create', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(401);
        expect(data.message).toEqual('Registration failed');
      });
    });
  });

  describe('POST /users/verify', () => {
    let user: AuthUser | undefined;

    const email = 'test@verify.com';

    beforeAll(async () => {
      const { orgId, appId } = mockAppData;
      user = await createMockUser(logger, pgClient, orgId, appId, email, password);
    });

    describe('2xx', () => {
      it('should authenticate a user with email and password', async () => {
        const code = await getVerificationCode(pgClient, user!.id);

        const body = {
          email,
          code
        };

        const { status, data } = await request('/users/verify', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(200);
        expect(data.message).toEqual('User verification successful');
      });
    });

    describe('4xx', () => {
      it('should return 400 Bad Request if schema validation fails', async () => {
        const body = {
          email,
          code: 'invalid-code'
        };

        const { status, data } = await request('/users/verify', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(400);
      });

      it('should return 401 Unauthorized if verification code is invalid', async () => {
        const body = {
          email,
          code: '123456'
        };

        const { status, data } = await request('/users/verify', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(401);
        expect(data.message).toEqual('User verification failed');
      });

      it('should return 401 Unauthorized if email address is invalid', async () => {
        const body = {
          email: 'not-in-the@system.com',
          code: '123456'
        };

        const { status, data } = await request('/users/verify', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(401);
        expect(data.message).toEqual('User verification failed');
      });
    });
  });

  describe('POST /users/authenticate', () => {
    let user: AuthUser | undefined;

    const email = 'test@authenticate.com';

    beforeAll(async () => {
      const { orgId, appId } = mockAppData;

      user = await createMockUser(logger, pgClient, orgId, appId, email, password);

      const code = await getVerificationCode(pgClient, user!.id);

      const body = {
        email,
        code
      };

      await request('/users/verify', {
        method: 'POST',
        headers,
        body: JSON.stringify(body)
      });
    });

    describe('2xx', () => {
      it('should authenticate a user with email and password', async () => {
        const body = {
          email,
          password
        };

        const { status, data } = await request('/users/authenticate', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(200);
        expect(data.user.id).toEqual(user!.id);
        expect(data.user.verifiedAt).toEqual(expect.any(String));
        expect(data.session.token).toBeDefined();
        expect(data.session.refreshToken).toBeDefined();
        expect(data.session.expiresIn).toEqual(expect.any(Number));
        expect(data.session.expiresAt).toEqual(expect.any(Number));
        expect(data.session.destroyAt).toEqual(expect.any(Number));
        expect(data.session.authStorageType).toBeDefined();
      });
    });

    describe('4xx', () => {
      it('should return 400 Bad Request if schema validation fails', async () => {
        const body = {
          email
        };

        const { status } = await request('/users/authenticate', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(400);
      });

      it('should return 401 Unauthorized with generic message if password authentication fails', async () => {
        const body = {
          email,
          password: 'invalid-password'
        };

        const { status, data } = await request('/users/authenticate', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(401);
        expect(data.message).toEqual('Login failed');
      });

      it('should return 401 Unauthorized with generic message if user not found', async () => {
        const body = {
          email: 'not-in-the@system.com',
          password
        };

        const { status, data } = await request('/users/authenticate', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });

        expect(status).toEqual(401);
        expect(data.message).toEqual('Login failed');
      });
    });
  });
});
