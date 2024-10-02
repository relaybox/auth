import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import PgClient from 'serverless-postgres';
import { createDbState } from '../db/setup';
import { getLogger } from '@/util/logger.util';
import { getPgClient } from '@/lib/postgres';
import { purgeDbState } from '../db/teardown';
import { getUserByEmail } from '@/modules/users/users.service';
import { request } from '../http/request';
import { getVerificationCode } from '../db/helpers';
import { AuthUserSession } from '@/types/auth.types';
import { runAuthenticationFlow } from '../http/helpers';

const logger = getLogger('test');

const email = 'new@user.com';
const password = 'Password$100';

interface CreateUserResponse {
  message: string;
  id: string;
  clientId: string;
}

describe('/users', () => {
  let pgClient: PgClient;
  let headers: Record<string, string>;
  let orgId: string;
  let appId: string;

  beforeAll(async () => {
    pgClient = await getPgClient();
    const dbState = await createDbState(pgClient);
    orgId = dbState.orgId;
    appId = dbState.appId;
    headers = {
      'X-Ds-Public-Key': dbState.publicKey
    };
  });

  afterAll(async () => {
    await purgeDbState(pgClient);
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

        const { status } = await request('/users/create', {
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

        const { status } = await request('/users/create', {
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

        const requestOptions = {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        };

        await request('/users/create', requestOptions);

        const { status, data } = await request('/users/create', requestOptions);

        expect(status).toEqual(401);
        expect(data.message).toEqual('Registration failed');
      });
    });
  });

  describe('POST /users/verify', () => {
    const email = 'test@verify.com';

    describe('2xx', () => {
      it('should verify a user following registration', async () => {
        const { data: userRegistrationResponse } = await request('/users/create', {
          method: 'POST',
          headers,
          body: JSON.stringify({
            email,
            password
          })
        });

        const code = await getVerificationCode(pgClient, userRegistrationResponse.id);

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

      it('should return 401 Unauthorized if verification code invalid', async () => {
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

      it('should return 401 Unauthorized if email address invalid', async () => {
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
    let uid: string;

    const email = 'test@authenticate.com';

    beforeAll(async () => {
      const { data: userRegistrationResponse } = await request('/users/create', {
        method: 'POST',
        headers,
        body: JSON.stringify({ email, password })
      });

      uid = userRegistrationResponse.id;
      const code = await getVerificationCode(pgClient, userRegistrationResponse.id);

      await request('/users/verify', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          email,
          code
        })
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
        expect(data.user.id).toEqual(uid);
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

  describe('Authenticated user endpoints', () => {
    const email = 'test@session.com';

    let authUserSession: AuthUserSession;

    beforeAll(async () => {
      authUserSession = (await runAuthenticationFlow(
        pgClient,
        email,
        password,
        headers
      )) as AuthUserSession;
    });

    describe('GET /users/session', () => {
      describe('2xx', () => {
        it('should return session data for authenticated user', async () => {
          const { session } = authUserSession!;

          const requestHeaders = {
            ...headers,
            Authorization: `Bearer ${session?.refreshToken}`
          };

          const { status, data } = await request('/users/session', {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(200);
          expect(data.user.id).toEqual(authUserSession!.user.id);
          expect(data.session.token).toBeDefined();
          expect(data.session.token).not.toEqual(session?.token);
        });
      });

      describe('4xx', () => {
        it('should return 403 Forbidden if invalid token provided', async () => {
          const requestHeaders = {
            ...headers,
            Authorization: `Bearer invalid-token`
          };

          const { status } = await request('/users/session', {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(403);
        });

        it('should return 401 Unauthorized if authorization header missing', async () => {
          const requestHeaders = {
            ...headers
          };

          const { status, data } = await request('/users/session', {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(401);
        });
      });
    });

    describe('GET /users/token/refresh', () => {
      describe('2xx', () => {
        it('should return refreshed token for authenticated user', async () => {
          const { session } = authUserSession!;

          const requestHeaders = {
            ...headers,
            Authorization: `Bearer ${session?.refreshToken}`
          };

          const { status, data } = await request('/users/token/refresh', {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(200);
          expect(data.token).toBeDefined();
          expect(data.expiresIn).toEqual(expect.any(Number));
          expect(data.expiresAt).toEqual(expect.any(Number));
        });
      });

      describe('4xx', () => {
        it('should return 403 Forbidden if token invalid', async () => {
          const requestHeaders = {
            ...headers,
            Authorization: `Bearer invalid-token`
          };

          const { status, data } = await request('/users/token/refresh', {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(403);
        });

        it('should return 401 Bad Request if authorization header missing', async () => {
          const requestHeaders = {
            ...headers
          };

          const { status } = await request('/users/token/refresh', {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(401);
        });
      });
    });

    describe('GET /users/:id', () => {
      describe('2xx', () => {
        it('should return non-sensitive user data by client id', async () => {
          const { session, user } = authUserSession!;

          const requestHeaders = {
            ...headers,
            Authorization: `Bearer ${session?.token}`
          };

          const { status, data } = await request(`/users/${user.clientId}`, {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(200);
          expect(data.id).toEqual(user.id);
          expect(data.clientId).toEqual(user.clientId);
        });
      });

      describe('4xx', () => {
        it('should return 404 Not Found if user not found', async () => {
          const { session } = authUserSession!;

          const requestHeaders = {
            ...headers,
            Authorization: `Bearer ${session?.token}`
          };

          const { status } = await request(`/users/unknown-client-id`, {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(404);
        });

        it('should return 403 Forbidden if token invalid', async () => {
          const { user } = authUserSession!;

          const requestHeaders = {
            ...headers,
            Authorization: `Bearer invalid-token`
          };

          const { status } = await request(`/users/${user.clientId}`, {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(403);
        });

        it('should return 401 Unauthorized if authorization header missing', async () => {
          const { user } = authUserSession!;

          const requestHeaders = {
            ...headers
          };

          const { status } = await request(`/users/${user.clientId}`, {
            method: 'GET',
            headers: requestHeaders
          });

          expect(status).toEqual(401);
        });
      });
    });
  });
});
