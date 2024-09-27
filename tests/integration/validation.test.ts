import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import PgClient from 'serverless-postgres';
import { AuthUserSession } from '@/types/auth.types';
import { getLogger } from '@/util/logger.util';
import { request } from '../http/request';
import { getPgClient } from '@/lib/postgres';
import { purgeDbState } from '../db/teardown';
import { createDbState } from '../db/setup';
import { getAuthToken } from '@/lib/token';
import { runAuthenticationFlow } from '../http/helpers';

const logger = getLogger('validation-test');

const email = 'test@session.com';
const password = 'Password$100';

describe('/validation', () => {
  let pgClient: PgClient;
  let headers: Record<string, string>;
  let orgId: string;
  let appId: string;
  let publicKey: string;
  let secretKey: string;

  beforeAll(async () => {
    pgClient = await getPgClient();
    const dbState = await createDbState(pgClient);
    orgId = dbState.orgId;
    appId = dbState.appId;
    publicKey = dbState.publicKey;
    secretKey = dbState.secretKey;
    headers = {
      'X-Ds-Public-Key': dbState.publicKey
    };
  });

  afterAll(async () => {
    await pgClient.clean();
  });

  describe('GET /validation/token', () => {
    let authUserSession: AuthUserSession;

    beforeAll(async () => {
      authUserSession = (await runAuthenticationFlow(
        pgClient,
        email,
        password,
        headers
      )) as AuthUserSession;
    });

    describe('2xx', () => {
      it('should return a valid session based on auth bearer token', async () => {
        const { session } = authUserSession!;

        const requestHeaders = {
          ...headers,
          Authorization: `Bearer ${session?.token}`
        };

        const { status, data } = await request('/validation/token', {
          method: 'GET',
          headers: requestHeaders
        });

        expect(status).toEqual(200);
        expect(data.user.id).toEqual(authUserSession!.user.id);
      });
    });

    describe('4xx', () => {
      it('should return 401 Unauthorized if authorization header missing', async () => {
        const requestHeaders = {
          ...headers
        };

        const { status } = await request('/validation/token', {
          method: 'GET',
          headers: requestHeaders
        });

        expect(status).toEqual(401);
      });

      it('should return 403 Forbidden if auth token invalid', async () => {
        const requestHeaders = {
          ...headers,
          Authorization: `Bearer invalid-token`
        };

        const { status } = await request('/validation/token', {
          method: 'GET',
          headers: requestHeaders
        });

        expect(status).toEqual(403);
      });

      it('should return 403 Forbidden if auth token signature invalid', async () => {
        const { user } = authUserSession!;

        const secretKey = 'invalid-secret';

        const invalidToken = getAuthToken(logger, user.id, publicKey, secretKey, user.clientId);

        const requestHeaders = {
          ...headers,
          Authorization: `Bearer ${invalidToken}`
        };

        const { status } = await request('/validation/token', {
          method: 'GET',
          headers: requestHeaders
        });

        expect(status).toEqual(403);
      });

      it('should return 403 Forbidden if auth token expired', async () => {
        const { user } = authUserSession!;

        const expiredToken = getAuthToken(logger, user.id, publicKey, secretKey, user.clientId, -1);

        const requestHeaders = {
          ...headers,
          Authorization: `Bearer ${expiredToken}`
        };

        const { status } = await request('/validation/token', {
          method: 'GET',
          headers: requestHeaders
        });

        expect(status).toEqual(403);
      });
    });
  });
});
