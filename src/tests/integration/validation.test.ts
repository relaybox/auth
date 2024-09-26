import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { getVerificationCode } from '../db/helpers';
import PgClient from 'serverless-postgres';
import { AuthUserSession } from '@/types/auth.types';
import { getLogger } from '@/util/logger.util';
import { request } from '../http/request';
import { getPgClient } from '@/lib/postgres';
import { purgeDbState } from '../db/teardown';
import { createDbState } from '../db/setup';
import { decodeAuthToken, getAuthToken } from '@/lib/token';
import jwt from 'jsonwebtoken';

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
    let authUserSession: AuthUserSession | undefined;

    beforeAll(async () => {
      const { data: userRegistrationResponse } = await request('/users/create', {
        method: 'POST',
        headers,
        body: JSON.stringify({ email, password })
      });

      const code = await getVerificationCode(pgClient, userRegistrationResponse.id);

      await request('/users/verify', {
        method: 'POST',
        headers,
        body: JSON.stringify({ email, code })
      });

      const { data } = await request<AuthUserSession>('/users/authenticate', {
        method: 'POST',
        headers,
        body: JSON.stringify({ email, password })
      });

      authUserSession = data;
    });

    describe('2xx', () => {
      it('should return a valid session', async () => {
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
      it('should return 401 Unauthorized if authorization header is missing', async () => {
        const requestHeaders = {
          ...headers
        };

        const { status } = await request('/validation/token', {
          method: 'GET',
          headers: requestHeaders
        });

        expect(status).toEqual(401);
      });

      it('should return 403 Forbidden if auth token is invalid', async () => {
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

      it('should return 403 Forbidden if auth token signature is invalid', async () => {
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

      it('should return 403 Forbidden if auth token has expired', async () => {
        const { user } = authUserSession!;

        const invalidToken = getAuthToken(logger, user.id, publicKey, secretKey, user.clientId, -1);

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
    });
  });
});
