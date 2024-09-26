import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { getVerificationCode } from '../db/helpers';
import PgClient from 'serverless-postgres';
import { AuthUserSession } from '@/types/auth.types';
import { getLogger } from '@/util/logger.util';
import { request } from '../http/request';
import { getPgClient } from '@/lib/postgres';
import { purgeDbState } from '../db/teardown';
import { createDbState } from '../db/setup';

const logger = getLogger('validation-test');

const email = 'test@session.com';
const password = 'Password$100';

describe('/validation', () => {
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
  });
});
