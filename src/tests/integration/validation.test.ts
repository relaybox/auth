import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createMockUser, getVerificationCode } from '../db/helpers';
import PgClient from 'serverless-postgres';
import { setupDb } from '../db/setup';
import { AuthUserSession } from '@/types/auth.types';
import { getLogger } from '@/util/logger.util';
import { request } from '../http/request';
import { getPgClient } from '@/lib/postgres';
import { teardownDb } from '../db/teardown';

const logger = getLogger('validation-test');

const email = 'test@session.com';
const password = 'Password$100';

describe.skip('/validation', () => {
  let pgClient: PgClient;
  let headers: Record<string, string>;
  let mockAppData: {
    orgId: string;
    appId: string;
    apiKey: string;
    publicKey: string;
  };

  let authUserSession: AuthUserSession | undefined;

  beforeAll(async () => {
    pgClient = await getPgClient();
    mockAppData = await setupDb(pgClient);
    headers = {
      'X-Ds-Public-Key': mockAppData.publicKey
    };

    const { orgId, appId } = mockAppData;

    const user = await createMockUser(logger, pgClient, orgId, appId, email, password);
    const code = await getVerificationCode(pgClient, user!.id);

    await request('/users/verify', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        email,
        code
      })
    });

    const { data } = await request('/users/authenticate', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        email,
        password
      })
    });

    authUserSession = data;
  });

  afterAll(async () => {
    // await teardownDb(logger, pgClient);s
    await pgClient.clean();
  });

  describe('GET /validation/token', () => {
    describe('2xx', () => {
      it('shuold return a valid session', async () => {
        const { session } = authUserSession!;

        const requestHeaders = {
          ...headers,
          Authorization: `Bearer ${session?.token}`
        };

        const { status, data } = await request('/validation/token', {
          method: 'GET',
          headers: requestHeaders
        });

        console.log(data);
      });
    });
  });
});
