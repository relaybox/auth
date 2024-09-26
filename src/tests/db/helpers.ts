import { registerUser } from '@/modules/users/users.actions';
import { getUserDataByClientId } from '@/modules/users/users.service';
import { AuthUser, AuthUserSession } from '@/types/auth.types';
import PgClient from 'serverless-postgres';
import { Logger } from 'winston';
import { request } from '../http/request';
import { DbState } from './types';

export async function getVerificationCode(pgClient: PgClient, uid: string): Promise<string> {
  const query = `
    SELECT code
    FROM authentication_user_verification
    WHERE "uid" = $1;
  `;

  const { rows } = await pgClient.query(query, [uid]);

  return rows[0].code;
}

export async function createUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  appId: string,
  email: string,
  password: string
): Promise<AuthUser | undefined> {
  const { clientId } = await registerUser(logger, pgClient, orgId, appId, email, password);

  return getUserDataByClientId(logger, pgClient, appId, clientId);
}

export async function verifyUser() {}

export async function authenticateUser(
  logger: Logger,
  pgClient: PgClient,
  user: AuthUser,
  publicKey: string,
  email: string,
  password: string
): Promise<AuthUser | AuthUserSession | undefined> {
  const code = await getVerificationCode(pgClient, user!.id);

  const headers = {
    'X-Ds-Public-Key': publicKey
  };

  await request('/users/verify', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      email,
      code
    })
  });

  const { data: authUserSession } = await request<AuthUserSession>('/users/authenticate', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      email,
      password
    })
  });

  return authUserSession;
}
