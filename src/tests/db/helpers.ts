import { registerUser } from '@/modules/users/users.actions';
import { getUserDataByClientId } from '@/modules/users/users.service';
import { AuthUser } from '@/types/auth.types';
import PgClient from 'serverless-postgres';
import { Logger } from 'winston';

export async function getVerificationCode(pgClient: PgClient, uid: string): Promise<string> {
  const query = `
    SELECT code
    FROM authentication_user_verification
    WHERE "uid" = $1;
  `;

  const { rows } = await pgClient.query(query, [uid]);

  return rows[0].code;
}

export async function createMockUser(
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
