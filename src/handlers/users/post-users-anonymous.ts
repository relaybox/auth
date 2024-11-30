import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from '@/lib/postgres';
import { registerUser } from '@/modules/users/users.actions';
import {
  generateUsername,
  getAuthDataByKeyId,
  getAuthenticationActionLog,
  getAuthSession,
  getRequestAuthParams
} from '@/modules/users/users.service';
import { AuthProvider, AuthStorageType } from '@/types/auth.types';
import * as httpResponse from '@/util/http.util';
import { handleErrorResponse } from '@/util/http.util';
import { getLogger } from '@/util/logger.util';
import { generateSalt } from '@/lib/encryption';

const logger = getLogger('post-users-anonymous');

const ANONYMOUS_TOKEN_EXPIRY_SECS = 900;
const ANONYMOUS_SESSION_EXPIRY_SECS = 30 * 24 * 60 * 60;

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  logger.info(`Creating anonymous user with public key`);

  const authenticationActionLog = getAuthenticationActionLog();

  try {
    const { publicKey, keyId } = getRequestAuthParams(event, authenticationActionLog);
    const { orgId, appId, secretKey } = await getAuthDataByKeyId(
      logger,
      pgClient,
      keyId,
      authenticationActionLog
    );

    const password = generateSalt();
    const username = generateUsername();
    const email = `${username}@relaybox.ai`;
    const firstName = undefined;
    const lastName = undefined;
    const anonymous = true;

    const { uid } = await registerUser(
      logger,
      pgClient,
      orgId,
      appId,
      email,
      password,
      username,
      firstName,
      lastName,
      AuthProvider.ANONYMOUS,
      anonymous
    );

    const tokenExpiry = ANONYMOUS_TOKEN_EXPIRY_SECS;
    const sessionExpiry = ANONYMOUS_SESSION_EXPIRY_SECS;
    const authStorageType = AuthStorageType.PERSIST;

    const authenticateAction = true;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      uid,
      appId,
      publicKey,
      secretKey,
      tokenExpiry,
      sessionExpiry,
      authenticateAction,
      authStorageType
    );

    return httpResponse._200(authSession);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
