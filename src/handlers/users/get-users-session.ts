import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  authenticateUser,
  getAuthDataByKeyId,
  getAuthRefreshToken,
  getAuthToken,
  getRequestAuthParams,
  getUserDataById,
  REFRESH_TOKEN_EXPIRES_IN_SECS
} from 'src/modules/users/users.service';
import { AuthStorageType } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('get-users-session');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const id = event.requestContext.authorizer!.principalId;

    const { keyName, keyId } = getRequestAuthParams(event);
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    logger.info(`Authenticating user`, { keyName });

    const { id: sub, clientId } = await getUserDataById(logger, pgClient, id);
    const expiresIn = 300;
    const user = await getUserDataById(logger, pgClient, sub);
    const authToken = await getAuthToken(logger, sub, keyName, secretKey, clientId, expiresIn);
    const refreshToken = await getAuthRefreshToken(logger, sub, keyName, secretKey, clientId);
    const expiresAt = new Date().getTime() + expiresIn * 1000;
    const destroyAt = new Date().getTime() + REFRESH_TOKEN_EXPIRES_IN_SECS * 1000;
    const authStorageType = AuthStorageType.SESSION;

    return httpResponse._200({
      token: authToken,
      refreshToken,
      expiresIn,
      expiresAt,
      destroyAt,
      authStorageType,
      user
    });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
