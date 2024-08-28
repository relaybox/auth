import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  authenticateUser,
  getAuthDataByKeyId,
  getAuthRefreshToken,
  getAuthSession,
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
    const expiresIn = 300;
    const authSession = await getAuthSession(logger, pgClient, id, keyName, secretKey, expiresIn);

    return httpResponse._200(authSession);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
