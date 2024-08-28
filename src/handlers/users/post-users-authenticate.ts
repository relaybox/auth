import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  authenticateUser,
  getAuthDataByKeyId,
  getAuthRefreshToken,
  getAuthToken,
  getRequestAuthParams,
  getUserDataById
} from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-authenticate');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { email, password } = JSON.parse(event.body!);

    if (!email || !password) {
      throw new ValidationError('Email and password required');
    }

    const { keyName, keyId } = getRequestAuthParams(event);
    const { orgId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    logger.info(`Authenticating user`, { keyName });

    const { id: sub, clientId } = await authenticateUser(logger, pgClient, orgId, email, password);
    const user = await getUserDataById(logger, pgClient, sub);
    const authToken = await getAuthToken(logger, sub, keyName, secretKey, clientId);
    const refreshToken = await getAuthRefreshToken(logger, sub, keyName, secretKey, clientId);
    const expiresIn = 900;
    const expiresAt = new Date().getTime() + expiresIn * 1000;

    return httpResponse._200({
      token: authToken,
      refreshToken,
      expiresIn,
      expiresAt,
      user
    });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
