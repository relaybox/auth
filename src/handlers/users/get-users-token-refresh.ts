import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { decodeAuthToken, getAuthToken, verifyRefreshToken } from 'src/lib/token';
import {
  getApplicationAuthenticationPreferences,
  getAuthDataByKeyId,
  getKeyParts
} from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-token-refresh');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Refreshing auth token`);

  const pgClient = await getPgClient();

  try {
    const refreshToken = event.headers.Authorization!.substring(7);

    if (!refreshToken) {
      throw new ValidationError('Missing refresh token header');
    }

    const { sub, keyName, clientId, tokenType } = decodeAuthToken(refreshToken);
    const { keyId } = getKeyParts(keyName);
    const { secretKey, appId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const { tokenExpiry } = await getApplicationAuthenticationPreferences(logger, pgClient, appId);

    verifyRefreshToken(refreshToken, secretKey, tokenType);

    const authToken = await getAuthToken(logger, sub, keyName, secretKey, clientId, tokenExpiry);
    const expiresAt = new Date().getTime() + tokenExpiry * 1000;

    return httpResponse._200({
      token: authToken,
      expiresIn: tokenExpiry,
      expiresAt
    });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
