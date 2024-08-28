import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { decodeAuthToken } from 'src/lib/encryption';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  getAuthDataByKeyId,
  getAuthToken,
  getKeyParts,
  verifyRefreshToken
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

  const pgClient = await getPgClient();

  try {
    const refreshToken = event.headers.Authorization!.substring(7);

    logger.info(`Refreshing auth token`);

    if (!refreshToken) {
      throw new ValidationError('Missing refresh token header');
    }

    const { sub, keyName, clientId, tokenType } = decodeAuthToken(refreshToken);
    const { keyId } = getKeyParts(keyName);
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    verifyRefreshToken(refreshToken, secretKey, tokenType);

    const expiresIn = 2;
    const authToken = await getAuthToken(logger, sub, keyName, secretKey, clientId, expiresIn);
    const expiresAt = new Date().getTime() + expiresIn * 1000;

    return httpResponse._200({
      token: authToken,
      expiresIn,
      expiresAt
    });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
