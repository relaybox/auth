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

    const { keyName, clientId, tokenType } = decodeAuthToken(refreshToken);
    const [_, keyId] = getKeyParts(keyName);
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    verifyRefreshToken(refreshToken, secretKey, tokenType);

    const authToken = await getAuthToken(logger, keyName, secretKey, clientId);

    return httpResponse._200({
      token: authToken,
      expiresIn: 900
    });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
