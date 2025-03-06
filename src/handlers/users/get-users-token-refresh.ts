import { lambdaProxyEventMiddleware } from '@/util/request.util';
import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { TokenError, UnauthorizedError } from 'src/lib/errors';
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

export async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Refreshing auth token`);

  const pgClient = await getPgClient();

  try {
    const refreshToken = event.headers.Authorization?.substring(7);

    if (!refreshToken) {
      throw new UnauthorizedError('Missing authorization header');
    }

    const decodedToken = decodeAuthToken(refreshToken);

    if (!decodedToken) {
      throw new TokenError('Invalid token');
    }

    const { sub, publicKey, clientId, tokenType } = decodedToken;
    const { keyId } = getKeyParts(publicKey);
    const { secretKey, appId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const { tokenExpiry } = await getApplicationAuthenticationPreferences(logger, pgClient, appId);

    verifyRefreshToken(refreshToken, secretKey, tokenType);

    const authToken = getAuthToken(logger, sub, publicKey, secretKey, clientId, tokenExpiry);
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
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
