import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  getClientCredentials,
  getPermissions,
  getTokenValidationCredentials
} from 'src/modules/validation/validation.service';
import { getPgClient } from 'src/lib/postgres';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { lambdaProxyEventMiddleware } from 'src/util/request.util';
import { ForbiddenError, TokenError, UnauthorizedError, ValidationError } from 'src/lib/errors';
import { TokenType } from 'src/types/jwt.types';
import { getKeyParts, getUserDataByClientId } from 'src/modules/users/users.service';
import { decodeAuthToken, verifyAuthToken } from 'src/lib/token';
import { handleErrorResponse } from 'src/util/http.util';

const logger = getLogger('get-validation-token');

async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const token = event.headers.Authorization?.substring(7);

    if (!token) {
      throw new UnauthorizedError('Missing authorization header');
    }

    const decodedToken = decodeAuthToken(token);

    if (!decodedToken) {
      throw new TokenError('Invalid auth token');
    }

    const {
      publicKey,
      clientId,
      timestamp,
      exp,
      tokenType,
      permissions: inlinePermissions
    } = decodedToken;

    if (tokenType !== TokenType.ID_TOKEN) {
      throw new ValidationError(`Invalid token type`);
    }

    logger.info(`Validating auth token`, { publicKey, clientId });

    const { appPid, keyId } = getKeyParts(publicKey);
    const { appId, secretKey } = await getTokenValidationCredentials(logger, pgClient, keyId);

    try {
      verifyAuthToken(token, secretKey);
    } catch (err) {
      throw new TokenError('Invalid auth token');
    }

    const connectionId = event.headers['X-Ds-Connection-Id'];
    const credentials = getClientCredentials(logger, appPid, clientId, connectionId);
    const sessionPermissions = await getPermissions(logger, pgClient, keyId, inlinePermissions);
    const user = await getUserDataByClientId(logger, pgClient, appId, clientId);

    if (user && user.blockedAt) {
      throw new ForbiddenError(`User ${user.clientId} blocked`);
    }

    const sessionData = {
      appPid,
      keyId,
      exp,
      timestamp,
      permissions: sessionPermissions,
      ...(user && { user }),
      ...credentials
    };

    return httpResponse._200(sessionData);
  } catch (err: any) {
    logger.error(err);
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
