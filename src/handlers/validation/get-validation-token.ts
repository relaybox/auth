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
import { ValidationError } from 'src/lib/errors';
import { TokenType } from 'src/types/jwt.types';
import { getKeyParts, getUserDataByClientId } from 'src/modules/users/users.service';
import { decodeAuthToken, verifyAuthToken } from 'src/lib/token';

const logger = getLogger('get-validation-token');

async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const token = event.headers.Authorization!.substring(7);
    const connectionId = event.headers['X-Ds-Connection-Id'];

    const {
      keyName,
      clientId,
      timestamp,
      exp,
      tokenType,
      permissions: inlinePermissions
    } = decodeAuthToken(token);

    if (tokenType !== TokenType.ID_TOKEN) {
      throw new ValidationError(`Invalid token type`);
    }

    logger.info(`Validating auth token`, { keyName, clientId });

    const { appPid, keyId } = getKeyParts(keyName);
    const { orgId, secretKey } = await getTokenValidationCredentials(logger, pgClient, keyId);

    verifyAuthToken(token, secretKey);

    const credentials = getClientCredentials(logger, appPid, clientId, connectionId);
    const sessionPermissions = await getPermissions(logger, pgClient, keyId, inlinePermissions);
    const user = await getUserDataByClientId(logger, pgClient, orgId, clientId);

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
    return httpResponse._500({ message: err.message });
  } finally {
    pgClient.clean();
  }
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
