import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  decodeAuthToken,
  getClientCredentials,
  getPermissions,
  getSecretKey,
  verifyAuthToken
} from 'src/module/service';
import { getConnection } from 'src/util/db.util';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { lambdaProxyEventMiddleware } from 'src/util/request.util';

const logger = getLogger('get-validate-token');

async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getConnection();

  try {
    const token = event.headers.Authorization!.substring(7);
    const connectionId = event.headers['X-Ds-Connection-Id'];

    const {
      keyName,
      clientId,
      timestamp,
      exp,
      permissions: inlinePermissions
    } = decodeAuthToken(token);

    const [appPid, keyId] = keyName.split('.');
    const secretKey = await getSecretKey(logger, pgClient, appPid, keyId);

    verifyAuthToken(token, secretKey);

    const credentials = getClientCredentials(logger, appPid, clientId, connectionId);
    const sessionPermissions = await getPermissions(logger, pgClient, keyId, inlinePermissions);

    const sessionData = {
      appPid,
      keyId,
      exp,
      timestamp,
      permissions: sessionPermissions,
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
