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
import { getKeyParts } from 'src/modules/users/users.service';

const logger = getLogger('get-validation-api-key');

async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const apiKey = event.headers.Authorization!.substring(7);
    const clientId = event.headers['X-Ds-Client-Id'];
    const connectionId = event.headers['X-Ds-Connection-Id'];

    const [publicKey, providedSecret] = apiKey.split(':');
    const { appPid, keyId } = getKeyParts(publicKey);
    const { secretKey } = await getTokenValidationCredentials(logger, pgClient, keyId);

    if (providedSecret !== secretKey) {
      throw new Error(`Invalid api key`);
    }

    const clientCredentials = getClientCredentials(logger, appPid, clientId, connectionId);
    const keyPermissions = await getPermissions(logger, pgClient, keyId);

    const sessionData = {
      appPid,
      keyId,
      permissions: keyPermissions,
      ...clientCredentials
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
