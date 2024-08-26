import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { authenticateUser, getAuthDataByKeyId, getIdToken } from 'src/modules/users/users.service';
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
    const apiKey = event.headers['X-Ds-Api-Key'];
    const { email, password } = JSON.parse(event.body!);

    if (!apiKey) {
      throw new ValidationError('Missing apiKey header');
    }

    if (!email || !password) {
      throw new ValidationError('Missing email, password or orgId');
    }

    const [_, keyId] = apiKey.split('.');
    const { clientId } = await authenticateUser(logger, pgClient, email, password);
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const idToken = await getIdToken(logger, apiKey, secretKey, clientId);

    return httpResponse._200(idToken);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
