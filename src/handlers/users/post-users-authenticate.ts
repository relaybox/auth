import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  authenticateUser,
  getAuthDataByKeyId,
  getAuthToken
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
    const apiKey = event.headers['X-Ds-Api-Key'];
    const { email, password } = JSON.parse(event.body!);

    logger.info(`Authenticating user`, { apiKey });

    if (!apiKey) {
      throw new ValidationError('Missing X-Ds-Api-Key header');
    }

    if (!email || !password) {
      throw new ValidationError('Missing email, password or orgId');
    }

    const [_, keyId] = apiKey.split('.');
    const { clientId } = await authenticateUser(logger, pgClient, email, password);
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const authToken = await getAuthToken(logger, apiKey, secretKey, clientId);

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
