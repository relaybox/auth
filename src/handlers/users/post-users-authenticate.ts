import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  authenticateUser,
  getAuthDataByKeyId,
  getAuthRefreshToken,
  getAuthToken,
  getKeyParts
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
    const keyName = event.headers['X-Ds-Key-Name'];
    const { email, password } = JSON.parse(event.body!);

    logger.info(`Authenticating user`, { keyName });

    if (!keyName) {
      throw new ValidationError('Missing X-Ds-Key-Name header');
    }

    if (!email || !password) {
      throw new ValidationError('Missing email, password or orgId');
    }

    const [_, keyId] = getKeyParts(keyName);
    const { clientId } = await authenticateUser(logger, pgClient, email, password);
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const authToken = await getAuthToken(logger, keyName, secretKey, clientId);
    const refreshToken = await getAuthRefreshToken(logger, keyName, secretKey, clientId);

    return httpResponse._200({
      token: authToken,
      refreshToken,
      expiresIn: 900
    });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
