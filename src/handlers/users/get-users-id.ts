import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { NotFoundError, UnauthorizedError, ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  getAuthDataByKeyId,
  getRequestAuthParams,
  getUserDataByClientId
} from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-id-session');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { id: clientId } = event.pathParameters!;

    if (!clientId) {
      throw new ValidationError('Missing client id');
    }

    logger.info(`Getting session data for user`, { clientId });

    const { keyId } = getRequestAuthParams(event);
    const { orgId, appId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const sessionData = await getUserDataByClientId(logger, pgClient, orgId, clientId);

    if (!sessionData) {
      throw new NotFoundError(`User not found`);
    }

    if (sessionData.appId !== appId) {
      throw new UnauthorizedError(`Cross organsiation authentication not supported`);
    }

    return httpResponse._200(sessionData);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
