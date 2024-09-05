import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import {
  getAuthDataByKeyId,
  getAuthSession,
  getRequestAuthParams
} from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('get-users-session');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const id = event.requestContext.authorizer!.principalId;

    logger.info(`Getting session data for user`, { id });

    const { keyName, keyId } = getRequestAuthParams(event);
    const { orgId, appId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const expiresIn = 300;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      id,
      appId,
      keyName,
      secretKey,
      expiresIn
    );

    return httpResponse._200(authSession);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
