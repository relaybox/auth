import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getPgClient } from 'src/lib/postgres';
import { lambdaProxyEventMiddleware } from 'src/util/request.util';
import { getLogger } from 'src/util/logger.util';
import { getSessionData } from 'src/modules/admin/admin.service';

const logger = getLogger('get-admin-session');

async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const id = event.requestContext.authorizer!.principalId;

    logger.info(`Getting admin session for user ${id}`, { id });

    const sessionData = await getSessionData(logger, pgClient, id);

    return httpResponse._200(sessionData);
  } catch (err: any) {
    return httpResponse._403({ message: err.message });
  } finally {
    pgClient.clean();
  }
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
