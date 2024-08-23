import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getPgClient } from 'src/lib/postgres';
import { getSessionData } from 'src/modules/~auth/auth.repository';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('get-auth-verirfy');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  logger.info('Source identity verification', event.requestContext.identity);

  try {
    const sub = event.requestContext.authorizer!.principalId;

    const { rows } = await getSessionData(pgClient, sub);

    return httpResponse._200(rows[0]);
  } catch (err: any) {
    logger.error(err);
    return httpResponse._403(err.message);
  } finally {
    pgClient.clean();
  }
};
