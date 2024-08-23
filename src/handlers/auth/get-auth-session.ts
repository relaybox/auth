import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getPgClient } from 'src/lib/postgres';
import { getSessionData } from 'src/modules/~auth/auth.repository';
import { lambdaProxyEventMiddleware } from 'src/util/request.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('get-auth-session');

async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const id = event.requestContext.authorizer!.principalId;

    const { rows } = await getSessionData(pgClient, id);

    if (!rows.length) {
      throw new Error('Invalid token');
    }

    return httpResponse._200(rows[0]);
  } catch (err: any) {
    return httpResponse._403({ message: err.message });
  } finally {
    pgClient.clean();
  }
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
