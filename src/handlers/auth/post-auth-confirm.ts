import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { confirmSession } from 'src/modules/auth/auth.repository';
import * as httpResponse from 'src/util/http.util';
import { processValidateUsername } from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';
import { getPgClient } from 'src/lib/postgres';

const logger = getLogger('post-auth-confirm');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { username } = JSON.parse(event.body!);

    if (!username) {
      return httpResponse._400({ message: 'Please enter a valid username' });
    }

    await processValidateUsername(logger, pgClient, username);

    const sub = event.requestContext.authorizer!.principalId;

    const { rows } = await confirmSession(pgClient, sub, username);

    return httpResponse._200(rows[0]);
  } catch (err: any) {
    return httpResponse._422({ message: err.message });
  } finally {
    pgClient.clean();
  }
};
