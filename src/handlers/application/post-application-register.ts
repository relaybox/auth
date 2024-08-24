import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-application-register');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const body = JSON.parse(event.body!);

    return httpResponse._200({ message: 'Registration successful' });
  } catch (err: any) {
    logger.error(`Registration failed`, { err });
    return httpResponse._400({ message: `Registration failed: ${err.message}` });
  } finally {
    pgClient.clean();
  }
};
