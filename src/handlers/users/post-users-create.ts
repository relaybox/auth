import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { createUser } from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-authentication-register');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { orgId, email, password } = JSON.parse(event.body!);

    if (!email || !password || !orgId) {
      throw new ValidationError('Missing email, password or orgId');
    }

    await createUser(logger, pgClient, orgId, email, password);

    return httpResponse._200({ message: 'Registration successful' });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
