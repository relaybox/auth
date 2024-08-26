import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { createUser, getAuthDataByKeyId } from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-create');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const apiKey = event.headers['X-Ds-Api-Key'];
    const { email, password } = JSON.parse(event.body!);

    if (!apiKey) {
      throw new ValidationError('Missing apiKey header');
    }

    if (!email || !password) {
      throw new ValidationError('Missing email or password');
    }

    const [_, keyId] = apiKey.split('.');

    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);

    await createUser(logger, pgClient, orgId, email, password);

    return httpResponse._200({ message: 'Registration successful' });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
