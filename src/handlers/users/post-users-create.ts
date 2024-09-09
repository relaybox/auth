import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { registerUser } from 'src/modules/users/users.actions';
import { getAuthDataByKeyId, getRequestAuthParams } from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-create');

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(5),
  username: z.string().min(3).optional(),
  firstName: z.string().min(3).optional(),
  lastName: z.string().min(3).optional()
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Creating user`);

  const pgClient = await getPgClient();

  try {
    const { email, password, username, firstName, lastName } = validateEventSchema(event, schema);
    const { keyId } = getRequestAuthParams(event);
    const { orgId, appId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const id = await registerUser(
      logger,
      pgClient,
      orgId,
      appId,
      email,
      password,
      username,
      firstName,
      lastName
    );

    return httpResponse._200({ message: 'Registration successful', id });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
