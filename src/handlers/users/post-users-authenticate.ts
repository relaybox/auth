import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { authenticateUser } from 'src/modules/users/users.actions';
import {
  getAuthDataByKeyId,
  getAuthSession,
  getRequestAuthParams
} from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-authenticate');

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(5)
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { email, password } = validateEventSchema(event, schema);
    const { keyName, keyId } = getRequestAuthParams(event);
    const { orgId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    logger.info(`Authenticating user with public key`, { keyName });

    const id = await authenticateUser(logger, pgClient, orgId, email, password);

    logger.info(`Authenticated user found by id`, { id });

    const expiresIn = 3600;
    const authenticateAction = true;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      id,
      orgId,
      keyName,
      secretKey,
      expiresIn,
      authenticateAction
    );

    return httpResponse._200(authSession);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
