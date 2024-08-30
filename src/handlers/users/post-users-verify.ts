import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import {
  getAuthDataByKeyId,
  getRequestAuthParams,
  verifyUser
} from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-verify');

const schema = z.object({
  email: z.string().email(),
  code: z.string().length(6)
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  logger.info(`Verifying user`);

  try {
    const { email, code } = validateEventSchema(event, schema);
    const { keyId } = getRequestAuthParams(event);
    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);

    await verifyUser(logger, pgClient, orgId, email, code);

    return httpResponse._200({ message: 'User verification successful' });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
