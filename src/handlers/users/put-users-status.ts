import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import {
  getAuthDataByKeyId,
  getRequestAuthParams,
  updateUserStatusById
} from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('put-users-status');

const schema = z.object({
  status: z.string()
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  logger.info(`Verifying user`);

  try {
    const uid = event.requestContext.authorizer!.principalId;
    const { status } = validateEventSchema(event, schema);
    const { appPid, keyId } = getRequestAuthParams(event);
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    await updateUserStatusById(logger, pgClient, uid, status);

    return httpResponse._200({ message: 'User status updated sucessfully' });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
