import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { NotFoundError, ValidationError, VerificationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import {
  getAuthDataByKeyId,
  getRequestAuthParams,
  getUserByEmail,
  resetUserPassword
} from 'src/modules/users/users.service';
import { AuthProvider } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-verify');

const schema = z.object({
  email: z.string().email(),
  code: z.string().length(6),
  password: z.string().min(5)
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  logger.info(`Verifying user`);

  try {
    const { email, code, password } = validateEventSchema(event, schema);
    const { keyId } = getRequestAuthParams(event);
    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const userData = await getUserByEmail(logger, pgClient, orgId, email, AuthProvider.EMAIL);

    if (!userData) {
      logger.warn(`User not found`, { email });
      throw new VerificationError('Password reset failed');
    }

    const { id: uid } = userData;

    await resetUserPassword(logger, pgClient, uid, code, password);

    return httpResponse._200({ message: 'Password reset successful' });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
