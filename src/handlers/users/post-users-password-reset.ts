import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { AuthenticationError, NotFoundError, ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import {
  createAuthVerificationCode,
  getAuthDataByKeyId,
  getRequestAuthParams,
  getUserByEmail,
  getUserEmailIdentityAuthCredentials,
  sendAuthVerificationCode
} from 'src/modules/users/users.service';
import { AuthProvider, AuthVerificationCodeType } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-password-reset');

const schema = z.object({
  email: z.string().email()
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Password reset request received`);

  const pgClient = await getPgClient();

  try {
    const { email } = validateEventSchema(event, schema);
    const { keyId } = getRequestAuthParams(event);
    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const userAuthCredentials = await getUserEmailIdentityAuthCredentials(
      logger,
      pgClient,
      orgId,
      email,
      AuthProvider.EMAIL
    );

    if (!userAuthCredentials) {
      logger.warn(`User not found`, { email });
      return httpResponse._200({ message: 'Password reset request initialized' });
    }

    const { id: uid } = userAuthCredentials;

    const code = await createAuthVerificationCode(
      logger,
      pgClient,
      uid,
      AuthVerificationCodeType.PASSWORD_RESET
    );

    await sendAuthVerificationCode(logger, email, code);

    return httpResponse._200({ message: 'Password reset request initialized' });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
