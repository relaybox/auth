import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { NotFoundError, ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import {
  createAuthVerificationCode,
  getAuthDataByKeyId,
  getRequestAuthParams,
  getUserByEmail,
  sendAuthVerificationCode
} from 'src/modules/users/users.service';
import { AuthProvider, AuthVerificationCodeType } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-generate-verification-code');

const schema = z.object({
  email: z.string().email()
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Generating verification code`);

  const pgClient = await getPgClient();

  try {
    const { email } = validateEventSchema(event, schema);
    const { keyId } = getRequestAuthParams(event);
    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const userData = await getUserByEmail(logger, pgClient, orgId, email, AuthProvider.EMAIL);

    if (!userData) {
      logger.warn(`Enumeration: User not found`, { email });
      return httpResponse._200({ message: `Verification code sent to ${email}` });
    }

    const { id: uid, verifiedAt } = userData;

    if (verifiedAt) {
      logger.warn(`Enumeration: User already verified`, { email });
      return httpResponse._200({ message: `Verification code sent to ${email}` });
    }

    const code = await createAuthVerificationCode(
      logger,
      pgClient,
      uid,
      AuthVerificationCodeType.REGISTER
    );

    await sendAuthVerificationCode(logger, email, code);

    return httpResponse._200({ message: `Verification code sent to ${email}` });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
