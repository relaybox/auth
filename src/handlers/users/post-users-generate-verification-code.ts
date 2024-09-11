import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import {
  createAuthVerificationCode,
  getAuthDataByKeyId,
  getRequestAuthParams,
  getUserIdentityByEmail,
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
    const { appId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const userData = await getUserIdentityByEmail(
      logger,
      pgClient,
      appId,
      email,
      AuthProvider.EMAIL
    );

    console.log(userData);

    if (!userData) {
      logger.warn(`Enumeration: User not found`, { id: userData.uid });
      return httpResponse._200({ message: `Verification code sent to ${email}` });
    }

    const { uid, identityId, verifiedAt } = userData;

    if (verifiedAt) {
      logger.warn(`Enumeration: User already verified`, { id: userData.uid, verifiedAt });
      return httpResponse._200({ message: `Verification code sent to ${email}` });
    }

    const code = await createAuthVerificationCode(
      logger,
      pgClient,
      uid,
      identityId,
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
