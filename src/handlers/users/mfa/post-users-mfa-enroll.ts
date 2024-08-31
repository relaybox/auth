import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { generateTotpQrCodeUrl } from 'src/lib/auth';
import { getPgClient } from 'src/lib/postgres';
import { createUserMfaFactor, getUserDataById } from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-mfa-enroll');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const uid = event.requestContext.authorizer!.principalId;

    const { id, type, secret } = await createUserMfaFactor(logger, pgClient, uid);
    const { email } = await getUserDataById(logger, pgClient, uid);
    const qrCodeUri = await generateTotpQrCodeUrl(secret, email, 'RelayBox');

    return httpResponse._200({ id, type, secret, qrCodeUri });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
