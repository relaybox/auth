import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { verifyUserMfaChallenge } from 'src/modules/users/users.actions';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-mfa-challenge');

const schema = z.object({
  factorId: z.string().uuid(),
  challengeId: z.string().uuid(),
  code: z.string().length(6)
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const uid = event.requestContext.authorizer!.principalId;
    const { factorId, challengeId, code } = validateEventSchema(event, schema);

    await verifyUserMfaChallenge(logger, pgClient, uid, factorId, challengeId, code);

    return httpResponse._200();
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
