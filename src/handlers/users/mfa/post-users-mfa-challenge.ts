import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ForbiddenError, ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { createUserMfaChallenge, getUserMfaFactorById } from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-mfa-challenge');

const schema = z.object({
  factorId: z.string().uuid()
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const uid = event.requestContext.authorizer!.principalId;
    const { factorId } = validateEventSchema(event, schema);
    const validatedUserMfaFactor = await getUserMfaFactorById(logger, pgClient, factorId, uid);

    if (!validatedUserMfaFactor) {
      throw new ForbiddenError('Invalid factor id');
    }

    const { id } = await createUserMfaChallenge(logger, pgClient, uid, validatedUserMfaFactor.id);

    return httpResponse._200({ id });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
