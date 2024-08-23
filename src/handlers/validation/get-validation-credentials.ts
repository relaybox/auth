import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { lambdaProxyEventMiddleware } from 'src/util/request.util';
import { nanoid } from 'nanoid';
import crypto from 'crypto';

const logger = getLogger('get-validation-credentials');

async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const appKeyId = nanoid(12);
    const keyId = nanoid(12);
    const secretKey = crypto.randomBytes(32).toString('hex');

    return httpResponse._200({
      appKeyId,
      keyId,
      secretKey
    });
  } catch (err: any) {
    logger.error(err);
    return httpResponse._500({ message: err.message });
  } finally {
    pgClient.clean();
  }
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
