import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { lambdaProxyEventMiddleware } from 'src/util/request.util';
import { getPgClient } from 'src/lib/postgres';
import { getIdpAuthCredentials, getIdpUser, syncIdpUser } from 'src/modules/auth/auth.service';

const logger = getLogger('post-auth-idp-code');

async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Retrieving idp credentials and syncing user`);

  const pgClient = await getPgClient();

  try {
    const { code } = JSON.parse(event.body!);

    const authCredentials = await getIdpAuthCredentials(logger, code);

    const {
      id_token: idToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
      expiry_date: expiryDate
    } = authCredentials;

    if (!idToken) {
      throw new Error(`Failed to get oauth credentials`);
    }

    const existingIdpUser = await getIdpUser(logger, pgClient, idToken);

    if (!existingIdpUser) {
      await syncIdpUser(logger, pgClient, idToken);
    }

    return httpResponse._200({
      idToken,
      refreshToken,
      expiresIn: expiresIn || expiryDate
    });
  } catch (err: any) {
    logger.error(`Failed to retrieve idp credentials and sync user`, { err });
    return httpResponse.handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
