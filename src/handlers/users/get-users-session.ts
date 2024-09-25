import { ValidationError } from '@/lib/errors';
import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import {
  createAuthenticationActivityLogEntry,
  getApplicationAuthenticationPreferences,
  getAuthDataByKeyId,
  getAuthenticationActionLog,
  getAuthSession,
  getRequestAuthParams
} from 'src/modules/users/users.service';
import { AuthenticationAction, AuthenticationActionResult } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { lambdaProxyEventMiddleware } from 'src/util/request.util';

const logger = getLogger('get-users-session');

export async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  const authenticationActionLog = getAuthenticationActionLog();

  try {
    const uid = event.requestContext.authorizer!.principalId;

    authenticationActionLog.uid = uid;

    logger.info(`Getting session data for user`, { uid });

    const { publicKey, keyId } = getRequestAuthParams(event, authenticationActionLog);
    const { appId, secretKey } = await getAuthDataByKeyId(
      logger,
      pgClient,
      keyId,
      authenticationActionLog
    );

    const { tokenExpiry, sessionExpiry, authStorageType } =
      await getApplicationAuthenticationPreferences(logger, pgClient, appId);

    const authenticateAction = false;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      uid,
      appId,
      publicKey,
      secretKey,
      tokenExpiry,
      sessionExpiry,
      authenticateAction,
      authStorageType
    );

    await createAuthenticationActivityLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.GET_SESSION,
      AuthenticationActionResult.SUCCESS,
      authenticationActionLog
    );

    return httpResponse._200(authSession);
  } catch (err: any) {
    await createAuthenticationActivityLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.GET_SESSION,
      AuthenticationActionResult.FAIL,
      authenticationActionLog,
      err
    );
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
