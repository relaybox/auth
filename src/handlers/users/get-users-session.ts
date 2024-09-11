import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import {
  createAuthenticationActionLogEntry,
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

async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  const authenticationActionLog = getAuthenticationActionLog();

  try {
    const uid = event.requestContext.authorizer!.principalId;

    logger.info(`Getting session data for user`, { uid });

    const { keyName, keyId } = getRequestAuthParams(event);
    const { appId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    authenticationActionLog.keyId = keyId;
    authenticationActionLog.uid = uid;

    const { tokenExpiry, sessionExpiry, authStorageType } =
      await getApplicationAuthenticationPreferences(logger, pgClient, appId);

    const authenticateAction = false;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      uid,
      appId,
      keyName,
      secretKey,
      tokenExpiry,
      sessionExpiry,
      authenticateAction,
      authStorageType
    );

    await createAuthenticationActionLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.GET_SESSION,
      AuthenticationActionResult.SUCCESS,
      authenticationActionLog
    );

    return httpResponse._200(authSession);
  } catch (err: any) {
    authenticationActionLog.errorMessage = err.message;
    await createAuthenticationActionLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.GET_SESSION,
      AuthenticationActionResult.FAIL,
      authenticationActionLog
    );
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
