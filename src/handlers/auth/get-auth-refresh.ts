import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { refreshAuthenticatedJwt } from 'src/modules/auth/auth.service';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('get-auth-refresh');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Refreshing auth id token`);

  try {
    const refreshToken = event.headers['X-Refresh-Token'];

    const { AuthenticationResult } = await refreshAuthenticatedJwt(cognitoClient, refreshToken!);

    return httpResponse._200({
      idToken: AuthenticationResult?.IdToken,
      expiresIn: AuthenticationResult?.ExpiresIn
    });
  } catch (err: any) {
    logger.error(`Failed to refresh auth id token`);
    return httpResponse._403(err.message);
  }
};
