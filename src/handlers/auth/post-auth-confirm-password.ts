import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import {
  formatAuthTokenResponse,
  getAuthenticatedUserData,
  processAuthentication
} from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-auth-confirm-password');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { password } = JSON.parse(event.body!);
    const { email } = getAuthenticatedUserData(logger, event);

    if (!password) {
      return httpResponse._400({ message: 'Password required' });
    }

    const response = await processAuthentication(cognitoClient, email, password);
    const authTokenResponse = formatAuthTokenResponse(response);

    return httpResponse._200(authTokenResponse);
  } catch (err: any) {
    logger.error(`Failed to confirm password`, { err });
    return httpResponse._400({ message: err.message });
  }
};
