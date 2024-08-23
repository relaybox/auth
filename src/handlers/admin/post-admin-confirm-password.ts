import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { getLogger } from 'src/util/logger.util';
import { formatAuthTokenResponse, getAuthenticatedUserData } from 'src/lib/auth';
import { processAuthentication } from 'src/modules/admin/admin.service';

const logger = getLogger('post-admin-confirm-password');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { password } = JSON.parse(event.body!);
    const { email } = getAuthenticatedUserData(event);

    if (!password) {
      return httpResponse._400({ message: 'Password required' });
    }

    const response = await processAuthentication(logger, cognitoClient, email, password);
    const authTokenResponse = formatAuthTokenResponse(response);

    return httpResponse._200(authTokenResponse);
  } catch (err: any) {
    logger.error(`Failed to confirm password`, { err });
    return httpResponse._400({ message: err.message });
  }
};
