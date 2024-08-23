import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getAuthenticatedUserData, processAuthentication } from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { processSetUserMfaSmsPreference } from 'src/modules/mfa/mfa.service';

const logger = getLogger('post-auth-mfa-sms-enable');

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

    const { AccessToken: accessToken } = response.AuthenticationResult!;

    const result = await processSetUserMfaSmsPreference(logger, cognitoClient, accessToken!, email);

    return httpResponse._200(result);
  } catch (err: any) {
    return httpResponse._422({ message: err.message });
  }
};
