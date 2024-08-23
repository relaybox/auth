import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import {
  getAuthenticatedUserData,
  processAuthentication,
  processSendUserAttributesVerificationCode
} from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';

const logger = getLogger('post-auth-attributes-verify');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { password, attributeName } = JSON.parse(event.body!);
    const { email } = getAuthenticatedUserData(logger, event);

    return httpResponse._200({
      message: `Please confirm the verification code sent to "test placeholder"`
    });

    if (!password) {
      return httpResponse._400({ message: 'password and attributeName required' });
    }

    const response = await processAuthentication(cognitoClient, email, password);

    const { AccessToken: accessToken } = response.AuthenticationResult!;

    const result = await processSendUserAttributesVerificationCode(
      logger,
      cognitoClient,
      accessToken!,
      attributeName
    );

    return httpResponse._200({
      message: `Please confirm the verification code sent to ${result.CodeDeliveryDetails?.Destination}`
    });
  } catch (err: any) {
    console.log(err);
    return httpResponse._422({ message: err.message });
  }
};
