import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import {
  getAuthenticatedUserData,
  processAuthentication,
  processConfirmUserAttributesVerificationCode,
  processSetUserMfaSmsPreference
} from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';

const logger = getLogger('post-auth-attributes-confirm');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { password, attributeName, verificationCode } = JSON.parse(event.body!);
    const { email } = getAuthenticatedUserData(logger, event);

    if (!password) {
      return httpResponse._400({
        message: 'password, attributeName name and verificationCode required'
      });
    }

    const response = await processAuthentication(cognitoClient, email, password);

    const { AccessToken: accessToken } = response.AuthenticationResult!;

    await processSetUserMfaSmsPreference(logger, cognitoClient, accessToken!, email);

    return httpResponse._200({ message: 'placeholder' });

    const result = await processConfirmUserAttributesVerificationCode(
      logger,
      cognitoClient,
      accessToken!,
      attributeName,
      verificationCode
    );

    return httpResponse._200(result);
  } catch (err: any) {
    return httpResponse._422({ message: err.message });
  }
};
