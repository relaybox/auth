import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { processConfirmForgotPassword } from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-auth-reset-password');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { email, password, confirmationCode } = JSON.parse(event.body!);

    if (!email || !password || !confirmationCode) {
      return httpResponse._400({ message: 'Missing email, password or confirmaton code' });
    }

    const confirmPasswordResponse = await processConfirmForgotPassword(
      cognitoClient,
      email,
      password,
      confirmationCode
    );

    return httpResponse._200({ requestId: confirmPasswordResponse.$metadata.requestId });
  } catch (err: any) {
    logger.error(`Failed to reset password`, { err });
    return httpResponse._400({ message: err.message });
  }
};
