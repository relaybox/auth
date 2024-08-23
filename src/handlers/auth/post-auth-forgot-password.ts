import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { processForgotPassword } from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-auth-forgot-password');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { email } = JSON.parse(event.body!);

    if (!email) {
      return httpResponse._400({ message: 'Email address is required' });
    }

    const forgotPasswordResponse = await processForgotPassword(cognitoClient, email);

    return httpResponse._200({ requestId: forgotPasswordResponse.$metadata.requestId });
  } catch (err: any) {
    logger.error(`failed to generate password reset code`, { err });
    return httpResponse._400({ message: err.message });
  }
};
