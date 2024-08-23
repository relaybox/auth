import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { generateTotpQrCodeUrl, processAssociateSoftwareToken } from 'src/modules/~mfa/mfa.service';
import { getAuthenticatedUserData } from 'src/lib/auth';
import { processAuthentication } from 'src/modules/admin/admin.service';

const logger = getLogger('post-admin-mfa-totp-associate');

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

    const { AccessToken: accessToken } = response.AuthenticationResult!;

    const result = await processAssociateSoftwareToken(logger, cognitoClient, accessToken!);

    // @ts-ignore
    const secretCode = result.SecretCode;
    const qrCodeUrl = await generateTotpQrCodeUrl(secretCode, email);

    return httpResponse._200({ url: qrCodeUrl });
  } catch (err: any) {
    logger.error(`Failed to associate mfa`, { err });
    return httpResponse._422({ message: err.message });
  }
};
