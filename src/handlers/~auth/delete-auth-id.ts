import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import {
  getAuthenticatedUser,
  processAuthentication,
  processDeleteAuthenticatedUser
} from 'src/modules/~auth/auth.service';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { processPurgeUserData } from 'src/modules/users/users.service';
import { getPgClient } from 'src/lib/postgres';

const logger = getLogger('delete-auth-id');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { email, password } = JSON.parse(event.body!);

    const { id: matchUidParam } = event.pathParameters!;
    const { id: uid, verified } = await getAuthenticatedUser(logger, pgClient, event, {
      matchUidParam
    });

    if (verified) {
      const response = await processAuthentication(cognitoClient, email, password);

      const { AccessToken: accessToken } = response.AuthenticationResult!;

      await processDeleteAuthenticatedUser(logger, cognitoClient, accessToken!);
    }

    await processPurgeUserData(logger, pgClient, uid);

    return httpResponse._200(uid);
  } catch (err: any) {
    return httpResponse._403({ message: err.message });
  } finally {
    pgClient.clean();
  }
};
