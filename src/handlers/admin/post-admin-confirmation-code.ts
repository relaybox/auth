import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getPgClient } from 'src/lib/postgres';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { getLogger } from 'src/util/logger.util';
import { generateAuthHashId } from 'src/util/hash.util';
import {
  getUserByHashId,
  processCodeConfirmation,
  saveUserVerification
} from 'src/modules/admin/admin.service';

const logger = getLogger('post-admin-confirmation-code');

const AUTH_HASH_ID_SECRET = process.env.AUTH_HASH_ID_SECRET || '';

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { email, confirmationCode } = JSON.parse(event.body!);

    if (!email || !confirmationCode) {
      return httpResponse._400({ message: 'Missing email or code' });
    }

    const codeConfirmation = await processCodeConfirmation(cognitoClient, email, confirmationCode);
    const hashId = generateAuthHashId(email, AUTH_HASH_ID_SECRET);

    const { id } = await getUserByHashId(logger, pgClient, hashId);

    await saveUserVerification(logger, pgClient, id);

    return httpResponse._200(codeConfirmation);
  } catch (err: any) {
    return httpResponse._422({ message: err.message });
  } finally {
    pgClient.clean();
  }
};
