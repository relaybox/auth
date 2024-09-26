import { AuthResponse, APIGatewayTokenAuthorizerEvent } from 'aws-lambda';
import { generateAuthResponsePolicyDocument } from 'src/lib/auth';
import { PolicyEffect } from 'src/types/aws.types';
import { getPgClient } from 'src/lib/postgres';
import { getLogger } from 'src/util/logger.util';
import { authorizeClientRequest } from 'src/modules/users/users.service';
import { TokenType } from 'src/types/jwt.types';

const logger = getLogger('session-authorizer');

export const handler = async (
  event: APIGatewayTokenAuthorizerEvent,
  context: any
): Promise<AuthResponse> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const token = event.authorizationToken!.substring(7);
    const verified = await authorizeClientRequest(logger, pgClient, token, TokenType.REFRESH_TOKEN);
    const policyDocument = generateAuthResponsePolicyDocument(PolicyEffect.ALLOW, event.methodArn);

    return <AuthResponse>{
      principalId: verified?.id,
      policyDocument,
      context: verified
    };
  } catch (err: any) {
    const policyDocument = generateAuthResponsePolicyDocument(PolicyEffect.DENY, event.methodArn);

    return <AuthResponse>{
      principalId: 'user',
      policyDocument
    };
  } finally {
    pgClient.clean();
  }
};
