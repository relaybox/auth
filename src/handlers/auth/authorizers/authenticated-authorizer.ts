import { AuthResponse, APIGatewayTokenAuthorizerEvent } from 'aws-lambda';
import {
  generateAuthResponsePolicyDocument,
  verifyAuthenticatedJwt
} from 'src/modules/auth/auth.service';
import { PolicyEffect } from 'src/types/aws.types';
import jwt from 'jsonwebtoken';

export const handler = async (
  event: APIGatewayTokenAuthorizerEvent,
  context: any
): Promise<AuthResponse> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const token = event.authorizationToken!.substring(7);
    const verified = await verifyAuthenticatedJwt(token);
    const policyDocument = generateAuthResponsePolicyDocument(PolicyEffect.ALLOW, event.methodArn);

    return <AuthResponse>{
      principalId: verified?.sub,
      policyDocument,
      context: {
        id: verified?.sub
      }
    };
  } catch (err: any) {
    const policyDocument = generateAuthResponsePolicyDocument(PolicyEffect.DENY, event.methodArn);

    return <AuthResponse>{
      principalId: 'user',
      policyDocument
    };
  }
};
