import {
  AuthFlowType,
  CognitoIdentityProviderClient,
  ConfirmForgotPasswordCommand,
  ConfirmSignUpCommand,
  DeleteUserCommand,
  ForgotPasswordCommand,
  GetUserAttributeVerificationCodeCommand,
  GetUserAttributeVerificationCodeCommandOutput,
  InitiateAuthCommand,
  InitiateAuthCommandOutput,
  SignUpCommand,
  SignUpCommandOutput,
  UpdateUserAttributesCommand,
  UpdateUserAttributesCommandOutput,
  VerifyUserAttributeCommand,
  VerifyUserAttributeCommandOutput
} from '@aws-sdk/client-cognito-identity-provider';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { APIGatewayProxyEvent, PolicyDocument } from 'aws-lambda';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { Moment } from 'moment-timezone';
import { PolicyEffect } from 'src/types/aws.types';
import { ExtendedJwtPayload } from 'src/types/jwt.types';
import * as repository from './auth.repository';
import PgClient from 'serverless-postgres';
import { User } from './auth.types';
import { GuardOptions } from 'src/types/system.types';
import { Logger } from 'winston';
import { ForbiddenError, UnauthorizedError } from 'src/lib/errors';
import { AuthMfaChallengeResponse, AuthTokenResponse, AuthUserData } from 'src/types/auth.types';
import { generateAuthSecretHash } from 'src/util/hash.util';

const COGNITO_VERIFIER_TOKEN = 'id';
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || '';
const COGNITO_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET || '';
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || '';
const COGNITO_USER_POOL_DOMAIN = process.env.COGNITO_USER_POOL_DOMAIN || '';
const COGNITO_OAUTH_CALLBACK_URL = process.env.COGNITO_OAUTH_CALLBACK_URL || '';
const COGNITO_SIGNUP_USER_ATTRIBUTE_NAME = 'email';
const AUTH_HASH_ID_SECRET = process.env.AUTH_HASH_ID_SECRET || '';
const OAUTH_GRANT_TYPE_AUTH_CODE = 'authorization_code';

export function processAuthentication(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string
): Promise<InitiateAuthCommandOutput> {
  console.info(`Authenticating...`);

  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  const initiateAuthParams = {
    AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
    ClientId: COGNITO_CLIENT_ID,
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
      SECRET_HASH: secretHash
    }
  };

  const initiateAuthParamsCommand = new InitiateAuthCommand(initiateAuthParams);

  return cognitoClient.send(initiateAuthParamsCommand);
}

export function processRegistration(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string
): Promise<SignUpCommandOutput> {
  console.info(`Registering...`);

  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  const signUpParams = {
    ClientId: COGNITO_CLIENT_ID,
    SecretHash: secretHash,
    Username: email,
    Password: password,
    UserAttributes: [
      {
        Name: COGNITO_SIGNUP_USER_ATTRIBUTE_NAME,
        Value: email
      }
    ]
  };

  const signUpCommand = new SignUpCommand(signUpParams);

  return cognitoClient.send(signUpCommand);
}

export function processCodeConfirmation(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  confirmationCode: string
) {
  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  const confirmSignUpParams = {
    ClientId: COGNITO_CLIENT_ID,
    SecretHash: secretHash,
    Username: email,
    ConfirmationCode: confirmationCode
  };

  const confirmSignUpCommand = new ConfirmSignUpCommand(confirmSignUpParams);

  return cognitoClient.send(confirmSignUpCommand);
}

export function processForgotPassword(cognitoClient: CognitoIdentityProviderClient, email: string) {
  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  const forgotPasswordParams = {
    ClientId: COGNITO_CLIENT_ID,
    SecretHash: secretHash,
    Username: email
  };

  const forgotPasswordCommand = new ForgotPasswordCommand(forgotPasswordParams);

  return cognitoClient.send(forgotPasswordCommand);
}

export function processConfirmForgotPassword(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string,
  confirmationCode: string
) {
  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  const confirmForgotPasswordParams = {
    ClientId: COGNITO_CLIENT_ID,
    SecretHash: secretHash,
    Username: email,
    ConfirmationCode: confirmationCode,
    Password: password
  };

  const confirmPasswordCommand = new ConfirmForgotPasswordCommand(confirmForgotPasswordParams);

  return cognitoClient.send(confirmPasswordCommand);
}

export async function verifyAuthenticatedJwt(token: string): Promise<JwtPayload> {
  const verifier = CognitoJwtVerifier.create({
    tokenUse: COGNITO_VERIFIER_TOKEN,
    clientId: COGNITO_CLIENT_ID!,
    userPoolId: COGNITO_USER_POOL_ID!
  });

  const payload = await verifier.verify(token);

  return payload;
}

export function refreshAuthenticatedJwt(
  cognitoClient: CognitoIdentityProviderClient,
  REFRESH_TOKEN: string
): Promise<InitiateAuthCommandOutput> {
  console.info(`Refreshing token...`);

  const initiateAuthParams = {
    AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
    ClientId: COGNITO_CLIENT_ID,
    AuthParameters: {
      REFRESH_TOKEN,
      SECRET_HASH: COGNITO_CLIENT_SECRET
    }
  };

  const initiateAuthCommand = new InitiateAuthCommand(initiateAuthParams);

  return cognitoClient.send(initiateAuthCommand);
}

export function generateAnonymousJwt(id: string, sub: string, exp: Moment): string {
  const payload = <ExtendedJwtPayload>{
    id,
    sub,
    exp: exp.unix(),
    grant: process.env.JWT_ANONYMOUS_GRANT
  };

  return jwt.sign(payload, process.env.JWT_SIGNATURE!);
}

export function generateAuthResponsePolicyDocument(
  effect: PolicyEffect,
  resource: string
): PolicyDocument {
  const policyDocument = <PolicyDocument>{};

  if (effect && resource) {
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];

    const statement: any = {
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource: '*'
    };

    policyDocument.Statement[0] = statement;
  }

  return policyDocument;
}

export async function completeAuthentication(pgClient: PgClient, idToken: string) {
  const { email_verified, sub: id } = <ExtendedJwtPayload>jwt.decode(idToken);

  if (email_verified && id) {
    return repository.setAuthenticationComplete(pgClient, id);
  }
}

export async function getAuthenticatedUser(
  logger: Logger,
  pgClient: PgClient,
  event: APIGatewayProxyEvent,
  guardOptions?: GuardOptions
): Promise<User> {
  logger.debug(`Getting authenticated user data`, {
    id: event.requestContext.authorizer!.principalId
  });

  const id = event.requestContext.authorizer!.principalId;

  const { rows: users } = await repository.getUserById(pgClient, id);

  if (!users.length) {
    throw new UnauthorizedError('Invalid authentication credentials');
  }

  const user = users[0];

  if (guardOptions?.matchUidParam && user.id !== guardOptions.matchUidParam) {
    throw new ForbiddenError('Forbidden');
  }

  if (guardOptions?.confirmed && !user.confirmed) {
    throw new ForbiddenError('Unconfirmed user request');
  }

  if (guardOptions?.verified && !user.verified) {
    throw new ForbiddenError('Unverified user request');
  }

  return <User>(<unknown>user);
}

export async function processDeleteAuthenticatedUser(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string
): Promise<any> {
  logger.debug(`Deleting user...`);

  const deletUserParams = {
    AccessToken: accessToken
  };

  const deleteUserCommand = new DeleteUserCommand(deletUserParams);

  return cognitoClient.send(deleteUserCommand);
}

export async function processValidateUsername(
  logger: Logger,
  pgClient: PgClient,
  username: string,
  existingUid?: string
): Promise<boolean> {
  const usernameRegex = new RegExp(/^[a-zA-Z0-9]{5,20}$/);

  if (!username.match(usernameRegex)?.length) {
    throw new Error('Username must be between 5 and 20 characters with no special characters');
  }

  const { rows } = await repository.validateUsername(pgClient, username, existingUid);

  if (rows.length) {
    throw new Error('Username unavailable');
  }

  return true;
}

export async function getUserByHashId(
  logger: Logger,
  pgClient: PgClient,
  hashId: string
): Promise<any> {
  logger.debug(`Getting user data by hash id`);

  const { rows } = await repository.getUserByHashId(pgClient, hashId);

  return rows[0];
}

export async function saveUserVerification(
  logger: Logger,
  pgClient: PgClient,
  id: string
): Promise<any> {
  logger.debug(`Getting user data by hash id`);

  const { rows } = await repository.saveUserVerification(pgClient, id);

  return rows[0];
}

export function getUserNameFromEmail(email: string): string {
  return email.split('@')[0];
}

export async function getUserById(logger: Logger, pgClient: PgClient, uid: string): Promise<any> {
  logger.debug(`Getting user data by id`);

  const { rows } = await repository.getUserById(pgClient, uid);

  return rows[0];
}

export function processUpdateUserAttributes(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  userAttributes: { Name: string; Value: string }[]
): Promise<UpdateUserAttributesCommandOutput> {
  logger.debug(`Updating user auth attributes`, { userAttributes });

  const updateUserAttributesCommandInput = {
    AccessToken: accessToken,
    UserAttributes: userAttributes
  };

  const updateUserAttributesCommand = new UpdateUserAttributesCommand(
    updateUserAttributesCommandInput
  );

  return cognitoClient.send(updateUserAttributesCommand);
}

export function processSendUserAttributesVerificationCode(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  attributeName: string
): Promise<GetUserAttributeVerificationCodeCommandOutput> {
  logger.debug(`Sending user auth attribute update verification code`, { attributeName });

  const getUserAttributeVerificationCodeCommandInput = {
    AccessToken: accessToken,
    AttributeName: attributeName
  };

  const getUserAttributeVerificationCodeCommand = new GetUserAttributeVerificationCodeCommand(
    getUserAttributeVerificationCodeCommandInput
  );

  return cognitoClient.send(getUserAttributeVerificationCodeCommand);
}

export function processConfirmUserAttributesVerificationCode(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  attributeName: string,
  verificationCode: string
): Promise<VerifyUserAttributeCommandOutput> {
  logger.debug(`Confirming user auth attribute update verification code`, { attributeName });

  const verifyUserAttributeCommandInput = {
    AccessToken: accessToken,
    AttributeName: attributeName,
    Code: verificationCode
  };

  const verifyUserAttributeCommand = new VerifyUserAttributeCommand(
    verifyUserAttributeCommandInput
  );

  return cognitoClient.send(verifyUserAttributeCommand);
}

export function formatAuthTokenResponse(
  response: InitiateAuthCommandOutput
): AuthTokenResponse | AuthMfaChallengeResponse {
  if (response.AuthenticationResult) {
    const {
      IdToken: idToken,
      RefreshToken: refreshToken,
      ExpiresIn: expiresIn
    } = response.AuthenticationResult;

    return {
      idToken,
      refreshToken,
      expiresIn
    } as AuthTokenResponse;
  } else if (response.ChallengeName) {
    const {
      ChallengeName: challengeName,
      ChallengeParameters: challengeParameters,
      Session: session
    } = response;

    return {
      challengeName,
      challengeParameters,
      session
    } as AuthMfaChallengeResponse;
  }

  throw new Error('Unrecognized auth command output');
}

export function getAuthenticatedUserData(
  logger: Logger,
  event: APIGatewayProxyEvent
): AuthUserData {
  logger.debug(`Getting authenticated user data from token`);

  try {
    const token = event.headers['Authorization']?.substring(7);

    if (!token) {
      throw new Error(`Auth token not found`);
    }

    const decodedToken = jwt.decode(token) as ExtendedJwtPayload;

    if (!decodedToken.sub || !decodedToken.email) {
      throw new Error('Token is missing necessary claims');
    }

    return {
      id: decodedToken.sub,
      email: decodedToken.email
    };
  } catch (err: any) {
    logger.error(`Failed to parse user data`);
    throw err;
  }
}
