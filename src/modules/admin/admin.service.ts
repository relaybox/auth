import PgClient from 'serverless-postgres';
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommandOutput,
  SignUpCommandOutput,
  AdminSetUserMFAPreferenceCommandOutput,
  ConfirmSignUpCommandOutput,
  ForgotPasswordCommandOutput,
  ConfirmForgotPasswordCommandOutput
} from '@aws-sdk/client-cognito-identity-provider';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { APIGatewayProxyEvent } from 'aws-lambda';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { Moment } from 'moment-timezone';
import { ExtendedJwtPayload } from 'src/types/jwt.types';
import * as repository from './admin.repository';
import { GuardOptions } from 'src/types/system.types';
import { Logger } from 'winston';
import { AuthConflictError, ForbiddenError, UnauthorizedError } from 'src/lib/errors';
import { OAuthTokenCredentials, User } from 'src/types/auth.types';
import { generateAuthHashId, generateAuthSecretHash } from 'src/util/hash.util';
import {
  adminSetUserMfaPreference,
  adminSetUserMfaTotpPreference,
  associcateSoftwareToken,
  authenticate,
  challengeSofwareToken,
  confirmAuthenticationCode,
  confirmForgotPassword,
  forgotPassword,
  getIdpAuthCredentials,
  refreshToken,
  register,
  verifySoftwareToken
} from 'src/lib/auth';

const COGNITO_VERIFIER_TOKEN = 'id';
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || '';
const COGNITO_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET || '';
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || '';
const COGNITO_USER_POOL_DOMAIN = process.env.COGNITO_USER_POOL_DOMAIN || '';
const COGNITO_SIGNUP_USER_ATTRIBUTE_NAME = 'email';
const COGNITO_OAUTH_CALLBACK_URL = process.env.COGNITO_OAUTH_CALLBACK_URL || '';
const OAUTH_GRANT_TYPE_AUTH_CODE = 'authorization_code';
const AUTH_HASH_ID_SECRET = process.env.AUTH_HASH_ID_SECRET || '';

export function processAuthentication(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string
): Promise<InitiateAuthCommandOutput> {
  logger.debug(`Authenticating...`);

  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  return authenticate(cognitoClient, email, password, COGNITO_CLIENT_ID, secretHash);
}

export function processRegistration(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string
): Promise<SignUpCommandOutput> {
  logger.debug(`Registering...`);

  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  const userAttributes = [
    {
      Name: COGNITO_SIGNUP_USER_ATTRIBUTE_NAME,
      Value: email
    }
  ];

  return register(cognitoClient, email, password, COGNITO_CLIENT_ID, secretHash, userAttributes);
}

export function processCodeConfirmation(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  confirmationCode: string
): Promise<ConfirmSignUpCommandOutput> {
  logger.debug(`Confirming authentication code...`);

  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  return confirmAuthenticationCode(
    cognitoClient,
    email,
    confirmationCode,
    COGNITO_CLIENT_ID,
    secretHash
  );
}

export function processForgotPassword(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  email: string
): Promise<ForgotPasswordCommandOutput> {
  logger.debug(`Forgot password...`);

  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  return forgotPassword(cognitoClient, email, COGNITO_CLIENT_ID, secretHash);
}

export function processConfirmForgotPassword(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string,
  confirmationCode: string
): Promise<ConfirmForgotPasswordCommandOutput> {
  logger.debug(`Confirming forgot password...`);

  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  return confirmForgotPassword(
    cognitoClient,
    email,
    password,
    confirmationCode,
    COGNITO_CLIENT_ID,
    secretHash
  );
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
  return refreshToken(cognitoClient, REFRESH_TOKEN, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);
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

export async function completeAuthentication(logger: Logger, pgClient: PgClient, idToken: string) {
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

// export async function processDeleteAuthenticatedUser(
//   logger: Logger,
//   cognitoClient: CognitoIdentityProviderClient,
//   accessToken: string
// ): Promise<any> {
//   logger.debug(`Deleting user...`);

//   const deletUserParams = {
//     AccessToken: accessToken
//   };

//   const deleteUserCommand = new DeleteUserCommand(deletUserParams);

//   return cognitoClient.send(deleteUserCommand);
// }

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

export async function processGetIdpAuthCredentials(
  logger: Logger,
  code: string
): Promise<OAuthTokenCredentials> {
  logger.debug(`getting idp auth credentials`);

  return getIdpAuthCredentials(
    code,
    COGNITO_CLIENT_ID,
    COGNITO_CLIENT_SECRET,
    COGNITO_USER_POOL_DOMAIN,
    COGNITO_OAUTH_CALLBACK_URL,
    OAUTH_GRANT_TYPE_AUTH_CODE
  );
}

export async function syncIdpUser(
  logger: Logger,
  pgClient: PgClient,
  idToken: string
): Promise<void> {
  logger.debug(`Syncing idp user to local database`);

  const {
    email,
    sub: id,
    identities,
    preferred_username: preferredUsername
  } = <ExtendedJwtPayload>jwt.decode(idToken);

  const hashId = generateAuthHashId(email!, AUTH_HASH_ID_SECRET);
  const username = preferredUsername || getUserNameFromEmail(email!);

  if (!id || !username || !hashId) {
    throw new Error(`Failed to parse user data from token`);
  }

  try {
    await repository.syncIdpUser(
      pgClient,
      id,
      username,
      hashId,
      <string>identities?.[0]?.providerName
    );
  } catch (err: any) {
    if (err.message.includes(`duplicate key`)) {
      throw new AuthConflictError(`Existing user found`);
    } else {
      throw err;
    }
  }
}

export async function getIdpUser(
  logger: Logger,
  pgClient: PgClient,
  idToken: string
): Promise<User> {
  logger.debug(`Getting idp user from local database`);

  const { sub: uid } = <ExtendedJwtPayload>jwt.decode(idToken);

  return getUserById(logger, pgClient, uid!);
}

export function processSetUserMfaSmsPreference(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  email: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  logger.debug(`Setting mfa sms preferences`);

  return adminSetUserMfaPreference(cognitoClient, accessToken, email, COGNITO_USER_POOL_ID!);
}

export function processAssociateSoftwareToken(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  logger.debug(`Associating software token to user`);

  return associcateSoftwareToken(cognitoClient, accessToken);
}

export function processVerifySoftwareToken(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  userCode: string,
  friendlyDeviceName?: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  logger.debug(`Verifying software token`);

  return verifySoftwareToken(cognitoClient, accessToken, userCode, friendlyDeviceName);
}

export function processChallengeSoftwareToken(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  userCode: string,
  email: string,
  session: string
): Promise<any> {
  logger.debug(`Challenging mfa software token`);

  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

  return challengeSofwareToken(
    cognitoClient,
    userCode,
    email,
    session,
    COGNITO_CLIENT_ID,
    secretHash
  );
}

export function processSetUserMfaTotpPreference(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  email: string,
  enabled: boolean
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  logger.debug(`Setting mfa totp preferences`);

  return adminSetUserMfaTotpPreference(
    cognitoClient,
    accessToken,
    email,
    enabled,
    COGNITO_USER_POOL_ID!
  );
}

export async function setMfaEnabled(
  logger: Logger,
  pgClient: PgClient,
  uid: string
): Promise<void> {
  logger.debug(`Saving mfa enabled`, { uid });

  const result = await repository.setMfaEnabled(pgClient, uid);
}

export async function setMfaDisabled(
  logger: Logger,
  pgClient: PgClient,
  uid: string
): Promise<void> {
  logger.debug(`Saving mfa disabled`, { uid });

  const result = await repository.setMfaDisabled(pgClient, uid);
}
