import {
  AdminSetUserMFAPreferenceCommand,
  AdminSetUserMFAPreferenceCommandOutput,
  AssociateSoftwareTokenCommand,
  AuthFlowType,
  ChallengeNameType,
  CognitoIdentityProviderClient,
  ConfirmForgotPasswordCommand,
  ConfirmSignUpCommand,
  DeleteUserCommand,
  ForgotPasswordCommand,
  GetUserAttributeVerificationCodeCommand,
  GetUserAttributeVerificationCodeCommandOutput,
  InitiateAuthCommand,
  InitiateAuthCommandOutput,
  RespondToAuthChallengeCommand,
  SignUpCommand,
  SignUpCommandOutput,
  UpdateUserAttributesCommand,
  UpdateUserAttributesCommandOutput,
  VerifySoftwareTokenCommand,
  VerifyUserAttributeCommand,
  VerifyUserAttributeCommandOutput
} from '@aws-sdk/client-cognito-identity-provider';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { APIGatewayProxyEvent, PolicyDocument } from 'aws-lambda';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { Moment } from 'moment-timezone';
import { PolicyEffect } from 'src/types/aws.types';
import { ExtendedJwtPayload } from 'src/types/jwt.types';
import * as crypto from 'crypto';
import * as repository from './auth.repository';
import PgClient from 'serverless-postgres';
import { User } from './auth.types';
import { GuardOptions } from 'src/types/system.types';
import { Logger } from 'winston';
import { AuthConflictError, ForbiddenError, UnauthorizedError } from 'src/lib/errors';
import qrcode from 'qrcode';
import {
  AuthMfaChallengeResponse,
  AuthTokenResponse,
  AuthUserData,
  OAuthTokenCredentials
} from 'src/types/auth.types';
import parser from 'lambda-multipart-parser';

const COGNITO_VERIFIER_TOKEN = 'id';
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || '';
const COGNITO_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET || '';
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || '';
const COGNITO_USER_POOL_DOMAIN = process.env.COGNITO_USER_POOL_DOMAIN || '';
const COGNITO_OAUTH_CALLBACK_URL = process.env.COGNITO_OAUTH_CALLBACK_URL || '';
const COGNITO_SIGNUP_USER_ATTRIBUTE_NAME = 'email';
const AUTH_HASH_ID_SECRET = process.env.AUTH_HASH_ID_SECRET || '';
const OAUTH_GRANT_TYPE_AUTH_CODE = 'authorization_code';

function generateAuthSecretHash(field: string): string {
  return crypto
    .createHmac('SHA256', COGNITO_CLIENT_SECRET)
    .update(field + COGNITO_CLIENT_ID)
    .digest('base64');
}

export function generateAuthHashId(email: string): string {
  return crypto
    .createHmac('SHA256', AUTH_HASH_ID_SECRET)
    .update(email + AUTH_HASH_ID_SECRET)
    .digest('base64');
}

export function processAuthentication(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string
): Promise<InitiateAuthCommandOutput> {
  console.info(`Authenticating...`);

  const secretHash = generateAuthSecretHash(email);

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

  const secretHash = generateAuthSecretHash(email);

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
  const secretHash = generateAuthSecretHash(email);

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
  const secretHash = generateAuthSecretHash(email);

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
  const secretHash = generateAuthSecretHash(email);

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
  logger.info(`Getting authenticated user data`, {
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
  logger.info(`Deleting user...`);

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
  logger.info(`Getting user data by hash id`);

  const { rows } = await repository.getUserByHashId(pgClient, hashId);

  return rows[0];
}

export async function saveUserVerification(
  logger: Logger,
  pgClient: PgClient,
  id: string
): Promise<any> {
  logger.info(`Getting user data by hash id`);

  const { rows } = await repository.saveUserVerification(pgClient, id);

  return rows[0];
}

export function getUserNameFromEmail(email: string): string {
  return email.split('@')[0];
}

export async function getUserById(logger: Logger, pgClient: PgClient, uid: string): Promise<any> {
  logger.info(`Getting user data by id`);

  const { rows } = await repository.getUserById(pgClient, uid);

  return rows[0];
}

export function processUpdateUserAttributes(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  userAttributes: { Name: string; Value: string }[]
): Promise<UpdateUserAttributesCommandOutput> {
  logger.info(`Updating user auth attributes`, { userAttributes });

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
  logger.info(`Sending user auth attribute update verification code`, { attributeName });

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
  logger.info(`Confirming user auth attribute update verification code`, { attributeName });

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

export function processSetUserMfaSmsPreference(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  email: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  logger.info(`Setting mfa sms preferences`);

  const adminSetUserMFAPreferenceCommandInput = {
    SMSMfaSettings: {
      Enabled: true,
      PreferredMfa: true
    },
    Username: email,
    UserPoolId: COGNITO_USER_POOL_ID!,
    AccessToken: accessToken
  };

  const adminSetUserMFAPreferenceCommand = new AdminSetUserMFAPreferenceCommand(
    adminSetUserMFAPreferenceCommandInput
  );

  return cognitoClient.send(adminSetUserMFAPreferenceCommand);
}

export function processAssociateSoftwareToken(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  logger.info(`Associating software token to user`);

  const associateSoftwareTokenCommandInput = {
    AccessToken: accessToken
  };

  const associateSoftwareTokenCommand = new AssociateSoftwareTokenCommand(
    associateSoftwareTokenCommandInput
  );

  return cognitoClient.send(associateSoftwareTokenCommand);
}

export function processVerifySoftwareToken(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  userCode: string,
  friendlyDeviceName?: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  logger.info(`Verifying software token`);

  const verifySoftwareTokenCommandInput = {
    AccessToken: accessToken,
    UserCode: userCode
    // FriendlyDeviceName: friendlyDeviceName
  };

  const verifySoftwareTokenCommand = new VerifySoftwareTokenCommand(
    verifySoftwareTokenCommandInput
  );

  return cognitoClient.send(verifySoftwareTokenCommand);
}

export function processChallengeSoftwareToken(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  userCode: string,
  email: string,
  session: string
): Promise<any> {
  logger.info(`Challenging mfa software token`);

  const secretHash = generateAuthSecretHash(email);

  const respondToAuthChallengeCommandInput = {
    ChallengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
    ClientId: COGNITO_CLIENT_ID,
    Session: session,
    ChallengeResponses: {
      SECRET_HASH: secretHash,
      USERNAME: email,
      SOFTWARE_TOKEN_MFA_CODE: userCode
    }
  };

  const respondToAuthChallengeCommand = new RespondToAuthChallengeCommand(
    respondToAuthChallengeCommandInput
  );

  return cognitoClient.send(respondToAuthChallengeCommand);
}

export function processSetUserMfaTotpPreference(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  email: string,
  enabled: boolean
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  logger.info(`Setting mfa totp preferences`);

  const adminSetUserMFAPreferenceCommandInput = {
    Username: email,
    UserPoolId: COGNITO_USER_POOL_ID!,
    AccessToken: accessToken,
    SoftwareTokenMfaSettings: {
      Enabled: enabled,
      PreferredMfa: enabled
    }
  };

  const adminSetUserMFAPreferenceCommand = new AdminSetUserMFAPreferenceCommand(
    adminSetUserMFAPreferenceCommandInput
  );

  return cognitoClient.send(adminSetUserMFAPreferenceCommand);
}

export function generateTotpQrCodeUrl(secretCode: string, email: string): Promise<string> {
  const totpUri = `otpauth://totp/${email}?secret=${secretCode}&issuer=relayBox`;
  return qrcode.toDataURL(totpUri);
}

export async function setMfaEnabled(
  logger: Logger,
  pgClient: PgClient,
  uid: string
): Promise<void> {
  logger.info(`Saving mfa enabled`, { uid });

  const result = await repository.setMfaEnabled(pgClient, uid);
}

export async function setMfaDisabled(
  logger: Logger,
  pgClient: PgClient,
  uid: string
): Promise<void> {
  logger.info(`Saving mfa disabled`, { uid });

  const result = await repository.setMfaDisabled(pgClient, uid);
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
  logger.info(`Getting authenticated user data from token`);

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

export async function getIdpAuthCredentials(
  logger: Logger,
  code: string
): Promise<OAuthTokenCredentials> {
  logger.info(`Fetching auth credentials from cognito oauth token endpoint`);

  const basicAuth = `Basic ${Buffer.from(`${COGNITO_CLIENT_ID}:${COGNITO_CLIENT_SECRET}`).toString(
    'base64'
  )}`;

  const requestBody = new URLSearchParams({
    grant_type: OAUTH_GRANT_TYPE_AUTH_CODE,
    client_id: COGNITO_CLIENT_ID,
    code,
    redirect_uri: COGNITO_OAUTH_CALLBACK_URL
  });

  const response = await fetch(`${COGNITO_USER_POOL_DOMAIN}/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: basicAuth,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: requestBody.toString()
  });

  const data = await response.json();

  return <OAuthTokenCredentials>data;
}

export async function syncIdpUser(
  logger: Logger,
  pgClient: PgClient,
  idToken: string
): Promise<void> {
  logger.info(`Syncing idp user to local database`);

  const {
    email,
    sub: id,
    identities,
    preferred_username: preferredUsername
  } = <ExtendedJwtPayload>jwt.decode(idToken);

  const hashId = generateAuthHashId(email!);
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
  logger.info(`Getting idp user from local database`);

  const { sub: uid } = <ExtendedJwtPayload>jwt.decode(idToken);

  return getUserById(logger, pgClient, uid!);
}

export async function getGitHubAuthToken(
  logger: Logger,
  event: APIGatewayProxyEvent
): Promise<any> {
  logger.info(`Exchanging auth code for GitHub access tokens`);

  try {
    const { client_id, client_secret, code } = await parser.parse(event);

    const queryParams = new URLSearchParams({
      client_id,
      client_secret,
      code
    });

    const requestUrl = `https://github.com/login/oauth/access_token?${queryParams}`;

    const response = await fetch(requestUrl, {
      method: 'POST',
      headers: {
        accept: 'application/json'
      }
    });

    const token = await response.json();

    return token;
  } catch (err: any) {
    logger.error(`Failed to get GitHub auth token`, { err });
    throw err;
  }
}

export async function getGitHubUserData(logger: Logger, authorization: string): Promise<any> {
  logger.info(`Fetching GitHub user data`);

  try {
    const response = await fetch(`https://api.github.com/user`, {
      method: 'GET',
      headers: {
        authorization,
        accept: 'application/json'
      }
    });

    const userData = <any>await response.json();

    return userData;
  } catch (err: any) {
    logger.error(`Failed to fetch GitHub user data`, { err });
    throw err;
  }
}

export async function getGitHubUserPrimaryEmail(
  logger: Logger,
  authorization: string
): Promise<any> {
  logger.info(`Fetching GitHub user email`);

  try {
    const response = await fetch(`https://api.github.com/user/emails`, {
      method: 'GET',
      headers: {
        authorization,
        accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    });

    const emailData = <any>await response.json();
    const primaryEmail = emailData.find((data: any) => data.primary);

    return primaryEmail.email;
  } catch (err: any) {
    logger.error(`Failed to fetch GitHub user primary email`, { err });
    throw err;
  }
}
