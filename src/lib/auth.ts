import {
  AuthFlowType,
  CognitoIdentityProviderClient,
  ConfirmForgotPasswordCommand,
  ConfirmSignUpCommand,
  DeleteUserCommand,
  ForgotPasswordCommand,
  InitiateAuthCommand,
  InitiateAuthCommandOutput,
  SignUpCommand,
  SignUpCommandOutput,
  UpdateUserAttributesCommand,
  UpdateUserAttributesCommandOutput,
  AdminSetUserMFAPreferenceCommand,
  AdminSetUserMFAPreferenceCommandOutput,
  AssociateSoftwareTokenCommand,
  ChallengeNameType,
  RespondToAuthChallengeCommand,
  VerifySoftwareTokenCommand,
  ConfirmSignUpCommandOutput,
  ForgotPasswordCommandOutput,
  ConfirmForgotPasswordCommandOutput
} from '@aws-sdk/client-cognito-identity-provider';
import { APIGatewayProxyEvent, PolicyDocument } from 'aws-lambda';
import jwt from 'jsonwebtoken';
import { ExtendedJwtPayload } from 'src/types/jwt.types';
import {
  AuthMfaChallengeResponse,
  AuthTokenResponse,
  AuthUserData,
  OAuthTokenCredentials
} from 'src/types/auth.types';
import qrcode from 'qrcode';
import { PolicyEffect } from 'src/types/aws.types';

export function authenticate(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string,
  clientId: string,
  secretHash: string
): Promise<InitiateAuthCommandOutput> {
  const initiateAuthParams = {
    AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
    ClientId: clientId,
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
      SECRET_HASH: secretHash
    }
  };

  const initiateAuthParamsCommand = new InitiateAuthCommand(initiateAuthParams);

  return cognitoClient.send(initiateAuthParamsCommand);
}

export function register(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string,
  clientId: string,
  secretHash: string,
  userAttributes: { Name: string; Value: string }[]
): Promise<SignUpCommandOutput> {
  const signUpParams = {
    ClientId: clientId,
    SecretHash: secretHash,
    Username: email,
    Password: password,
    UserAttributes: userAttributes
  };

  const signUpCommand = new SignUpCommand(signUpParams);

  return cognitoClient.send(signUpCommand);
}

export function refreshToken(
  cognitoClient: CognitoIdentityProviderClient,
  REFRESH_TOKEN: string,
  clientId: string,
  clientSecret: string
): Promise<InitiateAuthCommandOutput> {
  const initiateAuthParams = {
    AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
    ClientId: clientId,
    AuthParameters: {
      REFRESH_TOKEN,
      SECRET_HASH: clientSecret
    }
  };

  const initiateAuthCommand = new InitiateAuthCommand(initiateAuthParams);

  return cognitoClient.send(initiateAuthCommand);
}

export function confirmAuthenticationCode(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  confirmationCode: string,
  clientId: string,
  secretHash: string
): Promise<ConfirmSignUpCommandOutput> {
  const confirmSignUpParams = {
    ClientId: clientId,
    SecretHash: secretHash,
    Username: email,
    ConfirmationCode: confirmationCode
  };

  const confirmSignUpCommand = new ConfirmSignUpCommand(confirmSignUpParams);

  return cognitoClient.send(confirmSignUpCommand);
}

export function forgotPassword(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  clientId: string,
  secretHash: string
): Promise<ForgotPasswordCommandOutput> {
  const forgotPasswordParams = {
    ClientId: clientId,
    SecretHash: secretHash,
    Username: email
  };

  const forgotPasswordCommand = new ForgotPasswordCommand(forgotPasswordParams);

  return cognitoClient.send(forgotPasswordCommand);
}

export function confirmForgotPassword(
  cognitoClient: CognitoIdentityProviderClient,
  email: string,
  password: string,
  confirmationCode: string,
  clientId: string,
  secretHash: string
): Promise<ConfirmForgotPasswordCommandOutput> {
  const confirmForgotPasswordParams = {
    ClientId: clientId,
    SecretHash: secretHash,
    Username: email,
    ConfirmationCode: confirmationCode,
    Password: password
  };

  const confirmPasswordCommand = new ConfirmForgotPasswordCommand(confirmForgotPasswordParams);

  return cognitoClient.send(confirmPasswordCommand);
}

export function updateUserAttributes(
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  userAttributes: { Name: string; Value: string }[]
): Promise<UpdateUserAttributesCommandOutput> {
  const updateUserAttributesCommandInput = {
    AccessToken: accessToken,
    UserAttributes: userAttributes
  };

  const updateUserAttributesCommand = new UpdateUserAttributesCommand(
    updateUserAttributesCommandInput
  );

  return cognitoClient.send(updateUserAttributesCommand);
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

export function getAuthenticatedUserData(event: APIGatewayProxyEvent): AuthUserData {
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
}

export async function deleteUser(
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string
): Promise<any> {
  const deletUserParams = {
    AccessToken: accessToken
  };

  const deleteUserCommand = new DeleteUserCommand(deletUserParams);

  return cognitoClient.send(deleteUserCommand);
}

export function adminSetUserMfaPreference(
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  email: string,
  userPoolId: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  const adminSetUserMFAPreferenceCommandInput = {
    SMSMfaSettings: {
      Enabled: true,
      PreferredMfa: true
    },
    Username: email,
    UserPoolId: userPoolId!,
    AccessToken: accessToken
  };

  const adminSetUserMFAPreferenceCommand = new AdminSetUserMFAPreferenceCommand(
    adminSetUserMFAPreferenceCommandInput
  );

  return cognitoClient.send(adminSetUserMFAPreferenceCommand);
}

export function associcateSoftwareToken(
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  const associateSoftwareTokenCommandInput = {
    AccessToken: accessToken
  };

  const associateSoftwareTokenCommand = new AssociateSoftwareTokenCommand(
    associateSoftwareTokenCommandInput
  );

  return cognitoClient.send(associateSoftwareTokenCommand);
}

export function verifySoftwareToken(
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  userCode: string,
  friendlyDeviceName?: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
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

export function challengeSofwareToken(
  cognitoClient: CognitoIdentityProviderClient,
  userCode: string,
  email: string,
  session: string,
  clientId: string,
  secretHash: string
): Promise<any> {
  const respondToAuthChallengeCommandInput = {
    ChallengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
    ClientId: clientId,
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

export function adminSetUserMfaTotpPreference(
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  email: string,
  enabled: boolean,
  userPoolId: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  const adminSetUserMFAPreferenceCommandInput = {
    Username: email,
    UserPoolId: userPoolId!,
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

export function generateTotpQrCodeUrl(
  secretCode: string,
  email: string,
  issuer: string
): Promise<string> {
  const totpUri = `otpauth://totp/${email}?secret=${secretCode}&issuer=${issuer}`;
  return qrcode.toDataURL(totpUri);
}

export function generateAuthMfaTotpQrCodeUrl(
  secret: string,
  email: string,
  issuer: string
): Promise<string> {
  // const encodedSecret = Buffer.from(secret).toString('base64');
  const encodedEmail = encodeURIComponent(email);
  const encodedIssuer = encodeURIComponent(issuer);

  const totpUri = `otpauth://totp/${encodedIssuer}:${encodedEmail}?secret=${secret}&issuer=${encodedIssuer}`;

  return qrcode.toDataURL(totpUri);
}

export async function getIdpAuthCredentials(
  code: string,
  clientId: string,
  clientSecret: string,
  userPoolDomain: string,
  oauthCallbackUrl: string,
  oauthGrantTypeAuthCode: string
): Promise<OAuthTokenCredentials> {
  const basicAuth = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;

  const requestBody = new URLSearchParams({
    grant_type: oauthGrantTypeAuthCode,
    client_id: clientId,
    code,
    redirect_uri: oauthCallbackUrl
  });

  const response = await fetch(`${userPoolDomain}/oauth2/token`, {
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
