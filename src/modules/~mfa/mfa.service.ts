import {
  AdminSetUserMFAPreferenceCommand,
  AdminSetUserMFAPreferenceCommandOutput,
  AssociateSoftwareTokenCommand,
  ChallengeNameType,
  CognitoIdentityProviderClient,
  RespondToAuthChallengeCommand,
  VerifySoftwareTokenCommand
} from '@aws-sdk/client-cognito-identity-provider';
import { Logger } from 'winston';
import qrcode from 'qrcode';
import PgClient from 'serverless-postgres';
import * as repository from './mfa.repository';
import { generateAuthSecretHash } from 'src/util/hash.util';

const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || '';
const COGNITO_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET || '';
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || '';

export function processSetUserMfaSmsPreference(
  logger: Logger,
  cognitoClient: CognitoIdentityProviderClient,
  accessToken: string,
  email: string
): Promise<AdminSetUserMFAPreferenceCommandOutput> {
  logger.debug(`Setting mfa sms preferences`);

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
  logger.debug(`Associating software token to user`);

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
  logger.debug(`Verifying software token`);

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
  logger.debug(`Challenging mfa software token`);

  const secretHash = generateAuthSecretHash(email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET);

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
  logger.debug(`Setting mfa totp preferences`);

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
