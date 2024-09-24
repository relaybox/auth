import { nanoid } from 'nanoid';
import * as repository from './users.repository';
import PgClient from 'serverless-postgres';
import {
  decrypt,
  encrypt,
  generateHash,
  generateSalt,
  getKeyVersion,
  strongHash
} from 'src/lib/encryption';
import { Logger } from 'winston';
import {
  AuthenticationError,
  ForbiddenError,
  NotFoundError,
  PasswordRegexError,
  UnauthorizedError,
  ValidationError
} from 'src/lib/errors';
import {
  AuthenticationAction,
  AuthenticationActionLog,
  AuthenticationActionResult,
  AuthMfaFactorType,
  AuthProvider,
  AuthStorageType,
  AuthUser,
  AuthUserIdentityCredentials,
  AuthUserSession,
  AuthVerificationCodeType,
  RequestAuthParams
} from 'src/types/auth.types';
import { smtpTransport } from 'src/lib/smtp';
import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  uniqueNamesGenerator,
  adjectives,
  animals,
  NumberDictionary
} from 'unique-names-generator';
import { authenticator } from 'otplib';
import {
  decodeAuthToken,
  getAuthRefreshToken,
  getAuthToken,
  getTmpToken,
  verifyAuthToken
} from 'src/lib/token';

const SMTP_AUTH_EMAIL = process.env.SMTP_AUTH_EMAIL || '';

export async function createUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  appId: string,
  email: string,
  autoVerify: boolean = false,
  username?: string,
  firstName?: string,
  lastName?: string
): Promise<AuthUser> {
  logger.debug(`Creating user`, { orgId });

  const numberDictionary = NumberDictionary.generate({
    min: 100,
    max: 999
  });

  username =
    username ||
    uniqueNamesGenerator({
      dictionaries: [adjectives, animals, numberDictionary],
      separator: '',
      style: 'capital'
    });

  const clientId = nanoid(12);
  const encryptedEmail = encrypt(email);
  const emailHash = generateHash(email);

  try {
    const { rows } = await repository.createUser(
      pgClient,
      orgId,
      appId,
      clientId,
      encryptedEmail,
      emailHash,
      autoVerify,
      username,
      firstName,
      lastName
    );

    logger.info(`User created`, { orgId, clientId, id: rows[0].id });

    return rows[0];
  } catch (err: any) {
    if (err.message.includes(`duplicate key`)) {
      logger.warn(`User already exists`, { err });
    } else {
      logger.error(`Failed to create user`, { err });
    }

    throw new AuthenticationError(`Failed to create user`);
  }
}

export async function createUserIdentity(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  email: string,
  password: string,
  provider?: AuthProvider,
  providerId?: string,
  autoVerify: boolean = false
): Promise<AuthUser> {
  logger.debug(`Creating user identity`, { uid, provider });

  const encryptedEmail = encrypt(email);
  const emailHash = generateHash(email);
  const salt = generateSalt();
  const passwordHash = strongHash(password, salt);
  const keyVersion = getKeyVersion();

  try {
    const { rows } = await repository.createUserIdentity(
      pgClient,
      uid,
      encryptedEmail,
      emailHash,
      passwordHash,
      salt,
      keyVersion,
      provider,
      providerId,
      autoVerify
    );

    logger.info(`User identity created`, { uid, id: rows[0].id });

    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to create user`, { err });
    throw err;
  }
}

export async function updateUserData(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  userData: { key: string; value: string }[]
): Promise<void> {
  logger.debug(`Updating user data`, { uid, fields: Object.keys(userData) });

  const { rows } = await repository.updateUserData(pgClient, uid, userData);

  return rows[0];
}

export async function updateUserIdentityData(
  logger: Logger,
  pgClient: PgClient,
  identityId: string,
  userData: { key: string; value: string }[]
): Promise<void> {
  logger.debug(`Updating user idenitity data`, { identityId, fields: Object.keys(userData) });

  const { rows } = await repository.updateUserIdentityData(pgClient, identityId, userData);

  return rows[0];
}

export async function getUserByEmail(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  appId: string,
  email: string
): Promise<any> {
  logger.debug(`Getting user by email`);

  const emailHash = generateHash(email);

  const { rows } = await repository.getUserByEmailHash(pgClient, appId, emailHash);

  return rows[0];
}

export async function getUserIdentityByEmail(
  logger: Logger,
  pgClient: PgClient,
  appId: string,
  email: string,
  provider?: AuthProvider,
  authenticationActionLog?: AuthenticationActionLog
): Promise<AuthUserIdentityCredentials> {
  logger.debug(`Getting user by email identity`);

  const emailHash = generateHash(email);

  const { rows } = await repository.getUserIdentityByEmailHash(
    pgClient,
    appId,
    emailHash,
    provider
  );

  if (rows.length && authenticationActionLog) {
    authenticationActionLog.identityId = rows[0].identityId;
    authenticationActionLog.uid = rows[0].uid;
  }

  return rows[0];
}

export async function getUserIdentityByProviderId(
  logger: Logger,
  pgClient: PgClient,
  appId: string,
  providerId: string,
  provider: AuthProvider
): Promise<any> {
  logger.debug(`Getting user by provider id`);

  const { rows } = await repository.getUserIdentityByProviderId(
    pgClient,
    appId,
    providerId,
    provider
  );

  return rows[0];
}

export async function getAuthDataByKeyId(
  logger: Logger,
  pgClient: PgClient,
  keyId: string,
  authenticationActionLog?: AuthenticationActionLog
): Promise<{ orgId: string; appId: string; appPid: string; secretKey: string }> {
  logger.debug(`Getting secure auth data by key id`);

  const { rows } = await repository.getAuthDataByKeyId(pgClient, keyId);

  if (!rows.length) {
    throw new NotFoundError(`Secure auth data not found`);
  }

  if (authenticationActionLog) {
    authenticationActionLog.appId = rows[0].appId;
  }

  return rows[0];
}

export async function sendAuthVerificationCode(
  logger: Logger,
  email: string,
  code: number
): Promise<string> {
  logger.debug(`Sending auth verification code`);

  try {
    const options = {
      from: SMTP_AUTH_EMAIL,
      to: email,
      subject: 'Verification Code',
      text: `Your code is ${code}`
    };

    const result = await smtpTransport.sendMail(options);

    return result?.messageId;
  } catch (err: any) {
    logger.error(`Failed to send contact request email`);
    throw err;
  }
}

export function getKeyParts(publicKey: string): { appPid: string; keyId: string } {
  const [appPid, keyId] = publicKey.split('.');

  return { appPid, keyId };
}

export function getRequestAuthParams(
  event: APIGatewayProxyEvent,
  authenticationActionLog?: AuthenticationActionLog
): RequestAuthParams {
  const headers = event.headers;
  const publicKey = headers['X-Ds-Public-Key'] || headers['x-ds-public-key'];

  if (!publicKey) {
    throw new ValidationError('Missing X-Ds-Public-Key header');
  }

  const { appPid, keyId } = getKeyParts(publicKey);

  if (authenticationActionLog) {
    authenticationActionLog.keyId = keyId;
  }

  return { publicKey, appPid, keyId };
}

export async function getUserDataByClientId(
  logger: Logger,
  pgClient: PgClient,
  appId: string,
  clientId: string
): Promise<AuthUser | undefined> {
  logger.debug(`Getting user data for client id`, { clientId });

  const { rows } = await repository.getUserDataByClientId(pgClient, clientId);

  return rows[0];
}

export async function getUserDataById(
  logger: Logger,
  pgClient: PgClient,
  id: string
): Promise<AuthUser> {
  logger.debug(`Getting user data for user id: ${id}`, { id });

  const { rows } = await repository.getUserDataById(pgClient, id);

  if (!rows.length) {
    throw new NotFoundError(`Session user not found`);
  }

  const { email } = rows[0];

  const userData = {
    ...rows[0],
    email: decrypt(email)
  };

  return userData;
}

export async function authorizeClientRequest(
  logger: Logger,
  pgClient: PgClient,
  token: string,
  matchTokenType?: string
): Promise<any> {
  const { sub: id, publicKey, tokenType } = decodeAuthToken(token);
  const { keyId } = getKeyParts(publicKey);
  const { orgId, appId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

  verifyAuthToken(token, secretKey);

  if (tokenType !== matchTokenType) {
    throw new ValidationError(`Invalid token type`);
  }

  return { orgId, appId, id };
}

export async function getAuthSession(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  appId: string,
  publicKey: string,
  secretKey: string,
  expiresIn: number,
  sessionExpiresIn: number,
  authenticateAction: boolean = false,
  authStorageType: AuthStorageType = AuthStorageType.PERSIST
): Promise<AuthUserSession> {
  logger.debug(`Getting auth session for user ${uid}`, { uid });

  const now = Date.now();
  const user = await getUserDataById(logger, pgClient, uid);

  if (user.blockedAt) {
    throw new ForbiddenError(`User blocked`);
  }

  if (user.appId !== appId) {
    throw new UnauthorizedError(`Cross application authentication not supported`);
  }

  if (user.authMfaEnabled && authenticateAction) {
    const { username, authMfaEnabled, factors } = user;
    const tmpToken = await getTmpToken(logger, uid, publicKey, secretKey);

    return <AuthUserSession>{
      user: {
        username,
        authMfaEnabled,
        factors
      },
      session: null,
      tmpToken
    };
  }

  const authToken = await getAuthToken(
    logger,
    uid,
    publicKey,
    secretKey,
    user.clientId!,
    expiresIn
  );
  const refreshToken = await getAuthRefreshToken(
    logger,
    uid,
    publicKey,
    secretKey,
    user.clientId!,
    sessionExpiresIn
  );
  const expiresAt = now + expiresIn * 1000;
  const destroyAt = now + sessionExpiresIn * 1000;

  const session = {
    token: authToken,
    refreshToken,
    expiresIn,
    expiresAt,
    destroyAt,
    authStorageType
  };

  return {
    session,
    user
  };
}

export async function getOrCreateUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  appId: string,
  email: string,
  autoVerify: boolean = false,
  username?: string,
  firstName?: string,
  lastName?: string
): Promise<AuthUser> {
  logger.debug(`Getting existing or creating new user`, { orgId });

  const existingUser = await getUserByEmail(logger, pgClient, orgId, appId, email);

  if (existingUser) {
    return existingUser;
  }

  const newUser = await createUser(
    logger,
    pgClient,
    orgId,
    appId,
    email,
    autoVerify,
    username,
    firstName,
    lastName
  );

  return newUser;
}

export async function createAuthVerificationCode(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  identityId: string,
  type: AuthVerificationCodeType
): Promise<number> {
  logger.debug(`Getting auth verification code`);

  const code = Math.floor(100000 + Math.random() * 900000);

  try {
    const { rows } = await repository.createAuthVerificationCode(
      pgClient,
      uid,
      identityId,
      code,
      type
    );

    return rows[0].code;
  } catch (err: any) {
    logger.error(`Failed to create auth verification code`, { err });
    throw err;
  }
}

export async function validateAuthVerificationCode(
  logger: Logger,
  pgClient: PgClient,
  identityId: string,
  code: string,
  type: AuthVerificationCodeType
): Promise<void> {
  logger.debug(`Validating verification code`);

  const { rows: validAuthVerifications } = await repository.validateAuthVerificationCode(
    pgClient,
    identityId,
    code,
    type
  );

  if (!validAuthVerifications.length) {
    throw new NotFoundError(`Invalid verification code`);
  }

  if (validAuthVerifications[0].verifiedAt !== null) {
    throw new ValidationError(`Verification code already used`);
  }

  if (new Date(validAuthVerifications[0].expiresAt).getTime() < Date.now()) {
    throw new NotFoundError(`Verification code expired`);
  }

  if (validAuthVerifications[0].code !== code) {
    throw new ValidationError(`Invalid verification code`);
  }
}

export async function createUserMfaFactor(
  logger: Logger,
  pgClient: PgClient,
  uid: string
): Promise<{ id: string; type: AuthMfaFactorType; secret: string }> {
  logger.debug(`Creating user mfa factor`, { uid });

  try {
    const secret = authenticator.generateSecret(20);
    const salt = generateSalt();
    const encryptedSecret = encrypt(secret, salt);

    const { rows } = await repository.createUserMfaFactor(
      pgClient,
      uid,
      AuthMfaFactorType.TOTP,
      encryptedSecret,
      salt
    );

    return { ...rows[0], secret };
  } catch (err: any) {
    logger.error(`Failed to create user mfa factor`, { err });
    throw new AuthenticationError(`Failed to create user mfa factor`);
  }
}

export async function getMfaFactorTypeForUser(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  factorType = AuthMfaFactorType.TOTP
): Promise<
  { id: string; type: AuthMfaFactorType; secret: string; verifiedAt: string } | undefined
> {
  logger.debug(`Getting mfa factors for user`, { uid });

  try {
    const { rows } = await repository.getMfaFactorTypeForUser(pgClient, uid, factorType);

    if (!rows.length) {
      return undefined;
    }

    const { id, type, secret, salt, verifiedAt } = rows[0];

    return {
      id,
      type,
      secret: decrypt(secret, salt),
      verifiedAt
    };
  } catch (err: any) {
    logger.error(`Failed to get user mfa factor`, { err });
    throw new AuthenticationError(`Failed to get user mfa factor`);
  }
}

export async function getUserMfaFactorById(
  logger: Logger,
  pgClient: PgClient,
  id: string,
  uid: string
): Promise<{ id: string; type: AuthMfaFactorType; secret: string; salt: string }> {
  logger.debug(`Getting user mfa factor by id`, { uid });

  try {
    const { rows } = await repository.getUserMfaFactorById(pgClient, id, uid);

    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to get user mfa factor`, { err });
    throw new AuthenticationError(`Failed to get user mfa factor`);
  }
}

export async function createUserMfaChallenge(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  factorId: string
): Promise<{ id: string; expiresAt: string }> {
  logger.debug(`Creating user mfa factor challenge`, { uid });

  try {
    const now = Date.now();
    const expiresAt = now + 5 * 60 * 1000;

    const { rows } = await repository.createUserMfaChallenge(pgClient, uid, factorId, expiresAt);

    return { ...rows[0], expiresAt };
  } catch (err: any) {
    logger.error(`Failed to create user mfa factor`, { err });
    throw new AuthenticationError(`Failed to create user mfa factor challange`);
  }
}

export async function getUserMfaChallengeById(
  logger: Logger,
  pgClient: PgClient,
  id: string,
  uid: string
): Promise<{ id: string; factorId: string; expiresAt: string; verifiedAt: string }> {
  logger.debug(`Getting user mfa challenge by id`, { uid });

  try {
    const { rows } = await repository.getUserMfaChallengeById(pgClient, id, uid);

    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to get user mfa challenge`, { err });
    throw new AuthenticationError(`Failed to get user mfa challenge`);
  }
}

export async function invalidateMfaChallengeById(
  logger: Logger,
  pgClient: PgClient,
  id: string
): Promise<void> {
  logger.debug(`Invalidating user mfa challenge`, { id });

  try {
    await repository.invalidateMfaChallenge(pgClient, id);
  } catch (err: any) {
    logger.error(`Failed to invalidate user mfa challenge`, { err });
    throw new AuthenticationError(`Failed to invalidate user mfa challenge`);
  }
}

export async function setUserMfaFactorVerified(
  logger: Logger,
  pgClient: PgClient,
  factorId: string
): Promise<void> {
  logger.debug(`Setting user mfa factor verified`, { factorId });

  try {
    await repository.setUserMfaFactorVerified(pgClient, factorId);
  } catch (err: any) {
    logger.error(`Failed to set user mfa factor verified`, { err });
    throw new AuthenticationError(`Failed to set user mfa enabled`);
  }
}

export async function setUserMfaEnabled(
  logger: Logger,
  pgClient: PgClient,
  uid: string
): Promise<void> {
  logger.debug(`Setting user mfa enabled`, { uid });

  try {
    await repository.setUserMfaEnabled(pgClient, uid);
  } catch (err: any) {
    logger.error(`Failed to set user mfa enabled`, { err });
    throw new AuthenticationError(`Failed to set user mfa enabled`);
  }
}

export async function setUserMfaFactorLastUsedAt(
  logger: Logger,
  pgClient: PgClient,
  factorId: string
): Promise<void> {
  logger.debug(`Setting user mfa factor last used at`, { factorId });

  try {
    await repository.setUserMfaFactorLastUsedAt(pgClient, factorId);
  } catch (err: any) {
    logger.error(`Failed to set user mfa factor last used at`, { err });
    throw new AuthenticationError(`Failed to set user mfa factor last used at`);
  }
}

export async function getUserEmailAddress(
  logger: Logger,
  pgClient: PgClient,
  uid: string
): Promise<string> {
  logger.debug(`Getting user email address`);

  const { rows } = await repository.getUserEmailAddress(pgClient, uid);

  if (!rows.length) {
    logger.error(`Failed to get user email address`);
    throw new NotFoundError(`User email address not found`);
  }

  const { email } = rows[0];

  const decryptedEmail = decrypt(email);

  return decryptedEmail;
}

export async function updateUserIdentityLastLogin(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  provider: AuthProvider = AuthProvider.EMAIL
): Promise<{ id: string }> {
  logger.debug(`Updating user identity last login`);

  try {
    const { rows } = await repository.updateUserIdentityLastLogin(pgClient, uid, provider);
    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to update user identity last login`, { err });
    throw new AuthenticationError(`Failed to update user identity last login`);
  }
}

export async function updateUserStatusById(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  status: string
): Promise<void> {
  logger.debug(`Updating user status`, { uid, status });

  try {
    await repository.updateUserStatus(pgClient, uid, status);
  } catch (err: any) {
    logger.error(`Failed to update user status`, { err });
    throw new AuthenticationError(`Failed to update user status`);
  }
}

export async function addUserToApplication(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  appId: string,
  uid: string
): Promise<void> {
  logger.debug(`Adding user to application`, { uid, appId });

  try {
    const { rows } = await repository.getUserByAppId(pgClient, appId, uid);

    if (rows.length) {
      logger.info(`User already in application`, { uid, appId });
      return;
    }

    await repository.addUserToApplication(pgClient, orgId, appId, uid);
  } catch (err: any) {
    logger.error(`Failed to add user to application`, { err });
    throw err;
  }
}

export async function getUserByAppId(
  logger: Logger,
  pgClient: PgClient,
  appId: string,
  uid: string
): Promise<any> {
  logger.debug(`Getting user by application id`, { uid, appId });

  try {
    const { rows } = await repository.getUserByAppId(pgClient, appId, uid);

    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to get user by application id`, { err });
    throw new AuthenticationError(`Failed to get user by application id`);
  }
}

export async function getAuthProviderDataByProviderName(
  logger: Logger,
  pgClient: PgClient,
  appId: string,
  providerName: string
): Promise<{ clientId: string; clientSecret: string }> {
  logger.debug(`Getting auth provider data by provider name`, { providerName });

  try {
    const { rows } = await repository.getAuthProviderDataByProviderName(
      pgClient,
      appId,
      providerName
    );

    const { clientId, clientSecret, salt } = rows[0];

    const decryptedClientSecret = decrypt(clientSecret, salt);

    return {
      clientId,
      clientSecret: decryptedClientSecret
    };
  } catch (err: any) {
    logger.error(`Failed to get auth provider data by provider name`, { err });
    throw new AuthenticationError(`Failed to get auth provider data by provider name`);
  }
}

export async function getApplicationAuthenticationPreferences(
  logger: Logger,
  pgClient: PgClient,
  appId: string
): Promise<{
  tokenExpiry: number;
  sessionExpiry: number;
  authStorageType: AuthStorageType;
  passwordPattern: string | null;
}> {
  logger.debug(`Getting application authentication preferences`, { appId });

  try {
    const { rows } = await repository.getApplicationAuthenticationPreferences(pgClient, appId);

    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to get application authentication preferences`, { err });
    throw new AuthenticationError(`Failed to get application authentication preferences`);
  }
}

export async function validateUsername(
  logger: Logger,
  pgClient: PgClient,
  appId: string,
  username: string
): Promise<void> {
  logger.debug(`Validating username`, { username });

  try {
    const { rows } = await repository.validateUsername(pgClient, appId, username);

    if (rows.length) {
      throw new ValidationError(`Username already exists`);
    }
  } catch (err: any) {
    logger.error(`Failed to validate username`, { err });
    throw err;
  }
}

export async function validatePassword(
  logger: Logger,
  pgClient: PgClient,
  appId: string,
  password: string
): Promise<void> {
  logger.debug(`Validating password`);

  const { passwordPattern } = await getApplicationAuthenticationPreferences(
    logger,
    pgClient,
    appId
  );

  if (!passwordPattern) {
    return;
  }

  if (!password.match(passwordPattern)) {
    throw new PasswordRegexError(`Password does not match required pattern`);
  }
}

export async function createAuthenticationActivityLogEntry(
  logger: Logger,
  pgClient: PgClient,
  event: APIGatewayProxyEvent,
  action: AuthenticationAction,
  actionResult: AuthenticationActionResult,
  authenticationActionLog: AuthenticationActionLog,
  err?: any
): Promise<void> {
  logger.debug(`Creating auth action log entry`, { authenticationActionLog });

  try {
    const ipAddress = event.requestContext.identity.sourceIp;

    const encryptedIpAddress = encrypt(ipAddress);

    if (err) {
      authenticationActionLog.errorMessage = err.message;
    }

    const { rows } = await repository.createAuthenticationActivityLogEntry(
      pgClient,
      action,
      actionResult,
      encryptedIpAddress,
      authenticationActionLog
    );

    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to create authentication action log entry`, { err });
  }
}

export function getAuthenticationActionLog(): AuthenticationActionLog {
  return {
    uid: null,
    identityId: null,
    appId: null,
    keyId: null,
    errorMessage: null
  };
}
