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
  NotFoundError,
  UnauthorizedError,
  ValidationError
} from 'src/lib/errors';
import {
  AuthMfaFactorType,
  AuthProvider,
  AuthStorageType,
  AuthUser,
  AuthUserSession,
  AuthVerificationCodeType,
  RequestAuthParams
} from 'src/types/auth.types';
import { smtpTransport } from 'src/lib/smtp';
import { APIGatewayProxyEvent } from 'aws-lambda';
import { generateUsername } from 'unique-username-generator';
import { authenticator } from 'otplib';
import {
  decodeAuthToken,
  DEFAULT_REFRESH_TOKEN_EXPIRY_SECS,
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
  email: string,
  username?: string,
  autoVerify: boolean = false
): Promise<AuthUser> {
  logger.debug(`Creating user`, { orgId });

  username = username || generateUsername('', 3);
  const clientId = nanoid(12);
  const encryptedEmail = encrypt(email);
  const emailHash = generateHash(email);

  try {
    const { rows } = await repository.createUser(
      pgClient,
      orgId,
      clientId,
      encryptedEmail,
      emailHash,
      username,
      autoVerify
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
    throw new AuthenticationError(`Failed to create user`);
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
  email: string
): Promise<any> {
  logger.debug(`Getting user by email`);

  const emailHash = generateHash(email);

  const { rows } = await repository.getUserByEmailHash(pgClient, orgId, emailHash);

  return rows[0];
}

export async function getUserIdentityByEmail(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  provider?: AuthProvider
): Promise<any> {
  logger.debug(`Getting user by email identity`);

  const emailHash = generateHash(email);

  const { rows } = await repository.getUserIdentityByEmailHash(
    pgClient,
    orgId,
    emailHash,
    provider
  );

  return rows[0];
}

export async function getUserIdentityByProviderId(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  providerId: string,
  provider: AuthProvider
): Promise<any> {
  logger.debug(`Getting user by provider id`);

  const { rows } = await repository.getUserIdentityByProviderId(
    pgClient,
    orgId,
    providerId,
    provider
  );

  return rows[0];
}

export async function getAuthDataByKeyId(
  logger: Logger,
  pgClient: PgClient,
  keyId: string
): Promise<{ orgId: string; secretKey: string }> {
  logger.debug(`Getting secure auth data by key id`);

  const { rows } = await repository.getAuthDataByKeyId(pgClient, keyId);

  if (!rows.length) {
    throw new NotFoundError(`Secure auth data not found`);
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

export function getKeyParts(keyName: string): { appPid: string; keyId: string } {
  const [appPid, keyId] = keyName.split('.');

  return { appPid, keyId };
}

export function getRequestAuthParams(event: APIGatewayProxyEvent): RequestAuthParams {
  const headers = event.headers;
  const keyName = headers['X-Ds-Key-Name'];

  if (!keyName) {
    throw new ValidationError('Missing X-Ds-Key-Name header');
  }

  const { appPid, keyId } = getKeyParts(keyName);

  return { keyName, appPid, keyId };
}

export async function getUserDataByClientId(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  clientId: string
): Promise<AuthUser | undefined> {
  logger.debug(`Getting user data for client id`, { clientId });

  const { rows } = await repository.getUserDataByClientId(pgClient, clientId);

  if (!rows.length) {
    throw new NotFoundError(`User not found`);
  }

  if (rows[0].orgId !== orgId) {
    throw new UnauthorizedError(`Cross organsiation authentication not supported`);
  }

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
  const { sub: id, keyName, tokenType } = decodeAuthToken(token);
  const { keyId } = getKeyParts(keyName);
  const { orgId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

  verifyAuthToken(token, secretKey);

  if (tokenType !== matchTokenType) {
    throw new ValidationError(`Invalid token type`);
  }

  return { orgId, id };
}

export async function getAuthSession(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  orgId: string,
  keyName: string,
  secretKey: string,
  expiresIn: number = 300,
  authenticateAction: boolean = false,
  authStorageType: AuthStorageType = AuthStorageType.PERSIST
): Promise<AuthUserSession> {
  logger.debug(`Getting auth session for user ${uid}`, { uid });

  const now = Date.now();
  const user = await getUserDataById(logger, pgClient, uid);

  if (user.orgId !== orgId) {
    throw new UnauthorizedError(`Cross organsiation authentication not supported`);
  }

  if (user.authMfaEnabled && authenticateAction) {
    const { username, authMfaEnabled, factors } = user;
    const tmpToken = await getTmpToken(logger, uid, keyName, secretKey);

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

  const authToken = await getAuthToken(logger, uid, keyName, secretKey, user.clientId!, expiresIn);
  const refreshToken = await getAuthRefreshToken(logger, uid, keyName, secretKey, user.clientId!);
  const expiresAt = now + expiresIn * 1000;
  const destroyAt = now + DEFAULT_REFRESH_TOKEN_EXPIRY_SECS * 1000;

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
  email: string,
  username?: string,
  autoVerify: boolean = false
): Promise<AuthUser> {
  logger.debug(`Getting existing or creating new user`, { orgId });

  const existingUser = await getUserByEmail(logger, pgClient, orgId, email);

  if (existingUser) {
    return existingUser;
  }

  const newUser = await createUser(logger, pgClient, orgId, email, username, autoVerify);

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
): Promise<void> {
  logger.debug(`Updating user identity last login`);

  try {
    await repository.updateUserIdentityLastLogin(pgClient, uid, provider);
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
