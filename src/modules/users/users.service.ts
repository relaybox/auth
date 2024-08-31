import { nanoid } from 'nanoid';
import * as repository from './users.repository';
import PgClient from 'serverless-postgres';
import {
  decodeAuthToken,
  decrypt,
  encrypt,
  generateAuthToken,
  generateHash,
  generateSalt,
  generateSecret,
  getKeyVersion,
  strongHash,
  verifyAuthToken
} from 'src/lib/encryption';
import { Logger } from 'winston';
import {
  AuthenticationError,
  ForbiddenError,
  NotFoundError,
  TokenError,
  UnauthorizedError,
  ValidationError
} from 'src/lib/errors';
import {
  AuthMfaFactorType,
  AuthProvider,
  AuthSession,
  AuthStorageType,
  AuthUser,
  AuthVerificationCodeType,
  RequestAuthParams
} from 'src/types/auth.types';
import { smtpTransport } from 'src/lib/smtp';
import { TokenType } from 'src/types/jwt.types';
import { APIGatewayProxyEvent } from 'aws-lambda';
import { generateUsername } from 'unique-username-generator';

const SMTP_AUTH_EMAIL = process.env.SMTP_AUTH_EMAIL || '';

export const REFRESH_TOKEN_EXPIRES_IN_SECS = 7 * 24 * 60 * 60;

export async function createUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  username?: string,
  autoVerify: boolean = false
): Promise<AuthUser> {
  logger.debug(`Creating user`, { orgId });

  username = username || generateUsername();
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

export async function getAuthToken(
  logger: Logger,
  id: string,
  keyName: string,
  secretKey: string,
  clientId: string,
  expiresIn: number = 2
): Promise<any> {
  logger.debug(`Generating auth token`);

  const payload = {
    sub: id,
    keyName,
    clientId,
    tokenType: TokenType.ID_TOKEN,
    timestamp: new Date().toISOString()
  };

  try {
    return generateAuthToken(payload, secretKey, expiresIn);
  } catch (err: any) {
    logger.error(`Failed to generate token`, { err });
    throw new TokenError(`Failed to generate token, ${err.message}`);
  }
}

export async function getAuthRefreshToken(
  logger: Logger,
  id: string,
  keyName: string,
  secretKey: string,
  clientId: string,
  expiresIn: number = REFRESH_TOKEN_EXPIRES_IN_SECS
): Promise<any> {
  logger.debug(`Generating refresh token`);

  const payload = {
    sub: id,
    keyName,
    clientId,
    tokenType: TokenType.REFRESH_TOKEN,
    timestamp: new Date().toISOString()
  };

  try {
    return generateAuthToken(payload, secretKey, expiresIn);
  } catch (err: any) {
    logger.error(`Failed to generate token`, { err });
    throw new TokenError(`Failed to generate token, ${err.message}`);
  }
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
  clientId: string
): Promise<AuthUser> {
  logger.debug(`Getting user data for client id`, { clientId });

  const { rows } = await repository.getUserDataByClientId(pgClient, clientId);

  if (!rows.length) {
    throw new NotFoundError(`User data not found`);
  }

  const { email } = rows[0];

  const userData = {
    ...rows[0],
    email: decrypt(email)
  };

  return userData;
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
  id: string,
  orgId: string,
  keyName: string,
  secretKey: string,
  expiresIn: number = 300,
  authStorageType: AuthStorageType = AuthStorageType.PERSIST
): Promise<AuthSession> {
  logger.debug(`Getting auth session for user ${id}`, { id });

  const now = Date.now();
  const user = await getUserDataById(logger, pgClient, id);

  if (user.orgId !== orgId) {
    throw new UnauthorizedError(`Cross organsiation authentication not supported`);
  }

  const authToken = await getAuthToken(logger, id, keyName, secretKey, user.clientId, expiresIn);
  const refreshToken = await getAuthRefreshToken(logger, id, keyName, secretKey, user.clientId);
  const expiresAt = now + expiresIn * 1000;
  const destroyAt = now + REFRESH_TOKEN_EXPIRES_IN_SECS * 1000;

  return {
    token: authToken,
    refreshToken,
    expiresIn,
    expiresAt,
    destroyAt,
    authStorageType,
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

export function verifyRefreshToken(token: string, secretKey: string, tokenType: string): void {
  try {
    verifyAuthToken(token, secretKey);
  } catch (err: any) {
    throw new TokenError(`Refresh token invalid`);
  }

  if (tokenType !== 'refresh_token') {
    throw new ValidationError(`Invalid token type`);
  }
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

export async function validateVerificationCode(
  logger: Logger,
  pgClient: PgClient,
  identityId: string,
  code: string,
  type: AuthVerificationCodeType
): Promise<void> {
  logger.debug(`Validating verification code`);

  const { rows: validAuthVerifications } = await repository.validateVerificationCode(
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
    const secret = generateSecret();
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

export async function getUserMfaFactorById(
  logger: Logger,
  pgClient: PgClient,
  id: string,
  uid: string
): Promise<{ id: string; type: AuthMfaFactorType; secret: string }> {
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
): Promise<{ id: string; type: AuthMfaFactorType; secret: string }> {
  logger.debug(`Getting user mfa challenge by id`, { uid });

  try {
    const { rows } = await repository.getUserMfaChallengeById(pgClient, id, uid);

    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to get user mfa challenge`, { err });
    throw new AuthenticationError(`Failed to get user mfa challenge`);
  }
}
