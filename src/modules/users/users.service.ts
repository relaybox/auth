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
  getKeyVersion,
  strongHash,
  verifyAuthToken,
  verifyStrongHash
} from 'src/lib/encryption';
import { Logger } from 'winston';
import {
  AuthenticationError,
  NotFoundError,
  TokenError,
  ValidationError,
  VerificationError
} from 'src/lib/errors';
import {
  AuthProvider,
  AuthSession,
  AuthStorageType,
  AuthUser,
  AuthVerificationCodeType,
  RequestAuthParams
} from 'src/types/auth.types';
import { smtpTransport } from 'src/lib/smtp';
import { TokenType } from 'src/types/jwt.types';
import { generateUsername } from 'unique-username-generator';
import { APIGatewayProxyEvent } from 'aws-lambda';

const SMTP_AUTH_EMAIL = process.env.SMTP_AUTH_EMAIL || '';
export const REFRESH_TOKEN_EXPIRES_IN_SECS = 7 * 24 * 60 * 60;

export async function registerUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  password: string,
  provider: AuthProvider = AuthProvider.EMAIL
): Promise<string> {
  logger.info(`Registering user`, { orgId, provider });

  try {
    await pgClient.query('BEGIN');

    const { id } = await getOrCreateUser(logger, pgClient, orgId, email);
    const { id: identityId } = await createUserIdentity(
      logger,
      pgClient,
      id,
      email,
      password,
      provider
    );

    const code = await createAuthVerificationCode(
      logger,
      pgClient,
      id,
      identityId,
      AuthVerificationCodeType.REGISTER
    );

    await sendAuthVerificationCode(logger, email, code);

    await pgClient.query('COMMIT');

    return id;
  } catch (err: any) {
    await pgClient.query('ROLLBACK');
    logger.error(`Failed to register user`, { err });
    throw err;
  }
}

export async function registerIdpUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  keyId: string,
  email: string,
  password: string,
  provider: AuthProvider,
  providerId: string,
  username?: string
): Promise<AuthUser> {
  logger.info(`Registering idp user`, { orgId, provider });

  const autoVerify = true;

  const userData = await getOrCreateUser(logger, pgClient, orgId, email, username, autoVerify);

  await createUserIdentity(
    logger,
    pgClient,
    userData.id,
    email,
    password,
    provider,
    providerId,
    autoVerify
  );

  return userData;
}

export async function authenticateUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  password: string
): Promise<string> {
  logger.debug(`Authenticating user`);

  const emailHash = generateHash(email);
  const userIdentity = await getUserIdentityByEmail(
    logger,
    pgClient,
    orgId,
    email,
    AuthProvider.EMAIL
  );

  if (!userIdentity) {
    logger.warn(`User auth credenials not found`, { emailHash });
    throw new AuthenticationError('Login failed');
  }

  if (!userIdentity.verifiedAt || !userIdentity.password) {
    logger.warn(`User not verified`, { emailHash });
    throw new AuthenticationError('Login failed');
  }

  const passwordHash = strongHash(password, userIdentity.salt);

  if (!passwordHash) {
    logger.warn(`Password hash failed`, { emailHash });
    throw new AuthenticationError('Login failed');
  }

  const verifiedPassword = verifyStrongHash(password, userIdentity.password, userIdentity.salt);

  if (!verifiedPassword) {
    logger.warn(`Invalid password`, { emailHash });
    throw new AuthenticationError('Login failed');
  }

  return userIdentity.uid;
}

export async function verifyUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  code: string
): Promise<void> {
  try {
    await pgClient.query('BEGIN');

    const { uid, identityId, verifiedAt } = await getUserIdentityByEmail(
      logger,
      pgClient,
      orgId,
      email,
      AuthProvider.EMAIL
    );

    if (verifiedAt) {
      throw new ValidationError(`User already verified`);
    }

    logger.info(`Verifying user`, { orgId, identityId });

    await validateVerificationCode(
      logger,
      pgClient,
      identityId,
      code,
      AuthVerificationCodeType.REGISTER
    );

    await repository.verifyUser(pgClient, uid);
    await repository.verifyUserIdentity(pgClient, identityId);
    await repository.invalidateVerificationCode(pgClient, identityId, code);

    await pgClient.query('COMMIT');
  } catch (err: any) {
    await pgClient.query('ROLLBACK');
    logger.error(`Failed to verify user`, { err });
    throw new VerificationError(`Failed to verify user`);
  }
}

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

    logger.info(`User created`, { uid, id: rows[0].id });

    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to create user`, { err });
    throw new AuthenticationError(`Failed to create user`);
  }
}

export async function resetUserPassword(
  logger: Logger,
  pgClient: PgClient,
  identityId: string,
  code: string,
  password: string
): Promise<void> {
  logger.debug(`Resetting user password`);

  try {
    await pgClient.query('BEGIN');

    await validateVerificationCode(
      logger,
      pgClient,
      identityId,
      code,
      AuthVerificationCodeType.PASSWORD_RESET
    );

    const salt = generateSalt();
    const passwordHash = strongHash(password, salt);

    await updateUserIdentityData(logger, pgClient, identityId, [
      { key: 'password', value: passwordHash },
      { key: 'salt', value: salt }
    ]);

    await repository.invalidateVerificationCode(pgClient, identityId, code);

    await pgClient.query('COMMIT');
  } catch (err: any) {
    await pgClient.query('ROLLBACK');
    logger.error(`Failed to reset user password`, { err });
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
    logger.warn(`Invalid verification code`, { identityId, code, type });
    throw new NotFoundError(`Invalid verification code`);
  }

  if (validAuthVerifications[0].verifiedAt !== null) {
    logger.warn(`Code already verfied`, { identityId, code, type });
    throw new ValidationError(`Verification code already used`);
  }

  if (new Date(validAuthVerifications[0].expiresAt).getTime() < Date.now()) {
    logger.warn(`Code expired`, { identityId, code, type });
    throw new NotFoundError(`Verification code expired`);
  }

  if (validAuthVerifications[0].code !== code) {
    logger.warn(`Code not matched`, { identityId, code, type });
    throw new ValidationError(`Invalid verification code`);
  }
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
): Promise<any> {
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
  keyName: string,
  secretKey: string,
  expiresIn: number = 300
): Promise<AuthSession> {
  logger.debug(`Getting auth session for user ${id}`, { id });

  const now = Date.now();
  const user = await getUserDataById(logger, pgClient, id);
  const authToken = await getAuthToken(logger, id, keyName, secretKey, user.clientId, expiresIn);
  const refreshToken = await getAuthRefreshToken(logger, id, keyName, secretKey, user.clientId);
  const expiresAt = now + expiresIn * 1000;
  const destroyAt = now + REFRESH_TOKEN_EXPIRES_IN_SECS * 1000;
  const authStorageType = AuthStorageType.SESSION;

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
