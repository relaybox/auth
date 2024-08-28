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
  DuplicateKeyError,
  NotFoundError,
  TokenError,
  UnauthorizedError,
  ValidationError,
  VerificationError
} from 'src/lib/errors';
import {
  AuthProvider,
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
  provider: string = AuthProvider.EMAIL
): Promise<void> {
  logger.info(`Registering user`, { orgId, provider });

  try {
    await pgClient.query('BEGIN');

    const { id: uid } = await createUser(logger, pgClient, orgId, email, password, provider);

    const code = await createAuthVerificationCode(
      logger,
      pgClient,
      uid,
      AuthVerificationCodeType.REGISTER
    );

    await sendAuthVerificationCode(logger, email, code);

    await pgClient.query('COMMIT');
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
  provider: string,
  providerId: string,
  username?: string
): Promise<{ uid: string; clientId: string }> {
  logger.info(`Registering idp user`, { orgId, provider });

  const autoVerify = true;

  const { id: uid, clientId } = await createUser(
    logger,
    pgClient,
    orgId,
    email,
    password,
    provider,
    providerId,
    username,
    autoVerify
  );

  return { uid, clientId };
}

export async function authenticateUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  password: string
): Promise<AuthUser> {
  logger.debug(`Authenticating user`);

  const emailHash = generateHash(email);
  const { rows } = await repository.getUserByEmailHash(
    pgClient,
    orgId,
    emailHash,
    AuthProvider.EMAIL
  );

  if (!rows.length) {
    throw new NotFoundError(`User not found`);
  }

  const user = rows[0];

  if (!user.verifiedAt) {
    throw new VerificationError(`User verification incomplete`);
  }

  if (!user.password) {
    throw new NotFoundError(`User not found`);
  }

  const passwordHash = strongHash(password, user.salt);

  if (!passwordHash) {
    throw new NotFoundError(`User not found`);
  }

  const verifiedPassword = verifyStrongHash(password, user.password, user.salt);

  if (!verifiedPassword) {
    throw new UnauthorizedError(`Invalid password`);
  }

  return user;
}

export async function verifyUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  code: number
): Promise<void> {
  try {
    await pgClient.query('BEGIN');

    const { id: uid, verifiedAt } = await getUserByEmail(
      logger,
      pgClient,
      orgId,
      email,
      AuthProvider.EMAIL
    );

    if (verifiedAt) {
      throw new ValidationError(`User already verified`);
    }

    logger.info(`Verifying user`, { orgId, uid });

    await validateVerificationCode(logger, pgClient, uid, code, AuthVerificationCodeType.REGISTER);

    await repository.verifyUser(pgClient, uid);
    await repository.invalidateVerificationCode(pgClient, uid, code);

    await pgClient.query('COMMIT');
  } catch (err: any) {
    await pgClient.query('ROLLBACK');
    logger.error(`Failed to verify user`, { err });
    throw err;
  }
}

export async function createUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  password: string,
  provider?: string,
  providerId?: string,
  username?: string,
  autoVerify: boolean = false
): Promise<AuthUser> {
  logger.debug(`Creating user`, { orgId, provider });

  username = username || generateUsername();
  const clientId = nanoid(12);
  const encryptedEmail = encrypt(email);
  const emailHash = generateHash(email);
  const salt = generateSalt();
  const passwordHash = strongHash(password, salt);
  const keyVersion = getKeyVersion();

  try {
    const { rows } = await repository.createUser(
      pgClient,
      orgId,
      clientId,
      encryptedEmail,
      emailHash,
      passwordHash,
      salt,
      keyVersion,
      provider,
      providerId,
      username,
      autoVerify
    );

    logger.info(`User created`, { orgId, clientId, id: rows[0].id });

    return rows[0];
  } catch (err: any) {
    logger.error(`Failed to create user`, { err });

    if (err.message.includes(`duplicate key`)) {
      throw new DuplicateKeyError(`User already exists`);
    } else {
      throw err;
    }
  }
}

export async function resetUserPassword(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  code: number,
  password: string
): Promise<void> {
  logger.debug(`Resetting user password`);

  try {
    await pgClient.query('BEGIN');

    await validateVerificationCode(
      logger,
      pgClient,
      uid,
      code,
      AuthVerificationCodeType.PASSWORD_RESET
    );

    const salt = generateSalt();
    const passwordHash = strongHash(password, salt);

    await updateUserData(logger, pgClient, uid, [
      { key: 'password', value: passwordHash },
      { key: 'salt', value: salt }
    ]);

    await repository.invalidateVerificationCode(pgClient, uid, code);

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
  uid: string,
  code: number,
  type: AuthVerificationCodeType
): Promise<void> {
  logger.debug(`Validating verification code`);

  const { rows: validAuthVerifications } = await repository.validateVerificationCode(
    pgClient,
    uid,
    code,
    type
  );

  if (!validAuthVerifications.length) {
    throw new NotFoundError(`Invalid verification code`);
  }

  if (validAuthVerifications[0].verifiedAt !== null) {
    throw new ValidationError(`Verification code already used`);
  }

  if (validAuthVerifications[0].expiresAt < new Date().toISOString()) {
    throw new NotFoundError(`Verification code expired`);
  }

  if (validAuthVerifications[0].code !== code) {
    throw new ValidationError(`Invalid verification code`);
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

export async function getUserByEmail(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  provider: AuthProvider
): Promise<any> {
  logger.debug(`Getting user by email`);

  const emailHash = generateHash(email);

  const { rows } = await repository.getUserByEmailHash(pgClient, orgId, emailHash, provider);

  return rows[0];
}

export async function getUserByProviderId(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  providerId: string,
  provider: AuthProvider
): Promise<any> {
  logger.debug(`Getting user by provider id`);

  const { rows } = await repository.getUserByProviderId(pgClient, orgId, providerId, provider);

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
  sub: string,
  keyName: string,
  secretKey: string,
  clientId: string,
  expiresIn: number = 2
): Promise<any> {
  logger.debug(`Generating auth token`);

  const payload = {
    sub,
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
  sub: string,
  keyName: string,
  secretKey: string,
  clientId: string,
  expiresIn: number = 900
): Promise<any> {
  logger.debug(`Generating refresh token`);

  const payload = {
    sub,
    keyName,
    clientId,
    tokenType: TokenType.REFRESH_TOKEN,
    timestamp: new Date().toISOString()
  };

  try {
    return generateAuthToken(payload, secretKey, REFRESH_TOKEN_EXPIRES_IN_SECS);
  } catch (err: any) {
    logger.error(`Failed to generate token`, { err });
    throw new TokenError(`Failed to generate token, ${err.message}`);
  }
}

export async function createAuthVerificationCode(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  type: AuthVerificationCodeType
): Promise<number> {
  logger.debug(`Getting auth verification code`);

  const code = Math.floor(100000 + Math.random() * 900000);

  try {
    const { rows } = await repository.createAuthVerificationCode(pgClient, uid, code, type);

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
  logger.debug(`Getting session data for client id`, { clientId });

  const { rows } = await repository.getUserDataByClientId(pgClient, clientId);

  if (!rows.length) {
    throw new NotFoundError(`Session data not found`);
  }

  const { email } = rows[0];

  const sessionData = {
    ...rows[0],
    email: decrypt(email)
  };

  return sessionData;
}

export async function getUserDataById(
  logger: Logger,
  pgClient: PgClient,
  id: string
): Promise<AuthUser> {
  logger.debug(`Getting session data for client id`, { id });

  const { rows } = await repository.getUserDataById(pgClient, id);

  if (!rows.length) {
    throw new NotFoundError(`Session data not found`);
  }

  const { email } = rows[0];

  const sessionData = {
    ...rows[0],
    email: decrypt(email)
  };

  return sessionData;
}

export function verifyRefreshToken(token: string, secretKey: string, tokenType: string): void {
  verifyAuthToken(token, secretKey);

  if (tokenType !== 'refresh_token') {
    throw new ValidationError(`Invalid token type`);
  }
}

export async function authorizeClientRequest(
  logger: Logger,
  pgClient: PgClient,
  token: string
): Promise<any> {
  const { sub: id, keyName, tokenType } = decodeAuthToken(token);
  const { keyId } = getKeyParts(keyName);
  const { orgId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

  verifyAuthToken(token, secretKey);

  if (tokenType !== 'id_token') {
    throw new ValidationError(`Invalid token type`);
  }

  return { orgId, id };
}
