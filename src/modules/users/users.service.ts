import { nanoid } from 'nanoid';
import * as repository from './users.repository';
import PgClient from 'serverless-postgres';
import {
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
import { AuthProvider, AuthUser } from 'src/types/auth.types';
import { smtpTransport } from 'src/lib/smtp';
import { TokenType } from 'src/types/jwt.types';

const AUTH_EMAIL_ADDRESS = 'no-reply@relaybox.net';

export async function registerUser(
  logger: Logger,
  pgClient: PgClient,
  keyId: string,
  email: string,
  password: string,
  provider: string = 'email'
): Promise<void> {
  try {
    await pgClient.query('BEGIN');

    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const { id: uid } = await createUser(logger, pgClient, orgId, email, password, provider);
    const code = await createAuthVerificationCode(logger, pgClient, uid);
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
  keyId: string,
  email: string,
  password: string,
  provider: string,
  providerId: string,
  username?: string
): Promise<{ uid: string; clientId: string }> {
  const autoVerify = true;
  const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);
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
  email: string,
  password: string
): Promise<AuthUser> {
  logger.debug(`Authenticating user`);

  const emailHash = generateHash(email);
  const { rows } = await repository.getUserByEmailHash(pgClient, emailHash, AuthProvider.EMAIL);

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
  email: string,
  code: number
): Promise<void> {
  try {
    await pgClient.query('BEGIN');

    const { id: uid, verifiedAt } = await getUserByEmail(
      logger,
      pgClient,
      email,
      AuthProvider.EMAIL
    );

    if (verifiedAt) {
      throw new ValidationError(`User already verified`);
    }

    logger.debug(`Verifying user`, { uid });

    const { rows: validAuthVerifications } = await repository.validateVerificationCode(
      pgClient,
      uid,
      code
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

    await repository.verifyUserCode(pgClient, uid, code);
    await repository.verifyUser(pgClient, uid);

    await pgClient.query('COMMIT');
  } catch (err: any) {
    await pgClient.query('ROLLBACK');
    logger.error(`Failed to verify user`, { err });
    throw err;
  }
}

export async function updateUserData(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  userData: { key: string; value: string }[]
): Promise<void> {
  logger.debug(`Updating user data`);

  const { rows } = await repository.updateUserData(pgClient, uid, userData);

  return rows[0];
}

export async function getUserByEmail(
  logger: Logger,
  pgClient: PgClient,
  email: string,
  provider: AuthProvider
): Promise<any> {
  logger.debug(`Getting user by email`);

  const emailHash = generateHash(email);

  const { rows } = await repository.getUserByEmailHash(pgClient, emailHash, provider);

  return rows[0];
}

export async function getUserByProviderId(
  logger: Logger,
  pgClient: PgClient,
  providerId: string,
  provider: AuthProvider
): Promise<any> {
  logger.debug(`Getting user by provider id`);

  const { rows } = await repository.getUserByProviderId(pgClient, providerId, provider);

  return rows[0];
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
  logger.debug(`Creating user`);

  username = username || email.split('@')[0];
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

export async function getAuthDataByKeyId(
  logger: Logger,
  pgClient: PgClient,
  keyId: string
): Promise<any> {
  logger.debug(`Getting organization by key id`);

  const { rows } = await repository.getAuthDataByKeyId(pgClient, keyId);

  if (!rows.length) {
    throw new NotFoundError(`Organization not found`);
  }

  return rows[0];
}

export async function getAuthToken(
  logger: Logger,
  keyName: string,
  secretKey: string,
  clientId: string,
  expiresIn: number = 900
): Promise<any> {
  logger.debug(`Generating auth token`);

  const payload = {
    keyName,
    clientId,
    tokenType: TokenType.ID_TOKEN,
    timestamp: new Date().toISOString()
  };

  try {
    return generateAuthToken(payload, secretKey, expiresIn);
  } catch (err: any) {
    throw new TokenError(`Failed to generate token, ${err.message}`);
  }
}

export async function getAuthRefreshToken(
  logger: Logger,
  keyName: string,
  secretKey: string,
  clientId: string,
  expiresIn: number = 900
): Promise<any> {
  logger.debug(`Generating refresh token`);

  const payload = {
    keyName,
    clientId,
    tokenType: TokenType.REFRESH_TOKEN,
    timestamp: new Date().toISOString()
  };

  const refreshExpiresIn = 7 * 24 * 60 * 60;

  try {
    return generateAuthToken(payload, secretKey, refreshExpiresIn);
  } catch (err: any) {
    throw new TokenError(`Failed to generate token, ${err.message}`);
  }
}

export async function createAuthVerificationCode(
  logger: Logger,
  pgClient: PgClient,
  uid: string
): Promise<number> {
  logger.debug(`Getting auth verification code`);

  const code = Math.floor(100000 + Math.random() * 900000);

  try {
    const { rows } = await repository.createAuthVerificationCode(pgClient, uid, code);

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

  console.log('SES sandbox mode ON');
  return '123';

  try {
    const options = {
      from: AUTH_EMAIL_ADDRESS,
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

export function verifyRefreshToken(token: string, secretKey: string, tokenType: string): void {
  verifyAuthToken(token, secretKey);

  if (tokenType !== 'refresh_token') {
    throw new ValidationError(`Invalid typ`);
  }
}
