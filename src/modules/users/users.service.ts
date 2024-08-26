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
  verifyStrongHash
} from 'src/lib/encryption';
import { Logger } from 'winston';
import {
  DuplicateKeyError,
  NotFoundError,
  TokenError,
  UnauthorizedError,
  VerificationError
} from 'src/lib/errors';
import { AuthUser } from 'src/types/auth.types';
import { smtpTransport } from 'src/lib/smtp';

const AUTH_EMAIL_ADDRESS = 'no-reply@relaybox.net';

export async function getUserByEmail(
  logger: Logger,
  pgClient: PgClient,
  email: string
): Promise<any> {
  logger.debug(`Getting user by email`);

  const emailHash = generateHash(email);

  const { rows } = await repository.getUserByEmailHash(pgClient, emailHash);

  return rows[0];
}

export async function registerUser(
  logger: Logger,
  pgClient: PgClient,
  keyId: string,
  email: string,
  password: string
): Promise<void> {
  try {
    await pgClient.query('BEGIN');

    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const { id: uid } = await createUser(logger, pgClient, orgId, email, password);
    const code = await createAuthVerificationCode(logger, pgClient, uid);
    // await sendAuthVerificationCode(logger, email, code);

    await pgClient.query('COMMIT');
  } catch (err: any) {
    await pgClient.query('ROLLBACK');
    logger.error(`Failed to register user`, { err });
    throw err;
  }
}

export async function authenticateUser(
  logger: Logger,
  pgClient: PgClient,
  email: string,
  password: string
): Promise<AuthUser> {
  logger.debug(`Authenticating user`);

  const emailHash = generateHash(email);
  const { rows } = await repository.getUserByEmailHash(pgClient, emailHash);

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

export async function createUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  password: string
): Promise<AuthUser> {
  logger.debug(`Creating user`);

  const username = email.split('@')[0];
  const uid = nanoid(12);
  const encryptedEmail = encrypt(email);
  const emailHash = generateHash(email);
  const salt = generateSalt();
  const passwordHash = strongHash(password, salt);
  const keyVersion = getKeyVersion();

  try {
    const { rows } = await repository.createUser(
      pgClient,
      orgId,
      uid,
      username,
      encryptedEmail,
      emailHash,
      passwordHash,
      salt,
      keyVersion
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
  logger.debug(`Generating id token`);

  const payload = {
    keyName,
    clientId,
    timestamp: new Date().toISOString()
  };

  try {
    return generateAuthToken(payload, secretKey, expiresIn);
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

  try {
    const options = {
      from: AUTH_EMAIL_ADDRESS,
      to: email,
      subject: 'Verification Code',
      text: `Your code is ${code}`
    };

    console.log(options);

    const result = await smtpTransport.sendMail(options);

    return result?.messageId;
  } catch (err: any) {
    logger.error(`Failed to send contact request email`);
    throw err;
  }
}
