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
  ValidationError
} from 'src/lib/errors';
import { AuthUser } from 'src/types/auth.types';

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

export async function createUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  email: string,
  password: string
): Promise<void> {
  logger.debug(`Creating user`);

  const username = email.split('@')[0];
  const uid = nanoid(12);
  const encryptedEmail = encrypt(email);
  const emailHash = generateHash(email);
  const salt = generateSalt();
  const passwordHash = strongHash(password, salt);
  const keyVersion = getKeyVersion();

  try {
    await repository.createUser(
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
  } catch (err: any) {
    logger.error(`Failed to create user`, { err });

    if (err.message.includes(`duplicate key`)) {
      throw new DuplicateKeyError(`User already exists`);
    } else {
      throw err;
    }
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

  if (!user.password) {
    throw new NotFoundError(`User not found`);
  }

  const passwordHash = strongHash(password, user.salt);

  if (!passwordHash) {
    throw new NotFoundError(`User not found`);
  }

  if (!verifyStrongHash(password, user.password, user.salt)) {
    throw new UnauthorizedError(`Invalid password`);
  }

  return user;
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

export async function getIdToken(
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
