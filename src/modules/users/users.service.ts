import { nanoid } from 'nanoid';
import * as repository from './users.repository';
import PgClient from 'serverless-postgres';
import { encrypt, generateHash, generateSalt, getKeyVersion, strongHash } from 'src/lib/encryption';
import { Logger } from 'winston';
import { DuplicateKeyError } from 'src/lib/errors';

export async function getUserByEmail(
  logger: Logger,
  pgClient: PgClient,
  email: string
): Promise<any> {
  logger.debug(`Getting user by email`);

  const { rows } = await repository.getUserByEmail(pgClient, email);

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
