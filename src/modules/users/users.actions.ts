import * as repository from './users.repository';
import PgClient from 'serverless-postgres';
import { generateSalt, strongHash, verifyStrongHash } from 'src/lib/encryption';
import { Logger } from 'winston';
import { AuthenticationError, ValidationError, VerificationError } from 'src/lib/errors';
import { AuthProvider, AuthUser, AuthVerificationCodeType } from 'src/types/auth.types';
import {
  createAuthVerificationCode,
  createUserIdentity,
  getOrCreateUser,
  getUserIdentityByEmail,
  sendAuthVerificationCode,
  updateUserIdentityData,
  validateVerificationCode
} from './users.service';

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

  const userIdentity = await getUserIdentityByEmail(
    logger,
    pgClient,
    orgId,
    email,
    AuthProvider.EMAIL
  );

  if (!userIdentity) {
    logger.warn(`User auth credenials not found`);
    throw new AuthenticationError('Login failed');
  }

  if (!userIdentity.verifiedAt || !userIdentity.password) {
    logger.warn(`User not verified`);
    throw new AuthenticationError('Login failed');
  }

  const passwordHash = strongHash(password, userIdentity.salt);

  if (!passwordHash) {
    logger.warn(`Password hash failed`);
    throw new AuthenticationError('Login failed');
  }

  const verifiedPassword = verifyStrongHash(password, userIdentity.password, userIdentity.salt);

  if (!verifiedPassword) {
    logger.warn(`Invalid password`);
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
