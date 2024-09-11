import * as repository from './users.repository';
import PgClient from 'serverless-postgres';
import { decrypt, generateSalt, strongHash, verifyStrongHash } from 'src/lib/encryption';
import { Logger } from 'winston';
import {
  AuthenticationError,
  ForbiddenError,
  ValidationError,
  VerificationError
} from 'src/lib/errors';
import {
  AuthProvider,
  AuthUser,
  AuthUserIdentityCredentials,
  AuthVerificationCodeType
} from 'src/types/auth.types';
import {
  addUserToApplication,
  createAuthVerificationCode,
  createUserIdentity,
  getOrCreateUser,
  getUserIdentityByEmail,
  getUserMfaChallengeById,
  getUserMfaFactorById,
  invalidateMfaChallengeById,
  sendAuthVerificationCode,
  setUserMfaEnabled,
  setUserMfaFactorLastUsedAt,
  setUserMfaFactorVerified,
  updateUserIdentityData,
  validateAuthVerificationCode
} from './users.service';
import { authenticator } from 'otplib';

export async function registerUser(
  logger: Logger,
  pgClient: PgClient,
  orgId: string,
  appId: string,
  email: string,
  password: string,
  username?: string,
  firstName?: string,
  lastName?: string,
  provider: AuthProvider = AuthProvider.EMAIL
): Promise<string> {
  logger.info(`Registering user`, { orgId, provider });

  try {
    await pgClient.query('BEGIN');

    const autoVerify = false;

    const { id } = await getOrCreateUser(
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

    await addUserToApplication(logger, pgClient, orgId, appId, id);

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
  appId: string,
  keyId: string,
  email: string,
  password: string,
  provider: AuthProvider,
  providerId: string,
  username?: string
): Promise<AuthUser> {
  logger.info(`Registering idp user`, { orgId, provider });

  const autoVerify = true;

  const userData = await getOrCreateUser(
    logger,
    pgClient,
    orgId,
    appId,
    email,
    autoVerify,
    username
  );

  await addUserToApplication(logger, pgClient, orgId, appId, userData.id);

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
  appId: string,
  password: string,
  userIdentity?: AuthUserIdentityCredentials
): Promise<string> {
  logger.debug(`Authenticating user`);

  // const userIdentity = await getUserIdentityByEmail(
  //   logger,
  //   pgClient,
  //   appId,
  //   email,
  //   AuthProvider.EMAIL
  // );

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
  appId: string,
  email: string,
  code: string
): Promise<void> {
  try {
    await pgClient.query('BEGIN');

    const { uid, identityId, verifiedAt } = await getUserIdentityByEmail(
      logger,
      pgClient,
      appId,
      email,
      AuthProvider.EMAIL
    );

    if (verifiedAt) {
      throw new ValidationError(`User already verified`);
    }

    logger.info(`Verifying user`, { appId, identityId });

    await validateAuthVerificationCode(
      logger,
      pgClient,
      identityId,
      code,
      AuthVerificationCodeType.REGISTER
    );

    await Promise.all([
      repository.verifyUser(pgClient, uid),
      repository.verifyUserIdentity(pgClient, identityId),
      repository.invalidateAuthVerificationCode(pgClient, identityId, code)
    ]);

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

    await validateAuthVerificationCode(
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

    await repository.invalidateAuthVerificationCode(pgClient, identityId, code);

    await pgClient.query('COMMIT');
  } catch (err: any) {
    await pgClient.query('ROLLBACK');
    logger.error(`Failed to reset user password`, { err });
    throw err;
  }
}

export async function verifyUserMfaChallenge(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  factorId: string,
  challengeId: string,
  code: string
): Promise<any> {
  logger.debug(`Verifying user mfa challenge`, { uid });

  const validatedUserMfaFactor = await getUserMfaFactorById(logger, pgClient, factorId, uid);

  if (!validatedUserMfaFactor) {
    throw new ForbiddenError('Invalid mfafactor id');
  }

  const { secret, salt } = validatedUserMfaFactor;

  const validatedUserMfaChallenge = await getUserMfaChallengeById(
    logger,
    pgClient,
    challengeId,
    uid
  );

  if (!validatedUserMfaChallenge) {
    throw new ForbiddenError('Unable to verify mfa code');
  }

  const challengeExpiresAt = BigInt(validatedUserMfaChallenge.expiresAt);

  if (challengeExpiresAt < Date.now()) {
    throw new ForbiddenError('Challenge expired');
  }

  const decryptedSecret = decrypt(secret, salt);
  const verified = authenticator.verify({ token: code, secret: decryptedSecret });

  if (!verified) {
    throw new ForbiddenError('Unable to verify mfa code');
  }

  await Promise.all([
    invalidateMfaChallengeById(logger, pgClient, challengeId),
    setUserMfaFactorLastUsedAt(logger, pgClient, factorId)
  ]);
}

export async function enableMfaForUser(
  logger: Logger,
  pgClient: PgClient,
  uid: string,
  factorId: string
): Promise<void> {
  logger.debug(`Enabling mfa for user`, { uid, factorId });

  try {
    pgClient.query('BEGIN');

    await Promise.all([
      setUserMfaEnabled(logger, pgClient, uid),
      setUserMfaFactorVerified(logger, pgClient, factorId)
    ]);

    await pgClient.query('COMMIT');
  } catch (err: any) {
    await pgClient.query('ROLLBACK');
    logger.error(`Failed to enable mfa for user`, { err });
    throw new AuthenticationError(`Failed to enable mfa for user`);
  }
}
