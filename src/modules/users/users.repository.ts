import PgClient from 'serverless-postgres';
import { QueryResult } from 'pg';
import { AuthProvider, AuthVerificationCodeType } from 'src/types/auth.types';

export function createUser(
  pgClient: PgClient,
  orgId: string,
  clientid: string,
  email: string,
  emailHash: string,
  password: string,
  salt: string,
  keyVersion: number,
  provider: string = 'email',
  providerId: string | null = null,
  username: string,
  autoVerify: boolean = false
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    INSERT INTO authentication_users (
      "orgId", "clientId", email, "emailHash", password, salt, "keyVersion", "provider", "providerId", username, "verifiedAt"
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
    ) RETURNING id, "clientId";
  `;

  return pgClient.query(query, [
    orgId,
    clientid,
    email,
    emailHash,
    password,
    salt,
    keyVersion,
    provider,
    providerId,
    username,
    autoVerify ? now : null
  ]);
}

export function createUserIdentity(
  pgClient: PgClient,
  uid: string,
  email: string,
  emailHash: string,
  password: string,
  salt: string,
  keyVersion: number,
  provider: string = 'email',
  providerId: string | null = null,
  autoVerify: boolean = false
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    INSERT INTO authentication_users_identities (
      "uid", email, "emailHash", password, salt, "keyVersion", "provider", "providerId", "verifiedAt"
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9
    ) RETURNING id;
  `;

  return pgClient.query(query, [
    uid,
    email,
    emailHash,
    password,
    salt,
    keyVersion,
    provider,
    providerId,
    autoVerify ? now : null
  ]);
}

export function getUserByEmailHash(
  pgClient: PgClient,
  orgId: string,
  emailHash: string,
  provider: AuthProvider
): Promise<QueryResult> {
  let query = `
    SELECT * FROM authentication_users 
    WHERE "orgId" = $1 AND "emailHash" = $2 AND "provider" = $3
  `;

  return pgClient.query(query, [orgId, emailHash, provider]);
}

export function getUserByProviderId(
  pgClient: PgClient,
  orgId: string,
  providerId: string,
  provider: AuthProvider
): Promise<QueryResult> {
  let query = `
    SELECT * FROM authentication_users 
    WHERE "orgId" = $1 AND "providerId" = $2 AND "provider" = $3
  `;

  return pgClient.query(query, [orgId, providerId, provider]);
}

export function getAuthDataByKeyId(pgClient: PgClient, keyId: string): Promise<QueryResult> {
  const query = `
    SELECT "orgId", "secretKey" 
    FROM credentials
    WHERE "keyId" = $1;
  `;

  return pgClient.query(query, [keyId]);
}

export function createAuthVerificationCode(
  pgClient: PgClient,
  uid: string,
  code: number,
  type: AuthVerificationCodeType
): Promise<QueryResult> {
  const now = Date.now();
  const expiresAt = new Date(now + 5 * 60 * 1000).toISOString();

  const query = `
    INSERT INTO authentication_users_verification (
      "uid", "code", "expiresAt", type
    ) VALUES (
      $1, $2, $3, $4
    ) RETURNING code;
  `;

  return pgClient.query(query, [uid, code, expiresAt, type]);
}

export function validateVerificationCode(
  pgClient: PgClient,
  uid: string,
  code: string,
  type: AuthVerificationCodeType
): Promise<QueryResult> {
  const query = `
    SELECT "code", "expiresAt", "verifiedAt"
    FROM authentication_users_verification
    WHERE "uid" = $1 AND "code" = $2 AND type = $3
    LIMIT 1;
  `;

  return pgClient.query(query, [uid, code, type]);
}

export function invalidateVerificationCode(
  pgClient: PgClient,
  uid: string,
  code: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_users_verification 
    SET "verifiedAt" = $2
    WHERE "uid" = $1 AND "code" = $3;
  `;

  return pgClient.query(query, [uid, now, code]);
}

export function verifyUser(pgClient: PgClient, uid: string): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_users 
    SET "verifiedAt" = $2
    WHERE id = $1;
  `;

  return pgClient.query(query, [uid, now]);
}

export function verifyUserIdentity(pgClient: PgClient, uid: string): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_users_identities
    SET "verifiedAt" = $2
    WHERE uid = $1;
  `;

  return pgClient.query(query, [uid, now]);
}

export function updateUserData(
  pgClient: PgClient,
  uid: string,
  userData: { key: string; value: string }[]
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const setValues = userData.map(({ key }, i) => `"${key}" = $${i + 1}`);
  const params = [...userData.map(({ value }) => value), uid];

  const query = `
    UPDATE authentication_users 
    SET ${setValues.join(', ')}
    WHERE id = $${params.length};
  `;

  return pgClient.query(query, params);
}

function getUserDataQueryBy(idFilter: string): string {
  return `
    SELECT id, username, "clientId", email, "createdAt", "updatedAt", "provider", "providerId" 
    FROM authentication_users
    WHERE "${idFilter}" = $1;
  `;
}

export async function getUserDataByClientId(
  pgClient: PgClient,
  clientId: string
): Promise<QueryResult> {
  const query = getUserDataQueryBy('clientId');

  return pgClient.query(query, [clientId]);
}

export async function getUserDataById(pgClient: PgClient, id: string): Promise<QueryResult> {
  const query = getUserDataQueryBy('id');

  return pgClient.query(query, [id]);
}
