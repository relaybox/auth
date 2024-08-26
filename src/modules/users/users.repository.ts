import PgClient from 'serverless-postgres';
import { QueryResult } from 'pg';

export function createUser(
  pgClient: PgClient,
  orgId: string,
  clientid: string,
  username: string,
  email: string,
  emailHash: string,
  password: string,
  salt: string,
  keyVersion: number,
  provider: string = 'email'
): Promise<QueryResult> {
  const now = new Date().toISOString();
  const query = `
    INSERT INTO authentication_users (
      "orgId", "clientId", username, email, "emailHash", password, salt, "keyVersion", "provider", "verifiedAt"
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
    ) RETURNING id, "clientId";
  `;

  return pgClient.query(query, [
    orgId,
    clientid,
    username,
    email,
    emailHash,
    password,
    salt,
    keyVersion,
    provider,
    provider ? now : null
  ]);
}

export function getUserByEmailHash(pgClient: PgClient, emailHash: string): Promise<QueryResult> {
  const query = `
    SELECT * FROM authentication_users 
    WHERE "emailHash" = $1;
  `;

  return pgClient.query(query, [emailHash]);
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
  code: number
): Promise<QueryResult> {
  const now = Date.now();
  const expiresAt = new Date(now + 5 * 60 * 1000).toISOString();

  const query = `
    INSERT INTO authentication_users_verification (
      "uid", "code", "expiresAt"
    ) VALUES (
      $1, $2, $3
    ) RETURNING code;
  `;

  return pgClient.query(query, [uid, code, expiresAt]);
}

export function validateVerificationCode(
  pgClient: PgClient,
  uid: string,
  code: number
): Promise<QueryResult> {
  const query = `
    SELECT "code", "expiresAt", "verifiedAt"
    FROM authentication_users_verification
    WHERE "uid" = $1 AND "code" = $2
    LIMIT 1;
  `;

  return pgClient.query(query, [uid, code]);
}

export function verifyUserCode(
  pgClient: PgClient,
  uid: string,
  code: number
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
