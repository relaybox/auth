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
  provider = AuthProvider.EMAIL,
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

export function getUserIdentityByEmailHash(
  pgClient: PgClient,
  orgId: string,
  emailHash: string,
  provider?: AuthProvider
): Promise<QueryResult> {
  let query = `
    SELECT 
      aui.uid, 
      aui.id as "identityId", 
      aui."verifiedAt", 
      aui.email,
      aui.password, 
      aui.salt,
      aui.provider,
      aui."providerId"
    FROM authentication_users au
    INNER JOIN authentication_users_identities aui 
    ON aui."uid" = au."id"
    WHERE au."orgId" = $1 AND aui."emailHash" = $2
  `;

  if (provider) {
    query += `
      AND aui."provider" = $3
    `;
  }

  return pgClient.query(query, [orgId, emailHash, provider]);
}

// export function getUserByProviderId(
//   pgClient: PgClient,
//   orgId: string,
//   providerId: string,
//   provider: AuthProvider
// ): Promise<QueryResult> {
//   let query = `
//     SELECT * FROM authentication_users
//     WHERE "orgId" = $1 AND "providerId" = $2 AND "provider" = $3
//   `;

//   return pgClient.query(query, [orgId, providerId, provider]);
// }

export function getUserIdentityByProviderId(
  pgClient: PgClient,
  orgId: string,
  providerId: string,
  provider: AuthProvider
): Promise<QueryResult> {
  const query = `
    SELECT 
      au.id,
      au."clientId",
      aui.id as "identityId", 
      aui."verifiedAt", 
      aui.email,
      aui.password, 
      aui.salt,
      aui.provider,
      aui."providerId"
    FROM authentication_users au
    INNER JOIN authentication_users_identities aui 
    ON aui."uid" = au."id"
    WHERE au."orgId" = $1 AND aui."providerId" = $2 AND aui."provider" = $3
  `;

  return pgClient.query(query, [orgId, providerId, provider]);
}

export function getUserIdentityByVerificationCode(
  pgClient: PgClient,
  code: string
): Promise<QueryResult> {
  const query = `
    SELECT 
      aui.uid,
      aui.id as "identityId", 
      aui."verifiedAt", 
    FROM authentication_users_verification auv
    INNER JOIN authentication_users_identities aui 
    ON aui."id" = auv."identityId"
    WHERE auv."code" = $1
  `;

  return pgClient.query(query, [code]);
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
  identityId: string,
  code: number,
  type: AuthVerificationCodeType
): Promise<QueryResult> {
  const now = Date.now();
  const expiresAt = new Date(now + 5 * 60 * 1000).toISOString();

  const query = `
    INSERT INTO authentication_users_verification (
      "uid", "identityId", "code", "expiresAt", type
    ) VALUES (
      $1, $2, $3, $4, $5
    ) RETURNING code;
  `;

  return pgClient.query(query, [uid, identityId, code, expiresAt, type]);
}

export function validateVerificationCode(
  pgClient: PgClient,
  identityId: string,
  code: string,
  type: AuthVerificationCodeType
): Promise<QueryResult> {
  const query = `
    SELECT "code", "expiresAt", "verifiedAt", "createdAt"
    FROM authentication_users_verification
    WHERE "identityId" = $1 AND "code" = $2 AND type = $3
    LIMIT 1;
  `;

  return pgClient.query(query, [identityId, code, type]);
}

export function invalidateVerificationCode(
  pgClient: PgClient,
  identityId: string,
  code: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_users_verification 
    SET "verifiedAt" = $2
    WHERE "identityId" = $1 AND "code" = $3;
  `;

  return pgClient.query(query, [identityId, now, code]);
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

export function verifyUserIdentity(pgClient: PgClient, identityId: string): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_users_identities
    SET "verifiedAt" = $2
    WHERE id = $1;
  `;

  return pgClient.query(query, [identityId, now]);
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

export function updateUserIdentityData(
  pgClient: PgClient,
  identityId: string,
  userData: { key: string; value: string }[]
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const setValues = userData.map(({ key }, i) => `"${key}" = $${i + 1}`);
  const params = [...userData.map(({ value }) => value), identityId];

  const query = `
    UPDATE authentication_users_identities 
    SET ${setValues.join(', ')}
    WHERE id = $${params.length}; 
  `;

  return pgClient.query(query, params);
}

function getUserDataQueryBy(idFilter: string): string {
  return `
    SELECT 
      au.id, 
      au.username, 
      au."clientId", 
      au.email, 
      au."createdAt", 
      au."updatedAt", 
      au."verifiedAt",
      json_agg(
        json_build_object(
          'id', aui.id,
          'provider', aui.provider,
          'providerId', aui."providerId",
          'verifiedAt', aui."verifiedAt"
        )
      ) AS identities
    FROM authentication_users au
    LEFT JOIN authentication_users_identities aui ON au.id = aui."uid"
    WHERE au."${idFilter}" = $1
    GROUP BY au.id;
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
