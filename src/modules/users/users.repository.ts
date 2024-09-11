import PgClient from 'serverless-postgres';
import { QueryResult } from 'pg';
import {
  AuthenticationAction,
  AuthenticationActionLog,
  AuthenticationActionResult,
  AuthMfaFactorType,
  AuthProvider,
  AuthVerificationCodeType
} from 'src/types/auth.types';

export function createUser(
  pgClient: PgClient,
  orgId: string,
  appId: string,
  clientid: string,
  email: string,
  emailHash: string,
  autoVerify: boolean = false,
  username: string,
  firstName?: string,
  lastName?: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    INSERT INTO authentication_users (
      "orgId", 
      "appId", 
      "clientId", 
      "email", 
      "emailHash", 
      username, 
      "verifiedAt", 
      "firstName", 
      "lastName"
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9
    ) RETURNING id, "clientId";
  `;

  return pgClient.query(query, [
    orgId,
    appId,
    clientid,
    email,
    emailHash,
    username,
    autoVerify ? now : null,
    firstName || null,
    lastName || null
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
    INSERT INTO authentication_user_identities (
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
  appId: string,
  emailHash: string
): Promise<QueryResult> {
  let query = `
    SELECT * FROM authentication_users
    WHERE "appId" = $1 AND "emailHash" = $2;
  `;

  return pgClient.query(query, [appId, emailHash]);
}

export function getUserIdentityByEmailHash(
  pgClient: PgClient,
  appId: string,
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
    INNER JOIN authentication_user_identities aui 
    ON aui."uid" = au."id"
    WHERE au."appId" = $1 AND aui."emailHash" = $2
  `;

  if (provider) {
    query += `
      AND aui."provider" = $3
    `;
  }

  return pgClient.query(query, [appId, emailHash, provider]);
}

export function getUserIdentityByProviderId(
  pgClient: PgClient,
  appId: string,
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
    INNER JOIN authentication_user_identities aui 
    ON aui."uid" = au."id"
    WHERE au."appId" = $1 AND aui."providerId" = $2 AND aui."provider" = $3
  `;

  return pgClient.query(query, [appId, providerId, provider]);
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
    FROM authentication_user_verification auv
    INNER JOIN authentication_user_identities aui 
    ON aui."id" = auv."identityId"
    WHERE auv."code" = $1
  `;

  return pgClient.query(query, [code]);
}

export function getAuthDataByKeyId(pgClient: PgClient, keyId: string): Promise<QueryResult> {
  const query = `
    SELECT "orgId", "secretKey", "appId", "appPid"
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
    INSERT INTO authentication_user_verification (
      "uid", "identityId", "code", "expiresAt", type
    ) VALUES (
      $1, $2, $3, $4, $5
    ) RETURNING code;
  `;

  return pgClient.query(query, [uid, identityId, code, expiresAt, type]);
}

export function validateAuthVerificationCode(
  pgClient: PgClient,
  identityId: string,
  code: string,
  type: AuthVerificationCodeType
): Promise<QueryResult> {
  const query = `
    SELECT "code", "expiresAt", "verifiedAt", "createdAt"
    FROM authentication_user_verification
    WHERE "identityId" = $1 AND "code" = $2 AND type = $3
    LIMIT 1;
  `;

  return pgClient.query(query, [identityId, code, type]);
}

export function invalidateAuthVerificationCode(
  pgClient: PgClient,
  identityId: string,
  code: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_user_verification 
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
    UPDATE authentication_user_identities
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
    UPDATE authentication_user_identities 
    SET ${setValues.join(', ')}
    WHERE id = $${params.length}; 
  `;

  return pgClient.query(query, params);
}

export async function getUserDataByClientId(
  pgClient: PgClient,
  clientId: string
): Promise<QueryResult> {
  const query = `
    SELECT 
      id, 
      "clientId", 
      "createdAt", 
      "updatedAt", 
      username, 
      "orgId", 
      "appId", 
      "appId", 
      "isOnline", 
      "lastOnline",
      "blockedAt"
    FROM authentication_users
    WHERE "clientId" = $1;
  `;

  return pgClient.query(query, [clientId]);
}

export async function getUserDataById(pgClient: PgClient, id: string): Promise<QueryResult> {
  const query = `
    WITH identities_cte AS (
      SELECT 
      aui."uid" AS user_id,
      json_agg(
        json_build_object(
          'id', aui.id,
          'provider', aui.provider,
          'providerId', aui."providerId",
          'verifiedAt', aui."verifiedAt"
        )
      ) AS identities
      FROM authentication_user_identities aui
      WHERE aui."uid" = $1
        AND aui."verifiedAt" IS NOT NULL
        AND aui."deletedAt" IS NULL
      GROUP BY aui."uid"
    ),
    factors_cte AS (
      SELECT 
      aumf."uid" AS user_id,
      json_agg(
        json_build_object(
          'id', aumf.id,
          'type', aumf.type,
          'verifiedAt', aumf."verifiedAt"
        )
      ) AS factors
      FROM authentication_user_mfa_factors aumf
      WHERE aumf."uid" = $1 
        AND aumf."verifiedAt" IS NOT NULL 
        AND aumf."deletedAt" IS NULL
      GROUP BY aumf."uid"
    )
    SELECT 
      au.id,
      au."orgId",
      au."appId",
      au.username, 
      au."clientId", 
      au.email, 
      au."createdAt", 
      au."updatedAt", 
      au."verifiedAt",
      au."authMfaEnabled",
      au."blockedAt",
      COALESCE(identities_cte.identities, '[]') AS identities,
      COALESCE(factors_cte.factors, '[]') AS factors
    FROM authentication_users au
    LEFT JOIN identities_cte ON au.id = identities_cte.user_id
    LEFT JOIN factors_cte ON au.id = factors_cte.user_id
    WHERE au.id = $1;
  `;

  return pgClient.query(query, [id]);
}

export function createUserMfaFactor(
  pgClient: PgClient,
  uid: string,
  type: AuthMfaFactorType,
  secret: string,
  salt: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    INSERT INTO authentication_user_mfa_factors (
      "uid", "type", "secret", "salt", "createdAt"
    ) VALUES (
      $1, $2, $3, $4, $5
    ) RETURNING id, type;
  `;

  return pgClient.query(query, [uid, type, secret, salt, now]);
}

export async function getUserMfaFactorById(
  pgClient: PgClient,
  id: string,
  uid: string
): Promise<QueryResult> {
  const query = `
    SELECT * FROM authentication_user_mfa_factors
    WHERE "id" = $1 AND "uid" = $2 AND "deletedAt" IS NULL;
  `;

  return pgClient.query(query, [id, uid]);
}

export async function createUserMfaChallenge(
  pgClient: PgClient,
  uid: string,
  factorId: string,
  expiresAt: number
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    INSERT INTO authentication_user_mfa_challenges (
      "uid", "factorId", "createdAt", "expiresAt"
    ) VALUES (
      $1, $2, $3, $4
    ) RETURNING id;
  `;

  return pgClient.query(query, [uid, factorId, now, expiresAt]);
}

export async function getUserMfaChallengeById(
  pgClient: PgClient,
  id: string,
  uid: string
): Promise<QueryResult> {
  const query = `
    SELECT * FROM authentication_user_mfa_challenges
    WHERE "id" = $1 AND "uid" = $2 AND "verifiedAt" IS NULL;
  `;

  return pgClient.query(query, [id, uid]);
}

export async function getMfaFactorTypeForUser(
  pgClient: PgClient,
  uid: string,
  type: AuthMfaFactorType
): Promise<QueryResult> {
  const query = `
    SELECT * FROM authentication_user_mfa_factors
    WHERE "uid" = $1 AND "type" = $2 AND "deletedAt" IS NULL;
  `;

  return pgClient.query(query, [uid, type]);
}

export async function invalidateMfaChallenge(pgClient: PgClient, id: string): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_user_mfa_challenges 
    SET "verifiedAt" = $2
    WHERE "id" = $1;
  `;

  return pgClient.query(query, [id, now]);
}

export async function setUserMfaEnabled(pgClient: PgClient, uid: string): Promise<QueryResult> {
  const query = `
    UPDATE authentication_users 
    SET "authMfaEnabled" = TRUE
    WHERE id = $1;
  `;

  return pgClient.query(query, [uid]);
}

export async function setUserMfaFactorVerified(
  pgClient: PgClient,
  factorId: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_user_mfa_factors 
    SET "verifiedAt" = $1
    WHERE id = $2;
  `;

  return pgClient.query(query, [now, factorId]);
}

export async function setUserMfaFactorLastUsedAt(
  pgClient: PgClient,
  factorId: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_user_mfa_factors 
    SET "lastUsedAt" = $1
    WHERE id = $2;
  `;

  return pgClient.query(query, [now, factorId]);
}

export function getUserEmailAddress(pgClient: PgClient, uid: string): Promise<QueryResult> {
  const query = `
    SELECT "email" FROM authentication_users
    WHERE id = $1;
  `;

  return pgClient.query(query, [uid]);
}

export function updateUserIdentityLastLogin(
  pgClient: PgClient,
  uid: string,
  provider: AuthProvider
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    UPDATE authentication_user_identities
    SET "lastLoginAt" = $1
    WHERE uid = $2 AND provider = $3
    RETURNING id;
  `;

  return pgClient.query(query, [now, uid, provider]);
}

export function updateUserStatus(
  pgClient: PgClient,
  uid: string,
  status: string
): Promise<QueryResult> {
  const query = `
    UPDATE authentication_users
    SET "status" = $1
    WHERE id = $2;
  `;

  return pgClient.query(query, [status, uid]);
}

export function addUserToApplication(
  pgClient: PgClient,
  orgId: string,
  appId: string,
  uid: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    INSERT INTO authentication_users_applications (
      "orgId", "appId", "uid", "createdAt"
    ) VALUES (
      $1, $2, $3, $4
    );
  `;

  return pgClient.query(query, [orgId, appId, uid, now]);
}

export function getUserByAppId(
  pgClient: PgClient,
  appId: string,
  uid: string
): Promise<QueryResult> {
  const query = `
    SELECT id FROM authentication_users_applications
    WHERE "appId" = $1 AND "uid" = $2;
  `;

  return pgClient.query(query, [appId, uid]);
}

export function getAuthProviderDataByProviderName(
  pgClient: PgClient,
  appId: string,
  providerName: string
): Promise<QueryResult> {
  const query = `
    SELECT aap."clientId", aap."clientSecret", aap.salt
    FROM authentication_providers ap
    LEFT JOIN application_authentication_providers aap 
    ON ap."id" = aap."providerId" AND aap."deletedAt" IS NULL
    WHERE ap."name" = $1 AND aap."appId" = $2 AND aap.enabled = TRUE AND aap."deletedAt" IS NULL;
  `;

  return pgClient.query(query, [providerName, appId]);
}

export function getApplicationAuthenticationPreferences(
  pgClient: PgClient,
  appId: string
): Promise<QueryResult> {
  const query = `
    SELECT "tokenExpiry"::int, "sessionExpiry"::int, "authStorageType", "passwordPattern"
    FROM application_authentication_preferences
    WHERE "appId" = $1;
  `;

  return pgClient.query(query, [appId]);
}

export function validateUsername(
  pgClient: PgClient,
  appId: string,
  username: string
): Promise<QueryResult> {
  const query = `
    SELECT id FROM authentication_users
    WHERE "appId" = $1 AND username = $2;
  `;

  return pgClient.query(query, [appId, username]);
}

export function createAuthenticationActionLogEntry(
  pgClient: PgClient,
  action: AuthenticationAction,
  actionResult: AuthenticationActionResult,
  ipAddress: string,
  authenticationActionLog: AuthenticationActionLog
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const { uid, identityId, keyId, errorMessage } = authenticationActionLog;

  const query = `
    INSERT INTO authentication_action_logs (
      "uid", "identityId", "action", "actionResult", "ipAddress", "keyId", "errorMessage", "createdAt"
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8
    );
  `;

  return pgClient.query(query, [
    uid,
    identityId,
    action,
    actionResult,
    ipAddress,
    keyId,
    errorMessage,
    now
  ]);
}
