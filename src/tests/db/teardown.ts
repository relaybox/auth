import PgClient from 'serverless-postgres';
import { Logger } from 'winston';

export function deleteOrganisation(pgClient: PgClient, orgId: string): Promise<any> {
  const query = `DELETE FROM organisations WHERE id = $1`;

  return pgClient.query(query, [orgId]);
}

export function deleteApplication(pgClient: PgClient, appId: string): Promise<any> {
  const queries = [
    `DELETE FROM applications WHERE id = $1`,
    `DELETE FROM application_authentication_preferences WHERE "appId" = $1`,
    `DELETE FROM authentication_activity_logs WHERE "appId" = $1`,
    `DELETE FROM credentials WHERE "appId" = $1`
  ];

  return Promise.all(queries.map(async (query) => pgClient.query(query, [appId])));
}

export function deleteMockUser(pgClient: PgClient, uid: string): Promise<any> {
  const queries = [
    `DELETE FROM authentication_users WHERE id = $1`,
    `DELETE FROM authentication_users_applications WHERE uid = $1`,
    `DELETE FROM authentication_user_identities WHERE uid = $1`,
    `DELETE FROM authentication_user_verification WHERE uid = $1`
  ];

  return Promise.all(queries.map(async (query) => pgClient.query(query, [uid])));
}

export async function teardownDb(pgClient: PgClient): Promise<any[]> {
  const deleteQueries = [
    `TRUNCATE organisations`,
    `TRUNCATE applications`,
    `TRUNCATE credentials`,
    `TRUNCATE application_authentication_preferences`,
    `TRUNCATE application_authentication_providers`,
    `TRUNCATE authentication_users`,
    `TRUNCATE authentication_users_applications`,
    `TRUNCATE authentication_user_verification`,
    `TRUNCATE authentication_user_identities`,
    `TRUNCATE authentication_activity_logs`
  ];

  return Promise.all(deleteQueries.map(async (query) => pgClient.query(query)));
}
