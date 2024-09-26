import PgClient from 'serverless-postgres';
import { Logger } from 'winston';
import { DbState } from './types';

export function deleteOrganisation(pgClient: PgClient, orgId: string): Promise<any> {
  const query = `DELETE FROM organisations WHERE id = $1`;

  return pgClient.query(query, [orgId]);
}

export async function deleteApplication(pgClient: PgClient, appId: string): Promise<any> {
  const queries = [
    pgClient.query(`DELETE FROM applications WHERE id = $1`, [appId]),
    pgClient.query(`DELETE FROM application_authentication_preferences WHERE "appId" = $1`, [
      appId
    ]),
    pgClient.query(`DELETE FROM authentication_activity_logs`, []),
    pgClient.query(`DELETE FROM credentials WHERE "appId" = $1`, [appId])
  ];

  return Promise.all(queries);
}

export function deleteMockUserById(pgClient: PgClient, uid: string): Promise<any> {
  const queries = [
    `DELETE FROM authentication_users WHERE id = $1`,
    `DELETE FROM authentication_users_applications WHERE uid = $1`,
    `DELETE FROM authentication_user_identities WHERE uid = $1`,
    `DELETE FROM authentication_user_verification WHERE uid = $1`
  ];

  return Promise.all(queries.map(async (query) => pgClient.query(query, [uid])));
}

// export function purgeDbState(pgClient: PgClient, mockDbState: DbState): Promise<any[]> {
//   const { orgId, appId } = mockDbState;
//   return Promise.all([deleteOrganisation(pgClient, orgId), deleteApplication(pgClient, appId)]);
// }

export async function purgeDbState(pgClient: PgClient): Promise<any[]> {
  const deleteQueries = [
    `TRUNCATE organisations`,
    `TRUNCATE applications`,
    `TRUNCATE credentials`,
    `TRUNCATE application_authentication_preferences`,
    `TRUNCATE authentication_users`,
    `TRUNCATE authentication_users_applications`,
    `TRUNCATE authentication_user_verification`,
    `TRUNCATE authentication_user_identities`,
    `TRUNCATE authentication_activity_logs`
  ];

  return Promise.all(deleteQueries.map(async (query) => pgClient.query(query)));
}
