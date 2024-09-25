import PgClient from 'serverless-postgres';
import { Logger } from 'winston';

export async function teardownDb(logger: Logger, pgClient: PgClient): Promise<void> {
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

  await Promise.all(
    deleteQueries.map(async (query) => {
      return pgClient.query(query);
    })
  );
}
