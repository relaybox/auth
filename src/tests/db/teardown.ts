import PgClient from 'serverless-postgres';
import { Logger } from 'winston';

export async function teardownDb(logger: Logger, pgClient: PgClient): Promise<void> {
  const deleteOrganisationsQuery = `DELETE FROM organisations`;
  const deleteApplicationsQuery = `DELETE FROM applications`;
  const deleteCredentialsQuery = `DELETE FROM credentials`;

  await Promise.all([
    pgClient.query(deleteOrganisationsQuery),
    pgClient.query(deleteApplicationsQuery),
    pgClient.query(deleteCredentialsQuery)
  ]);
}
