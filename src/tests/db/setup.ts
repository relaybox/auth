import PgClient from 'serverless-postgres';
import { QueryResult } from 'pg';
import { Logger } from 'winston';

export async function setupDb(logger: Logger, pgClient: PgClient): Promise<void> {
  const query = `
    SELECT * FROM organisations
  `;

  const { rows } = await pgClient.query(query);

  return rows[0];
}
