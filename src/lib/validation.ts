import { APIGatewayProxyEvent } from 'aws-lambda';
import { SchemaValidationError } from './errors';

export function validateEventSchema(event: APIGatewayProxyEvent, schema: any): any {
  if (!event.body) {
    throw new SchemaValidationError('Request body undefined');
  }

  const body = JSON.parse(event.body!);
  const result = schema.safeParse(body);

  if (!result.success) {
    throw new SchemaValidationError('Schema validation failed', result.error.issues);
  }

  return result.data;
}
