import * as crypto from 'crypto';

export function generateAuthSecretHash(
  field: string,
  clientId: string,
  clientSecret: string
): string {
  return crypto
    .createHmac('SHA256', clientSecret)
    .update(field + clientId)
    .digest('base64');
}

export function generateAuthHashId(email: string, authHashIdSecret: string): string {
  return crypto
    .createHmac('SHA256', authHashIdSecret)
    .update(email + authHashIdSecret)
    .digest('base64');
}
