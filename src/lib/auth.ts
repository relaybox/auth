import qrcode from 'qrcode';
import { PolicyEffect } from '@/types/aws.types';
import { PolicyDocument } from 'aws-lambda';

export function generateAuthResponsePolicyDocument(
  effect: PolicyEffect,
  resource: string
): PolicyDocument {
  const policyDocument = <PolicyDocument>{};

  if (effect && resource) {
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];

    const statement: any = {
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource: '*'
    };

    policyDocument.Statement[0] = statement;
  }

  return policyDocument;
}

export function generateAuthMfaTotpQrCodeUrl(
  secret: string,
  email: string,
  issuer: string
): Promise<string> {
  // const encodedSecret = Buffer.from(secret).toString('base64');
  const encodedEmail = encodeURIComponent(email);
  const encodedIssuer = encodeURIComponent(issuer);

  const totpUri = `otpauth://totp/${encodedIssuer}:${encodedEmail}?secret=${secret}&issuer=${encodedIssuer}`;

  return qrcode.toDataURL(totpUri);
}
