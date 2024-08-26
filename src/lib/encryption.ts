import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { ExtendedClientJwtPayload } from 'src/types/jwt.types';

const AUTH_ENCRYPTION_KEY = process.env.AUTH_ENCRYPTION_KEY || '';
const AUTH_ENCRYPTION_SALT = process.env.AUTH_ENCRYPTION_SALT || '';
const AUTH_HMAC_KEY = process.env.AUTH_HMAC_KEY || '';
const AUTH_ENCRYPTION_ALGORITHM = 'aes-256-cbc';
const SALT_LENGTH = 16;
const ITERATIONS = 100000;
const KEY_LENGTH = 64;
const JWT_ISSUER = process.env.JWT_ISSUER || '';
const JWT_HASHING_ALGORITHM = 'HS256';

enum Encoding {
  BASE64 = 'base64',
  HEX = 'hex',
  UTF8 = 'utf-8'
}

enum Digest {
  SHA256 = 'sha256',
  SHA512 = 'sha512'
}

export function encrypt(value: string): string {
  const key = crypto.scryptSync(AUTH_ENCRYPTION_KEY, AUTH_ENCRYPTION_SALT, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(AUTH_ENCRYPTION_ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(value), cipher.final()]);
  const encryptedString = `${iv.toString(Encoding.HEX)}:${encrypted.toString(Encoding.HEX)}`;

  return Buffer.from(encryptedString).toString(Encoding.BASE64);
}

export function decrypt(encryptedValue: string): string {
  const encryptedString = Buffer.from(encryptedValue, Encoding.BASE64).toString(Encoding.UTF8);
  const [ivHex, encryptedHex] = encryptedString.split(':');
  const key = crypto.scryptSync(AUTH_ENCRYPTION_KEY, AUTH_ENCRYPTION_SALT, 32);

  const decipher = crypto.createDecipheriv(
    AUTH_ENCRYPTION_ALGORITHM,
    key,
    Buffer.from(ivHex, Encoding.HEX)
  );

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedHex, Encoding.HEX)),
    decipher.final()
  ]);

  return decrypted.toString();
}

export function generateHash(value: string): string {
  const hmac = crypto.createHmac(Digest.SHA256, AUTH_HMAC_KEY);
  hmac.update(value);
  return hmac.digest(Encoding.HEX);
}

export function generateSalt(): string {
  return crypto.randomBytes(SALT_LENGTH).toString(Encoding.HEX);
}

export function strongHash(password: string, salt: string): string {
  const hash = crypto
    .pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, Digest.SHA512)
    .toString(Encoding.HEX);

  return hash;
}

export function verifyStrongHash(password: string, storedHash: string, salt: string): boolean {
  const hash = crypto
    .pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, Digest.SHA512)
    .toString(Encoding.HEX);

  return crypto.timingSafeEqual(
    Buffer.from(hash, Encoding.HEX),
    Buffer.from(storedHash, Encoding.HEX)
  );
}

export function getKeyVersion() {
  return 1;
}

export function generateAuthToken(
  payload: ExtendedClientJwtPayload,
  secretKey: string,
  expiresIn: number
): string {
  return jwt.sign(payload, secretKey, {
    expiresIn,
    algorithm: JWT_HASHING_ALGORITHM,
    issuer: JWT_ISSUER
  });
}
