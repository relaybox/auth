import crypto from 'crypto';

const AUTH_ENCRYPTION_KEY = process.env.AUTH_ENCRYPTION_KEY || '';
const AUTH_ENCRYPTION_SALT = process.env.AUTH_ENCRYPTION_SALT || '';
const AUTH_HMAC_KEY = process.env.AUTH_HMAC_KEY || '';
const AUTH_ENCRYPTION_ALGORITHM = 'aes-256-cbc';
const SALT_LENGTH = 16;
const ITERATIONS = 100000;
const KEY_LENGTH = 64;
const DIGEST = 'sha512';

export function encrypt(value: string): string {
  const key = crypto.scryptSync(AUTH_ENCRYPTION_KEY, AUTH_ENCRYPTION_SALT, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(AUTH_ENCRYPTION_ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(value), cipher.final()]);
  const encryptedString = `${iv.toString('hex')}:${encrypted.toString('hex')}`;

  return Buffer.from(encryptedString).toString('base64');
}

export function decrypt(encryptedValue: string): string {
  const encryptedString = Buffer.from(encryptedValue, 'base64').toString('utf-8');
  const [ivHex, encryptedHex] = encryptedString.split(':');
  const key = crypto.scryptSync(AUTH_ENCRYPTION_KEY, AUTH_ENCRYPTION_SALT, 32);

  const decipher = crypto.createDecipheriv(
    AUTH_ENCRYPTION_ALGORITHM,
    key,
    Buffer.from(ivHex, 'hex')
  );

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedHex, 'hex')),
    decipher.final()
  ]);

  return decrypted.toString();
}

export function generateHash(value: string): string {
  const hmac = crypto.createHmac('sha256', AUTH_HMAC_KEY);
  hmac.update(value);
  return hmac.digest('hex');
}

export function generateSalt(): string {
  return crypto.randomBytes(SALT_LENGTH).toString('hex');
}

export function strongHash(password: string, salt: string): string {
  const hash = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST).toString('hex');
  return hash;
}

export function verifyStrongHash(password: string, storedHash: string, salt: string): boolean {
  const hash = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}
