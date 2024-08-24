import crypto from 'crypto';

const AUTH_ENCRYPTION_KEY = process.env.AUTH_ENCRYPTION_KEY || '';
const AUTH_ENCRYPTION_SALT = process.env.AUTH_ENCRYPTION_SALT || '';
const AUTH_HMAC_KEY = process.env.AUTH_HMAC_KEY || '';
const AUTH_ENCRYPTION_ALGORITHM = 'aes-256-cbc';
const SALT_LENGTH = 16;
const ITERATIONS = 100000;
const KEY_LENGTH = 64;
const DIGEST = 'sha512';

export function encrypt(email: string): string {
  const key = crypto.scryptSync(AUTH_ENCRYPTION_KEY, AUTH_ENCRYPTION_SALT, 32);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(AUTH_ENCRYPTION_ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(email), cipher.final()]);

  const encryptedString = `${iv.toString('hex')}:${encrypted.toString('hex')}`;

  return Buffer.from(encryptedString).toString('base64');
}

export function decrypt(encryptedEmail: string): string {
  const encryptedString = Buffer.from(encryptedEmail, 'base64').toString('utf-8');

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

export function generateSearchableHash(email: string): string {
  const hmac = crypto.createHmac('sha256', AUTH_HMAC_KEY);
  hmac.update(email);
  return hmac.digest('hex');
}

export function searchableEncrypt(email: string): string {
  const key = crypto.scryptSync(AUTH_ENCRYPTION_KEY, '', 32);
  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv(AUTH_ENCRYPTION_ALGORITHM, key, iv);

  let encrypted = cipher.update(email, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return encrypted;
}

export function searchableDecrypt(encryptedEmail: string): string {
  const key = crypto.scryptSync(AUTH_ENCRYPTION_KEY, '', 32);
  const iv = Buffer.alloc(16, 0);
  const decipher = crypto.createDecipheriv(AUTH_ENCRYPTION_ALGORITHM, key, iv);

  let decrypted = decipher.update(encryptedEmail, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const hash = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST);
  const saltedHash = Buffer.concat([salt, hash]).toString('base64');

  return saltedHash;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const saltedHashBuffer = Buffer.from(storedHash, 'base64');
  const salt = saltedHashBuffer.subarray(0, SALT_LENGTH);
  const originalHash = saltedHashBuffer.subarray(SALT_LENGTH);
  const hash = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST);

  return crypto.timingSafeEqual(hash, originalHash);
}
