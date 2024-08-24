import { describe, expect, it } from 'vitest';
import {
  encrypt,
  decrypt,
  searchableEncrypt,
  searchableDecrypt,
  hashPassword,
  verifyPassword
} from 'src/lib/encryption';

describe('encrypt / decrypt', () => {
  it('should encrpt an email address', () => {
    const email = 'test@test.com';
    const encryptedEmail = encrypt(email);
    const decryptedEmail = decrypt(encryptedEmail);

    expect(encryptedEmail).not.toBe(email);
    expect(decryptedEmail).toBe(email);
  });
});

describe('searchableEncrypt', () => {
  it('should encrpt an email address', () => {
    const email = 'test@test.com';
    const encryptedEmail = searchableEncrypt(email);

    expect(encryptedEmail).not.toBe(email);
  });
});

describe('searchableDecrypt', () => {
  it('should encrpt an email address', () => {
    const email = 'test@test.com';
    const encryptedEmail = searchableEncrypt(email);
    const decryptedEmail = searchableDecrypt(encryptedEmail);

    expect(decryptedEmail).toBe(email);
  });
});

describe('hashPassword / verifyPassword', () => {
  it('should generate a hash for a password', () => {
    const password = 'password';

    const hash = hashPassword(password);
    const isValid = verifyPassword(password, hash);

    expect(hash).toBeDefined();
    expect(isValid).toBe(true);
  });
});
