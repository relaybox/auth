import { describe, expect, it } from 'vitest';
import { encrypt, decrypt, strongHash, verifyStrongHash, generateSalt } from 'src/lib/encryption';

describe('encrypt / decrypt', () => {
  it('should encrpt an email address', () => {
    const email = 'test@test.com';
    const encryptedEmail = encrypt(email);
    const decryptedEmail = decrypt(encryptedEmail);

    expect(encryptedEmail).not.toBe(email);
    expect(decryptedEmail).toBe(email);
  });
});

describe('strongHash / verifyStrongHash', () => {
  it('should generate a hash for a password', () => {
    const password = 'password';
    const salt = generateSalt();
    const hash = strongHash(password, salt);
    const isValid = verifyStrongHash(password, hash, salt);

    expect(hash).toBeDefined();
    expect(isValid).toBe(true);
  });
});
