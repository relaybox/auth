import { describe, expect, it } from 'vitest';
import {
  encrypt,
  decrypt,
  strongHash,
  generateSalt,
  verifyStrongHash,
  generateSecret
} from 'src/lib/encryption';

describe('encryption', () => {
  describe('encrypt', () => {
    it('should encrypt a string', () => {
      const string = 'test@test.com';
      const encryptedString = encrypt(string);
      expect(encryptedString).not.toBe(string);
    });
  });

  describe('decrypt', () => {
    it('should decrypt an encrypted string', () => {
      const string = 'test@test.com';
      const encryptedString = encrypt(string);
      const decryptedString = decrypt(encryptedString);
      expect(decryptedString).toBe(string);
    });
  });

  describe('strongHash', () => {
    it('should generate a hash from a string', () => {
      const string = 'password';
      const salt = generateSalt();
      const hash = strongHash(string, salt);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(string);
    });
  });

  describe('verifyStrongHash', () => {
    it('should verify a hash value matches a string', () => {
      const string = 'password';
      const salt = generateSalt();
      const hash = strongHash(string, salt);
      const isMatch = verifyStrongHash(string, hash, salt);

      expect(hash).toBeDefined();
      expect(isMatch).toBe(true);
    });
  });

  describe('generateSecret', () => {
    it('should a 64 bit secret secret', () => {
      expect(generateSecret()).toHaveLength(64);
    });
  });
});
