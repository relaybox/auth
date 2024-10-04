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
      const stringToEncrypt = 'test@test.com';
      const encryptedString = encrypt(stringToEncrypt);
      expect(encryptedString).not.toBe(stringToEncrypt);
    });
  });

  describe('decrypt', () => {
    it('should decrypt an encrypted string', () => {
      const stringToEncrypt = 'test@test.com';
      const encryptedString = encrypt(stringToEncrypt);
      const decryptedString = decrypt(encryptedString);
      expect(decryptedString).toBe(stringToEncrypt);
    });

    it('should decrypt value with salt', () => {
      const stringToEncrypt = 'test-client-id';
      const salt = '92a7f968a5362e469935c340f969e109';

      const encryptedString = encrypt(stringToEncrypt, salt);
      const decryptedString = decrypt(encryptedString, salt);

      expect(decryptedString).toBe(stringToEncrypt);
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
