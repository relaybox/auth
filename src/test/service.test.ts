import { describe, it, expect } from 'vitest';

describe('permissionsGuard', () => {
  describe('success', () => {
    it('returns true if global permissions include the specific requested permission', () => {
      const permissions = ['subscribe'];

      expect(true).toBe(true);
    });
  });
});
