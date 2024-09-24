import { describe, expect, it } from 'vitest';

describe('/users', () => {
  describe('GET /users/id', () => {
    it('should return a user by id', async () => {
      const response = await fetch('http://localhost:4006/dev/users/id');
      expect(response.status).toBe(401);
    });
  });
});
