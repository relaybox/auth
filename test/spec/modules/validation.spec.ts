import {
  mockGlobalPermissions,
  mockInlinePermissions,
  mockOverridePermissions,
  mockOverridePermissionsMultiRoom,
  mockRoomInlinePattern,
  mockRoomPatternOne,
  mockRoomPatternTwo
} from 'test/__mocks__/internal/validation.spec.mock';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getPermissions } from '@/modules/validation/validation.service';
import PgClient from 'serverless-postgres';
import { getLogger } from '@/util/logger.util';

const logger = getLogger('validation-service');

const mockKeyId = 'test-key-id';

const mockRepository = vi.hoisted(() => ({
  getPermissionsByKeyId: vi.fn()
}));

vi.mock('@/modules/validation/validation.repository', () => mockRepository);

describe('validation.service', () => {
  let mockPgClient = {} as PgClient;

  afterEach(() => {
    vi.clearAllMocks();
    vi.resetAllMocks();
  });

  describe('getPermissions', () => {
    it('should return an array of global permissions when inline permissions are not provided', async () => {
      mockRepository.getPermissionsByKeyId.mockResolvedValueOnce(mockGlobalPermissions);

      const inlinePermissions = {};

      const permissions = await getPermissions(logger, mockPgClient, mockKeyId, inlinePermissions);

      expect(permissions).toEqual(['subscribe', 'publish']);
    });

    it('should return a map of room scoped permissions when a single room override is provided', async () => {
      mockRepository.getPermissionsByKeyId.mockResolvedValueOnce(mockOverridePermissions);

      const inlinePermissions = {};

      const permissions = await getPermissions(logger, mockPgClient, mockKeyId, inlinePermissions);

      expect(permissions).toEqual({
        [mockRoomPatternOne]: ['subscribe', 'publish']
      });
    });

    it('should return a map of room scoped permissions when multiple room overrides are provided', async () => {
      mockRepository.getPermissionsByKeyId.mockResolvedValueOnce(mockOverridePermissionsMultiRoom);

      const inlinePermissions = {};

      const permissions = await getPermissions(logger, mockPgClient, mockKeyId, inlinePermissions);

      expect(permissions).toEqual({
        [mockRoomPatternOne]: ['subscribe', 'publish'],
        [mockRoomPatternTwo]: ['subscribe', 'publish']
      });
    });

    it('should return a map of inline permissions when inline permissions are provided', async () => {
      mockRepository.getPermissionsByKeyId.mockResolvedValueOnce(mockGlobalPermissions);

      const permissions = await getPermissions(
        logger,
        mockPgClient,
        mockKeyId,
        mockInlinePermissions
      );

      expect(permissions).toEqual({
        [mockRoomInlinePattern]: ['subscribe', 'publish']
      });
    });
  });
});
