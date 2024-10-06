export const mockRoomPatternOne = 'one:two:*';
export const mockRoomPatternTwo = 'three:four:*';
export const mockRoomInlinePattern = 'inline:*';

export const mockInlinePermissions = { [mockRoomInlinePattern]: ['subscribe', 'publish'] };

export const mockOverridePermissions = {
  rows: [
    { permission: 'subscribe', pattern: mockRoomPatternOne },
    { permission: 'publish', pattern: mockRoomPatternOne }
  ]
};

export const mockOverridePermissionsMultiRoom = {
  rows: [
    { permission: 'subscribe', pattern: mockRoomPatternOne },
    { permission: 'subscribe', pattern: mockRoomPatternTwo },
    { permission: 'publish', pattern: mockRoomPatternOne },
    { permission: 'publish', pattern: mockRoomPatternTwo }
  ]
};

export const mockGlobalPermissions = {
  rows: [
    { permission: 'subscribe', pattern: null },
    { permission: 'publish', pattern: null }
  ]
};
