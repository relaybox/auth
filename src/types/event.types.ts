export enum EventType {
  DEFAULT_EVENT = 'default:event'
}

export enum DataType {
  STRING = 'String'
}

export enum RoomPrefix {
  TAB = 'tab',
  DOMAIN = 'domain',
  THREAD = 'thread',
  USER = 'user',
  URL = 'url',
  APPLICATION = 'application',
  SYSTEM = 'system'
}

export enum RoomSuffix {
  WATCH = 'watch',
  THREADS = 'threads',
  MESSAGES = 'messages',
  PRIVATE = 'private',
  INDEX = 'index',
  ONLINE = 'online',
  STATUS = 'status',
  GLOBALS = 'globals',
  SESSION = 'session',
  ROOMS = 'rooms',
  ACTIVE = 'active',
  PENDING = 'pending',
  CONNECT = 'connect',
  DISCONNECT = 'disconnect'
}

export interface DispatchGroup {
  eventType: string;
  room: string;
}

export interface SystemEvent {
  appKey: string;
  event: string;
  room: string;
  data: any;
}

export enum ClientEvent {
  AUTH_USER_SUBSCRIBE = 'ds:client:auth:user:subscribe',
  AUTH_USER_UNSUBSCRIBE = 'ds:client:auth:user:unsubscribe',
  AUTH_USER_UNSUBSCRIBE_ALL = 'ds:client:auth:user:unsubscribe:all',
  AUTH_USER_STATUS_UPDATE = 'ds:client:auth:user:status:update'
}
