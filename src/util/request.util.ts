import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { Logger } from 'winston';

export enum EventBridgeInputParams {
  KEEP_ALIVE = 'keepAlive'
}

export interface EventBridgeKeepAliveEvent {
  keepAlive: boolean;
}

export function eventBridgeKeepAliveEventHandler(
  logger: Logger,
  event: EventBridgeKeepAliveEvent
): void {
  logger.info(`EventBridge keep alive event received`, { event });
  return;
}

export function lambdaProxyEventMiddleware(logger: Logger, lambdaProxyEventHandler: any) {
  return function (
    event: APIGatewayProxyEvent | EventBridgeKeepAliveEvent,
    context: any
  ): Promise<APIGatewayProxyResult> | void {
    if (EventBridgeInputParams.KEEP_ALIVE in event) {
      return eventBridgeKeepAliveEventHandler(logger, event);
    } else {
      return lambdaProxyEventHandler(event, context);
    }
  };
}
