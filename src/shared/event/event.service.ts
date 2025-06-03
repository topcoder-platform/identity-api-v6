import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BUS_API_CLIENT } from './event.constants';

// Basic interface for the Bus API Client based on observed usage
// Adjust if the actual library provides more specific methods or types
interface BusApiClient {
  postEvent(message: BusEventMessage): Promise<void>;
}

// Interface for the message structure expected by postEvent
interface BusEventMessage {
  topic: string;
  originator: string;
  timestamp: string;
  'mime-type': string;
  payload: any;
  key?: string; // Optional key
}

@Injectable()
export class EventService {
  private readonly logger = new Logger(EventService.name);
  private readonly eventOriginator: string = 'app.identity.service'; // Changed: Hardcode to 'app.identity.service'
  private readonly eventMimeType: string = 'application/json';
  private readonly busEnvelopedNotificationTopic: string =
    'event.notification.send'; // Renamed for clarity

  constructor(
    private readonly configService: ConfigService, // Kept for potential future use, though EVENT_ORIGINATOR is now hardcoded
    @Inject(BUS_API_CLIENT) private readonly busClient: BusApiClient,
  ) {
    this.logger.log(
      `EventService initialized. Originator: '${this.eventOriginator}', Standard Notification Topic: '${this.busEnvelopedNotificationTopic}'`,
    );
  }

  /**
   * Constructs a STANDARD ENVELOPED notification and posts it to the message bus.
   * The Kafka topic is always 'event.notification.send' (this.busEnvelopedNotificationTopic).
   * The 'notificationType' parameter becomes a field within the standard payload envelope.
   *
   * @param notificationType The type of the notification (e.g., 'event.user.created', 'userpasswordreset').
   * @param attributes The actual data/attributes for this notificationType, to be nested in the envelope.
   * @param options Optional parameters, like a partition key.
   * @throws Error if the bus client fails to post the event.
   */
  async postEnvelopedNotification(
    // Renamed from postEvent for clarity
    notificationType: string,
    attributes: any,
    options: { key?: string } = {},
  ): Promise<void> {
    if (!notificationType) {
      this.logger.error(
        'postEnvelopedNotification called without a notificationType.',
      );
      throw new Error('Event notificationType cannot be empty.');
    }

    const finalPayloadEnvelope = {
      notificationType: notificationType,
      ...attributes,
    };

    const message: BusEventMessage = {
      topic: this.busEnvelopedNotificationTopic, // Always use 'event.notification.send'
      originator: this.eventOriginator,
      timestamp: new Date().toISOString(),
      'mime-type': this.eventMimeType,
      payload: finalPayloadEnvelope,
      ...(options.key && { key: options.key }),
    };

    try {
      this.logger.log(
        `Attempting to post ENVELOPED notification (type: ${notificationType}) to bus topic: ${this.busEnvelopedNotificationTopic}`,
      );
      this.logger.log(
        `[DEBUG] Full enveloped message being sent to bus client: ${JSON.stringify(message, null, 2)}`,
      );

      await this.busClient.postEvent(message);
      this.logger.log(
        `Successfully posted ENVELOPED notification (type: ${notificationType}) to bus topic: ${this.busEnvelopedNotificationTopic}${options.key ? ' with key ' + options.key : ''}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to post ENVELOPED notification (type: ${notificationType}) to bus topic ${this.busEnvelopedNotificationTopic}: ${error.message}`,
      );

      // --- Add detailed logging ---
      if (error.response) {
        // Log details if the error object has response information (common in HTTP clients)
        this.logger.error(
          `--> Event Bus Request Error Details: Status: ${error.response.status}, ` +
            `Method: ${error.response.request?.method}, URL: ${error.response.request?.url}`,
        );
        // Avoid logging potentially large or sensitive response bodies unless necessary
        // You could conditionally log error.response.body or error.response.text here
        // this.logger.error(`--> Response Body: ${JSON.stringify(error.response.body)}`);
      } else if (error.request) {
        // Log details if the error object only has request information
        this.logger.error(
          `--> Event Bus Request Error Details: Method: ${error.request?.method}, URL: ${error.request?.url}`,
        );
      } else {
        // Fallback for other types of errors
        this.logger.error(
          '--> No additional request/response details available on the error object.',
        );
      }
      // Add the full stack trace manually for more context if needed
      this.logger.error(`--> Full Error Stack: ${error.stack}`);
      // --- End detailed logging ---

      // Re-throw the error so the caller is aware of the failure
      throw error;
    }
  }

  /**
   * Constructs a DIRECT message with a SPECIFIED TOPIC and payload and posts it to the bus.
   * This method bypasses the standard 'event.notification.send' envelope.
   * Use this for messages that need to adhere to a specific, non-standard topic or payload structure.
   *
   * @param topic The exact Kafka topic to publish to (e.g., 'external.action.email').
   * @param payload The exact payload object for the message.
   * @param options Optional parameters, like a partition key.
   * @throws Error if the bus client fails to post the message.
   */
  async postDirectBusMessage(
    topic: string,
    payload: any,
    options: { key?: string } = {},
  ): Promise<void> {
    if (!topic) {
      this.logger.error('postDirectBusMessage called without a topic.');
      throw new Error('Direct message topic cannot be empty.');
    }
    if (payload === undefined || payload === null) {
      // Allow empty object {} but not undefined/null
      this.logger.error('postDirectBusMessage called without a payload.');
      throw new Error('Direct message payload cannot be undefined or null.');
    }

    const message: BusEventMessage = {
      topic: topic, // Use the explicitly provided topic
      originator: this.eventOriginator,
      timestamp: new Date().toISOString(),
      'mime-type': this.eventMimeType,
      payload: payload, // Use the provided payload directly
      ...(options.key && { key: options.key }),
    };

    try {
      this.logger.log(
        `Attempting to post DIRECT message to bus topic: ${topic}`,
      );
      this.logger.log(
        `[DEBUG] Full direct message being sent to bus client: ${JSON.stringify(message, null, 2)}`,
      );

      await this.busClient.postEvent(message); // Assuming busClient.postEvent is generic enough
      this.logger.log(
        `Successfully posted DIRECT message to bus topic: ${topic}${options.key ? ' with key ' + options.key : ''}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to post DIRECT message to bus topic ${topic}: ${error.message}`,
      );
      // --- Add detailed logging ---
      if (error.response) {
        // Log details if the error object has response information (common in HTTP clients)
        this.logger.error(
          `--> Event Bus Request Error Details: Status: ${error.response.status}, ` +
            `Method: ${error.response.request?.method}, URL: ${error.response.request?.url}`,
        );
        // Avoid logging potentially large or sensitive response bodies unless necessary
        // You could conditionally log error.response.body or error.response.text here
        // this.logger.error(`--> Response Body: ${JSON.stringify(error.response.body)}`);
      } else if (error.request) {
        // Log details if the error object only has request information
        this.logger.error(
          `--> Event Bus Request Error Details: Method: ${error.request?.method}, URL: ${error.request?.url}`,
        );
      } else {
        // Fallback for other types of errors
        this.logger.error(
          '--> No additional request/response details available on the error object.',
        );
      }
      // Add the full stack trace manually for more context if needed
      this.logger.error(`--> Full Error Stack: ${error.stack}`);
      // --- End detailed logging ---

      // Re-throw the error so the caller is aware of the failure
      throw error;
    }
  }

  // --- Example of getting a topic name from config ---
  // You would call this from other services like:
  // await this.eventService.postEvent(this.eventService.getNotificationTopic(), payload);
  /*
  getNotificationTopic(): string {
    const topic = this.configService.get<string>('KAFKA_NOTIFICATIONS_TOPIC');
    if (!topic) {
      this.logger.warn('KAFKA_NOTIFICATIONS_TOPIC is not configured.');
      return 'default.notifications'; // Provide a default or handle error
    }
    return topic;
  }
  */

  // Add other event-related utility methods if needed
}
