import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';
import { EventService } from './event.service';
import { BUS_API_CLIENT } from './event.constants';

// Mock interfaces
interface BusApiClient {
  postEvent(message: any): Promise<void>;
}

interface BusEventMessage {
  topic: string;
  originator: string;
  timestamp: string;
  'mime-type': string;
  payload: any;
  key?: string;
}

// Custom error interfaces for testing HTTP client errors
interface HttpError extends Error {
  response?: {
    status: number;
    request?: {
      method: string;
      url: string;
    };
  };
  request?: {
    method: string;
    url: string;
  };
}

describe('EventService', () => {
  let service: EventService;
  let mockBusClient: jest.Mocked<BusApiClient>;
  let mockConfigService: jest.Mocked<ConfigService>;
  let loggerSpy: jest.SpyInstance;

  // Test constants
  const mockTimestamp = '2023-12-01T10:00:00.000Z';
  const expectedOriginator = 'app.identity.service';
  const expectedMimeType = 'application/json';
  const expectedNotificationTopic = 'event.notification.send';

  beforeEach(async () => {
    // Mock Date.prototype.toISOString for consistent timestamps
    jest.spyOn(Date.prototype, 'toISOString').mockReturnValue(mockTimestamp);

    // Spy on logger methods BEFORE creating the service
    loggerSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation();
    jest.spyOn(Logger.prototype, 'error').mockImplementation();
    jest.spyOn(Logger.prototype, 'warn').mockImplementation();

    // Create mock bus client
    mockBusClient = {
      postEvent: jest.fn().mockResolvedValue(undefined),
    };

    // Create mock config service
    mockConfigService = {
      get: jest.fn(),
    } as any;

    // Create testing module
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EventService,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: BUS_API_CLIENT,
          useValue: mockBusClient,
        },
      ],
    }).compile();

    service = module.get<EventService>(EventService);
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  describe('Service Initialization', () => {
    it('should be defined', () => {
      expect(service).toBeDefined();
    });

    it('should initialize with correct configuration', () => {
      expect(loggerSpy).toHaveBeenCalledWith(
        `EventService initialized. Originator: '${expectedOriginator}', Standard Notification Topic: '${expectedNotificationTopic}'`,
      );
    });
  });

  describe('postEnvelopedNotification', () => {
    const validNotificationType = 'event.user.created';
    const validAttributes = { userId: '123', email: 'test@example.com' };

    describe('Success Cases', () => {
      it('should post enveloped notification successfully with basic parameters', async () => {
        await service.postEnvelopedNotification(
          validNotificationType,
          validAttributes,
        );

        const expectedMessage: BusEventMessage = {
          topic: expectedNotificationTopic,
          originator: expectedOriginator,
          timestamp: mockTimestamp,
          'mime-type': expectedMimeType,
          payload: {
            notificationType: validNotificationType,
            ...validAttributes,
          },
        };

        expect(mockBusClient.postEvent).toHaveBeenCalledTimes(1);
        expect(mockBusClient.postEvent).toHaveBeenCalledWith(expectedMessage);
      });

      it('should post enveloped notification with partition key', async () => {
        const options = { key: 'partition-key-123' };

        await service.postEnvelopedNotification(
          validNotificationType,
          validAttributes,
          options,
        );

        const expectedMessage: BusEventMessage = {
          topic: expectedNotificationTopic,
          originator: expectedOriginator,
          timestamp: mockTimestamp,
          'mime-type': expectedMimeType,
          payload: {
            notificationType: validNotificationType,
            ...validAttributes,
          },
          key: options.key,
        };

        expect(mockBusClient.postEvent).toHaveBeenCalledWith(expectedMessage);
      });

      it('should handle empty attributes object', async () => {
        await service.postEnvelopedNotification(validNotificationType, {});

        const expectedPayload = {
          notificationType: validNotificationType,
        };

        expect(mockBusClient.postEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            payload: expectedPayload,
          }),
        );
      });

      it('should handle null attributes', async () => {
        await service.postEnvelopedNotification(validNotificationType, null);

        const expectedPayload = {
          notificationType: validNotificationType,
        };

        expect(mockBusClient.postEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            payload: expectedPayload,
          }),
        );
      });

      it('should log success messages correctly', async () => {
        const loggerLogSpy = jest.spyOn(Logger.prototype, 'log');

        await service.postEnvelopedNotification(
          validNotificationType,
          validAttributes,
        );

        expect(loggerLogSpy).toHaveBeenCalledWith(
          `Attempting to post ENVELOPED notification (type: ${validNotificationType}) to bus topic: ${expectedNotificationTopic}`,
        );
        expect(loggerLogSpy).toHaveBeenCalledWith(
          `Successfully posted ENVELOPED notification (type: ${validNotificationType}) to bus topic: ${expectedNotificationTopic}`,
        );
      });

      it('should log success with partition key', async () => {
        const loggerLogSpy = jest.spyOn(Logger.prototype, 'log');
        const options = { key: 'test-key' };

        await service.postEnvelopedNotification(
          validNotificationType,
          validAttributes,
          options,
        );

        expect(loggerLogSpy).toHaveBeenCalledWith(
          `Successfully posted ENVELOPED notification (type: ${validNotificationType}) to bus topic: ${expectedNotificationTopic} with key ${options.key}`,
        );
      });
    });

    describe('Validation Cases', () => {
      it('should throw error when notificationType is empty string', async () => {
        await expect(
          service.postEnvelopedNotification('', validAttributes),
        ).rejects.toThrow('Event notificationType cannot be empty.');
      });

      it('should throw error when notificationType is null', async () => {
        await expect(
          service.postEnvelopedNotification(null as any, validAttributes),
        ).rejects.toThrow('Event notificationType cannot be empty.');
      });

      it('should throw error when notificationType is undefined', async () => {
        await expect(
          service.postEnvelopedNotification(undefined as any, validAttributes),
        ).rejects.toThrow('Event notificationType cannot be empty.');
      });

      it('should log error when notificationType is invalid', async () => {
        const loggerErrorSpy = jest.spyOn(Logger.prototype, 'error');

        await expect(
          service.postEnvelopedNotification('', validAttributes),
        ).rejects.toThrow();

        expect(loggerErrorSpy).toHaveBeenCalledWith(
          'postEnvelopedNotification called without a notificationType.',
        );
      });
    });

    describe('Error Handling', () => {
      it('should handle bus client error with response details', async () => {
        const mockError: HttpError = Object.assign(
          new Error('Request failed'),
          {
            response: {
              status: 500,
              request: {
                method: 'POST',
                url: 'http://bus-api/events',
              },
            },
          },
        );

        mockBusClient.postEvent.mockRejectedValue(mockError);

        await expect(
          service.postEnvelopedNotification(
            validNotificationType,
            validAttributes,
          ),
        ).rejects.toThrow(mockError);

        const loggerErrorSpy = jest.spyOn(Logger.prototype, 'error');
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          `Failed to post ENVELOPED notification (type: ${validNotificationType}) to bus topic ${expectedNotificationTopic}: ${mockError.message}`,
        );
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          `--> Event Bus Request Error Details: Status: ${mockError.response.status}, Method: ${mockError.response.request.method}, URL: ${mockError.response.request.url}`,
        );
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          `--> Full Error Stack: ${mockError.stack}`,
        );
      });

      it('should handle bus client error with request details only', async () => {
        const mockError: HttpError = Object.assign(new Error('Network error'), {
          request: {
            method: 'POST',
            url: 'http://bus-api/events',
          },
        });

        mockBusClient.postEvent.mockRejectedValue(mockError);

        await expect(
          service.postEnvelopedNotification(
            validNotificationType,
            validAttributes,
          ),
        ).rejects.toThrow(mockError);

        const loggerErrorSpy = jest.spyOn(Logger.prototype, 'error');
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          `--> Event Bus Request Error Details: Method: ${mockError.request.method}, URL: ${mockError.request.url}`,
        );
      });

      it('should handle generic error without request/response details', async () => {
        const mockError = new Error('Generic error');

        mockBusClient.postEvent.mockRejectedValue(mockError);

        await expect(
          service.postEnvelopedNotification(
            validNotificationType,
            validAttributes,
          ),
        ).rejects.toThrow(mockError);

        const loggerErrorSpy = jest.spyOn(Logger.prototype, 'error');
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          '--> No additional request/response details available on the error object.',
        );
      });
    });
  });

  describe('postDirectBusMessage', () => {
    const validTopic = 'external.action.email';
    const validPayload = { recipient: 'test@example.com', subject: 'Test' };

    describe('Success Cases', () => {
      it('should post direct message successfully', async () => {
        await service.postDirectBusMessage(validTopic, validPayload);

        const expectedMessage: BusEventMessage = {
          topic: validTopic,
          originator: expectedOriginator,
          timestamp: mockTimestamp,
          'mime-type': expectedMimeType,
          payload: validPayload,
        };

        expect(mockBusClient.postEvent).toHaveBeenCalledWith(expectedMessage);
      });

      it('should post direct message with partition key', async () => {
        const options = { key: 'direct-key-456' };

        await service.postDirectBusMessage(validTopic, validPayload, options);

        const expectedMessage: BusEventMessage = {
          topic: validTopic,
          originator: expectedOriginator,
          timestamp: mockTimestamp,
          'mime-type': expectedMimeType,
          payload: validPayload,
          key: options.key,
        };

        expect(mockBusClient.postEvent).toHaveBeenCalledWith(expectedMessage);
      });

      it('should handle empty object payload', async () => {
        await service.postDirectBusMessage(validTopic, {});
        expect(mockBusClient.postEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            payload: {},
          }),
        );
      });

      it('should log success messages correctly', async () => {
        const loggerLogSpy = jest.spyOn(Logger.prototype, 'log');

        await service.postDirectBusMessage(validTopic, validPayload);

        expect(loggerLogSpy).toHaveBeenCalledWith(
          `Attempting to post DIRECT message to bus topic: ${validTopic}`,
        );
        expect(loggerLogSpy).toHaveBeenCalledWith(
          `Successfully posted DIRECT message to bus topic: ${validTopic}`,
        );
      });
    });

    describe('Validation Cases', () => {
      it('should throw error when topic is empty string', async () => {
        await expect(
          service.postDirectBusMessage('', validPayload),
        ).rejects.toThrow('Direct message topic cannot be empty.');
      });

      it('should throw error when topic is null', async () => {
        await expect(
          service.postDirectBusMessage(null as any, validPayload),
        ).rejects.toThrow('Direct message topic cannot be empty.');
      });

      it('should throw error when payload is null', async () => {
        await expect(
          service.postDirectBusMessage(validTopic, null),
        ).rejects.toThrow(
          'Direct message payload cannot be undefined or null.',
        );
      });

      it('should throw error when payload is undefined', async () => {
        await expect(
          service.postDirectBusMessage(validTopic, undefined),
        ).rejects.toThrow(
          'Direct message payload cannot be undefined or null.',
        );
      });

      it('should log validation errors', async () => {
        const loggerErrorSpy = jest.spyOn(Logger.prototype, 'error');

        await expect(
          service.postDirectBusMessage('', validPayload),
        ).rejects.toThrow();

        expect(loggerErrorSpy).toHaveBeenCalledWith(
          'postDirectBusMessage called without a topic.',
        );
      });
    });

    describe('Error Handling', () => {
      it('should handle and re-throw bus client errors', async () => {
        const mockError = new Error('Bus client failure');
        mockBusClient.postEvent.mockRejectedValue(mockError);

        await expect(
          service.postDirectBusMessage(validTopic, validPayload),
        ).rejects.toThrow(mockError);

        const loggerErrorSpy = jest.spyOn(Logger.prototype, 'error');
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          `Failed to post DIRECT message to bus topic ${validTopic}: ${mockError.message}`,
        );
      });

      it('should handle bus client error with response details for direct messages', async () => {
        const mockError: HttpError = Object.assign(
          new Error('Request failed'),
          {
            response: {
              status: 400,
              request: {
                method: 'POST',
                url: 'http://bus-api/direct',
              },
            },
          },
        );

        mockBusClient.postEvent.mockRejectedValue(mockError);

        await expect(
          service.postDirectBusMessage(validTopic, validPayload),
        ).rejects.toThrow(mockError);

        const loggerErrorSpy = jest.spyOn(Logger.prototype, 'error');
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          `--> Event Bus Request Error Details: Status: ${mockError.response.status}, Method: ${mockError.response.request.method}, URL: ${mockError.response.request.url}`,
        );
      });
    });
  });

  describe('Message Structure', () => {
    it('should create messages with consistent structure for enveloped notifications', async () => {
      const notificationType = 'test.notification';
      const attributes = { data: 'test' };

      await service.postEnvelopedNotification(notificationType, attributes);

      const calledMessage = mockBusClient.postEvent.mock.calls[0][0];

      expect(calledMessage).toHaveProperty('topic');
      expect(calledMessage).toHaveProperty('originator');
      expect(calledMessage).toHaveProperty('timestamp');
      expect(calledMessage).toHaveProperty('mime-type');
      expect(calledMessage).toHaveProperty('payload');
      expect(typeof calledMessage.timestamp).toBe('string');
      expect(calledMessage.originator).toBe(expectedOriginator);
      expect(calledMessage['mime-type']).toBe(expectedMimeType);
    });

    it('should create messages with consistent structure for direct messages', async () => {
      const topic = 'test.topic';
      const payload = { data: 'test' };

      await service.postDirectBusMessage(topic, payload);

      const calledMessage = mockBusClient.postEvent.mock.calls[0][0];

      expect(calledMessage).toHaveProperty('topic');
      expect(calledMessage).toHaveProperty('originator');
      expect(calledMessage).toHaveProperty('timestamp');
      expect(calledMessage).toHaveProperty('mime-type');
      expect(calledMessage).toHaveProperty('payload');
      expect(calledMessage.topic).toBe(topic);
      expect(calledMessage.payload).toEqual(payload);
    });
  });

  describe('Edge Cases', () => {
    it('should handle special characters in notification type', async () => {
      const specialNotificationType = 'event.user-created_v2.test@domain';
      const attributes = { test: true };

      await service.postEnvelopedNotification(
        specialNotificationType,
        attributes,
      );
      expect(mockBusClient.postEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          payload: expect.objectContaining({
            notificationType: specialNotificationType,
          }),
        }),
      );
    });

    it('should handle large payload objects', async () => {
      const largePayload = {
        data: 'x'.repeat(1000),
        nested: {
          array: new Array(100).fill('test'),
          object: Object.fromEntries(
            Array.from({ length: 50 }, (_, i) => [`key${i}`, `value${i}`]),
          ),
        },
      };

      await service.postDirectBusMessage('test.topic', largePayload);
      expect(mockBusClient.postEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          payload: largePayload,
        }),
      );
    });

    it('should handle concurrent calls', async () => {
      const promises = Array.from({ length: 5 }, (_, i) =>
        service.postEnvelopedNotification(`event.test.${i}`, { index: i }),
      );

      await Promise.all(promises);
      expect(mockBusClient.postEvent).toHaveBeenCalledTimes(5);
    });
  });
});

// Additional test utilities for integration testing
export const createMockEventService = () => {
  const mockService = {
    postEnvelopedNotification: jest.fn().mockResolvedValue(undefined),
    postDirectBusMessage: jest.fn().mockResolvedValue(undefined),
  };
  return mockService;
};

// Test data factory for consistent test data creation
export const createTestEventData = {
  notification: (overrides = {}) => ({
    notificationType: 'test.notification',
    attributes: { userId: '123', action: 'created' },
    options: {},
    ...overrides,
  }),

  directMessage: (overrides = {}) => ({
    topic: 'test.topic',
    payload: { message: 'test payload' },
    options: {},
    ...overrides,
  }),

  busMessage: (overrides = {}): BusEventMessage => ({
    topic: 'test.topic',
    originator: 'app.identity.service',
    timestamp: '2023-12-01T10:00:00.000Z',
    'mime-type': 'application/json',
    payload: {},
    ...overrides,
  }),
};
