import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';
import { EventModule } from './event.module';
import { EventService } from './event.service';
import { BUS_API_CLIENT } from './event.constants';
import busApi from '@topcoder-platform/topcoder-bus-api-wrapper';

// Mock the external bus API
jest.mock('@topcoder-platform/topcoder-bus-api-wrapper');
const mockBusApi = busApi as jest.MockedFunction<typeof busApi>;

describe('EventModule', () => {
  let module: TestingModule;
  let configService: ConfigService;
  let logger: Logger;

  const mockConfig = {
    AUTH0_URL: 'https://auth0.example.com',
    AUTH0_AUDIENCE: 'test-audience',
    TOKEN_CACHE_TIME: '3600',
    AUTH0_CLIENT_ID: 'test-client-id',
    AUTH0_CLIENT_SECRET: 'test-client-secret',
    BUSAPI_URL: 'https://bus-api.example.com',
    KAFKA_ERROR_TOPIC: 'error-topic',
    AUTH0_PROXY_SERVER_URL: 'https://proxy.example.com',
    HTTP_TIMEOUT: 5000,
    HTTP_MAX_REDIRECTS: 5,
  };

  beforeEach(async () => {
    jest.clearAllMocks();
  });

  describe('Bus API Client Provider', () => {
    it('should create bus API client with valid configuration', async () => {
      const mockConfigService = {
        get: jest.fn((key: string, defaultValue?: any) => {
          return mockConfig[key] || defaultValue;
        }),
      };

      const mockBusApiInstance = { publish: jest.fn(), subscribe: jest.fn() };
      mockBusApi.mockReturnValue(mockBusApiInstance);

      module = await Test.createTestingModule({
        imports: [EventModule],
      })
        .overrideProvider(ConfigService)
        .useValue(mockConfigService)
        .compile();

      const busApiClient = module.get(BUS_API_CLIENT);

      expect(busApiClient).toBeDefined();
      expect(mockBusApi).toHaveBeenCalledWith({
        AUTH0_URL: mockConfig.AUTH0_URL,
        AUTH0_AUDIENCE: mockConfig.AUTH0_AUDIENCE,
        TOKEN_CACHE_TIME: mockConfig.TOKEN_CACHE_TIME,
        AUTH0_CLIENT_ID: mockConfig.AUTH0_CLIENT_ID,
        AUTH0_CLIENT_SECRET: mockConfig.AUTH0_CLIENT_SECRET,
        BUSAPI_URL: mockConfig.BUSAPI_URL,
        KAFKA_ERROR_TOPIC: mockConfig.KAFKA_ERROR_TOPIC,
        AUTH0_PROXY_SERVER_URL: mockConfig.AUTH0_PROXY_SERVER_URL,
      });
    });

    it('should log warnings for missing required configuration', async () => {
      const incompleteConfig = {
        ...mockConfig,
        AUTH0_CLIENT_ID: undefined,
        BUSAPI_URL: undefined,
      };

      const mockConfigService = {
        get: jest.fn((key: string, defaultValue?: any) => {
          return incompleteConfig[key] || defaultValue;
        }),
      };

      const loggerWarnSpy = jest
        .spyOn(Logger.prototype, 'warn')
        .mockImplementation();
      const loggerErrorSpy = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation();

      mockBusApi.mockReturnValue({ publish: jest.fn() });

      try {
        module = await Test.createTestingModule({
          imports: [EventModule],
        })
          .overrideProvider(ConfigService)
          .useValue(mockConfigService)
          .compile();

        expect(loggerWarnSpy).toHaveBeenCalledWith(
          'Bus API Client Config Missing/Empty: AUTH0_CLIENT_ID. Check environment variables.',
        );
        expect(loggerWarnSpy).toHaveBeenCalledWith(
          'Bus API Client Config Missing/Empty: BUSAPI_URL. Check environment variables.',
        );
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          'Essential Bus API configuration is missing. Client initialization might fail or be incomplete.',
        );
      } finally {
        loggerWarnSpy.mockRestore();
        loggerErrorSpy.mockRestore();
      }
    });

    it('should log successful initialization', async () => {
      const mockConfigService = {
        get: jest.fn((key: string, defaultValue?: any) => {
          return mockConfig[key] || defaultValue;
        }),
      };

      const loggerLogSpy = jest
        .spyOn(Logger.prototype, 'log')
        .mockImplementation();
      mockBusApi.mockReturnValue({ publish: jest.fn() });

      try {
        module = await Test.createTestingModule({
          imports: [EventModule],
        })
          .overrideProvider(ConfigService)
          .useValue(mockConfigService)
          .compile();

        expect(loggerLogSpy).toHaveBeenCalledWith(
          `Initializing Bus API Client for BUSAPI_URL: ${mockConfig.BUSAPI_URL}`,
        );
      } finally {
        loggerLogSpy.mockRestore();
      }
    });

    it('should handle bus API initialization errors', async () => {
      const mockConfigService = {
        get: jest.fn((key: string, defaultValue?: any) => {
          return mockConfig[key] || defaultValue;
        }),
      };

      const initError = new Error('Bus API initialization failed');
      mockBusApi.mockImplementation(() => {
        throw initError;
      });

      const loggerErrorSpy = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation();

      try {
        await expect(
          Test.createTestingModule({
            imports: [EventModule],
          })
            .overrideProvider(ConfigService)
            .useValue(mockConfigService)
            .compile(),
        ).rejects.toThrow('Bus API initialization failed');

        expect(loggerErrorSpy).toHaveBeenCalledWith(
          `Failed to initialize Bus API Client: ${initError.message}`,
          initError.stack,
        );
      } finally {
        loggerErrorSpy.mockRestore();
      }
    });
  });

  describe('Module Structure', () => {
    it('should be defined and compile successfully', async () => {
      const mockConfigService = {
        get: jest.fn((key: string, defaultValue?: any) => {
          return mockConfig[key] || defaultValue;
        }),
      };

      mockBusApi.mockReturnValue({ publish: jest.fn() });

      module = await Test.createTestingModule({
        imports: [EventModule],
      })
        .overrideProvider(ConfigService)
        .useValue(mockConfigService)
        .compile();

      expect(module).toBeDefined();
    });

    it('should provide EventService', async () => {
      const mockConfigService = {
        get: jest.fn((key: string, defaultValue?: any) => {
          return mockConfig[key] || defaultValue;
        }),
      };

      mockBusApi.mockReturnValue({ publish: jest.fn() });

      module = await Test.createTestingModule({
        imports: [EventModule],
      })
        .overrideProvider(ConfigService)
        .useValue(mockConfigService)
        .compile();

      const eventService = module.get<EventService>(EventService);
      expect(eventService).toBeDefined();
    });

    it('should provide BUS_API_CLIENT', async () => {
      const mockConfigService = {
        get: jest.fn((key: string, defaultValue?: any) => {
          return mockConfig[key] || defaultValue;
        }),
      };

      mockBusApi.mockReturnValue({ publish: jest.fn() });

      module = await Test.createTestingModule({
        imports: [EventModule],
      })
        .overrideProvider(ConfigService)
        .useValue(mockConfigService)
        .compile();

      const busApiClient = module.get(BUS_API_CLIENT);
      expect(busApiClient).toBeDefined();
    });
  });

  describe('HTTP Module Configuration', () => {
    it('should configure HTTP module with correct timeout and redirects', async () => {
      const mockConfigService = {
        get: jest.fn((key: string, defaultValue?: any) => {
          return mockConfig[key] || defaultValue;
        }),
      };

      mockBusApi.mockReturnValue({ publish: jest.fn() });

      module = await Test.createTestingModule({
        imports: [EventModule],
      })
        .overrideProvider(ConfigService)
        .useValue(mockConfigService)
        .compile();

      expect(mockConfigService.get).toHaveBeenCalledWith('HTTP_TIMEOUT', 5000);
      expect(mockConfigService.get).toHaveBeenCalledWith(
        'HTTP_MAX_REDIRECTS',
        5,
      );
    });
  });

  afterEach(async () => {
    if (module) {
      await module.close();
    }
  });
});
