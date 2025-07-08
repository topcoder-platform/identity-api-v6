import { Test, TestingModule } from '@nestjs/testing';
import {
  AuthDataStore,
  InMemoryDataStore,
  RedisDataStore,
} from './auth-data-store.service';
import { ConfigurationService } from '../../config/configuration.service';
import { AuthorizationResponse } from '../../dto/authorization/authorization.dto';

jest.mock('ioredis', () => {
  return jest.fn().mockImplementation(() => ({
    // Mock Redis methods you use
    get: jest.fn(),
    set: jest.fn(),
    on: jest.fn(),
    // Add other methods you need
    disconnect: jest.fn(),
    // You can chain mock implementations if needed
  }));
});

import Redis from 'ioredis';

jest.mock('../../shared/util/common.utils', () => ({
  CommonUtils: {
    parseJWTClaims: jest.fn().mockImplementation(() => {
      // Your mock implementation
      return { userId: 123456 };
    }),
  },
}));

describe('AuthDataStore', () => {
  let service: AuthDataStore;
  let mockConfigService: Partial<ConfigurationService>;

  const mockAuthResponse: AuthorizationResponse = {
    token: 'test-token',
    target: 'test-target',
  };

  describe('with InMemoryDataStore', () => {
    beforeEach(async () => {
      mockConfigService = {
        getAuthStore: jest.fn().mockReturnValue({ type: 'memory' }),
      };

      const module: TestingModule = await Test.createTestingModule({
        providers: [
          AuthDataStore,
          { provide: ConfigurationService, useValue: mockConfigService },
        ],
      }).compile();

      service = module.get<AuthDataStore>(AuthDataStore);
    });

    it('should initialize with InMemoryDataStore', () => {
      expect(service['store']).toBeInstanceOf(InMemoryDataStore);
    });

    it('should store and retrieve authorization data', async () => {
      await service.put(mockAuthResponse);
      const result = await service.get(
        mockAuthResponse.token,
        mockAuthResponse.target,
      );
      expect(result).toEqual(mockAuthResponse);
    });

    it('should delete authorization data', async () => {
      await service.put(mockAuthResponse);
      await service.delete(mockAuthResponse.token, mockAuthResponse.target);
      const result = await service.get(
        mockAuthResponse.token,
        mockAuthResponse.target,
      );
      expect(result).toBeUndefined();
    });

    it('should handle null auth data in put', async () => {
      await expect(service.put(null)).resolves.not.toThrow();
    });

    it('should return null for empty token in get', async () => {
      const result = await service.get('', 'test-target');
      expect(result).toBeNull();
    });

    it('should handle empty token in delete', async () => {
      await expect(service.delete('', 'test-target')).resolves.not.toThrow();
    });
  });

  describe('with RedisDataStore', () => {
    let mockRedisClient: Partial<Redis>;

    beforeEach(async () => {
      mockRedisClient = {
        ping: jest.fn().mockResolvedValue('PONG'),
        setex: jest.fn().mockResolvedValue('OK'),
        get: jest.fn().mockResolvedValue(JSON.stringify(mockAuthResponse)),
        del: jest.fn().mockResolvedValue(1),
      };
      (Redis as unknown as jest.Mock).mockImplementation(() => mockRedisClient);

      mockConfigService = {
        getAuthStore: jest.fn().mockReturnValue({
          type: 'redis',
          spec: {
            host: 'localhost',
            port: 6379,
            expirySeconds: 3600,
          },
        }),
      };

      const module: TestingModule = await Test.createTestingModule({
        providers: [
          AuthDataStore,
          { provide: ConfigurationService, useValue: mockConfigService },
        ],
      }).compile();

      service = module.get<AuthDataStore>(AuthDataStore);
    });

    it('should initialize with RedisDataStore', () => {
      expect(service['store']).toBeInstanceOf(RedisDataStore);
    });

    it('should store and retrieve authorization data', async () => {
      await service.put(mockAuthResponse);
      const result = await service.get(
        mockAuthResponse.token,
        mockAuthResponse.target,
      );
      expect(result).toEqual(mockAuthResponse);
      expect(mockRedisClient.setex).toHaveBeenCalled();
      expect(mockRedisClient.get).toHaveBeenCalled();
    });

    it('should delete authorization data', async () => {
      await service.delete(mockAuthResponse.token, mockAuthResponse.target);
      expect(mockRedisClient.del).toHaveBeenCalled();
    });

    it('should handle connection errors', async () => {
      // Simulate connection failure
      (mockRedisClient.ping as jest.Mock).mockRejectedValue(
        new Error('Connection failed'),
      );

      // Need to create new instance since connection is established in constructor
      const failingConfigService = {
        getAuthStore: jest.fn().mockReturnValue({
          type: 'redis',
          spec: {
            host: 'localhost',
            port: 6379,
            expirySeconds: 3600,
          },
        }),
      };

      const failingModule: TestingModule = await Test.createTestingModule({
        providers: [
          AuthDataStore,
          { provide: ConfigurationService, useValue: failingConfigService },
        ],
      }).compile();

      const failingService = failingModule.get<AuthDataStore>(AuthDataStore);

      // Verify that operations fail with connection error
      await expect(failingService.put(mockAuthResponse)).rejects.toThrow();
      await expect(failingService.get('token', 'target')).rejects.toThrow();
      await expect(failingService.delete('token', 'target')).rejects.toThrow();
    });

    it('should handle null auth data in put', async () => {
      await service.put(null);
      expect(mockRedisClient.setex).not.toHaveBeenCalled();
    });

    it('should return null for empty token in get', async () => {
      const result = await service.get('', 'test-target');
      expect(result).toBeNull();
      expect(mockRedisClient.get).not.toHaveBeenCalled();
    });

    it('should handle empty token in delete', async () => {
      await service.delete('', 'test-target');
      expect(mockRedisClient.del).not.toHaveBeenCalled();
    });
  });

  describe('store switching', () => {
    it('should dynamically switch between store implementations based on config', async () => {
      // First test with memory store
      mockConfigService = {
        getAuthStore: jest.fn().mockReturnValue({ type: 'memory' }),
      };

      const memoryModule: TestingModule = await Test.createTestingModule({
        providers: [
          AuthDataStore,
          { provide: ConfigurationService, useValue: mockConfigService },
        ],
      }).compile();

      const memoryService = memoryModule.get<AuthDataStore>(AuthDataStore);
      expect(memoryService['store']).toBeInstanceOf(InMemoryDataStore);

      // Then test with redis store
      mockConfigService.getAuthStore = jest.fn().mockReturnValue({
        type: 'redis',
        spec: {
          host: 'localhost',
          port: 6379,
          expirySeconds: 3600,
        },
      });

      const redisModule: TestingModule = await Test.createTestingModule({
        providers: [
          AuthDataStore,
          { provide: ConfigurationService, useValue: mockConfigService },
        ],
      }).compile();

      const redisService = redisModule.get<AuthDataStore>(AuthDataStore);
      expect(redisService['store']).toBeInstanceOf(RedisDataStore);
    });
  });
});
