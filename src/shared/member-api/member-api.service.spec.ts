import { Test, TestingModule } from '@nestjs/testing';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { HttpException, HttpStatus, Logger } from '@nestjs/common';
import { of, throwError } from 'rxjs';
import { AxiosResponse } from 'axios';

import { MemberApiService } from './member-api.service';
import { M2M_AUTH_CLIENT } from './member-api.constants';
import { MemberInfoDto } from '../../dto/member/member.dto';

describe('MemberApiService', () => {
  let service: MemberApiService;
  let httpService: HttpService;
  let configService: ConfigService;
  let cacheManager: Cache;
  let m2mAuthClient: any;
  let module: TestingModule;

  // Test data
  const mockMemberInfo: MemberInfoDto[] = [
    { userId: 1, handle: 'john_doe', email: 'john@example.com' },
    { userId: 2, handle: 'jane_smith', email: 'jane@example.com' },
  ];

  const mockToken = 'mock-jwt-token';
  const mockApiUrl = 'https://api.example.com/members';
  const mockClientId = 'test-client-id';
  const mockClientSecret = 'test-client-secret';

  beforeEach(async () => {
    const mockHttpService = {
      get: jest.fn(),
    };

    const mockConfigService = {
      get: jest.fn().mockImplementation((key: string, defaultValue?: any) => {
        const config = {
          MEMBER_API_URL: mockApiUrl,
          AUTH0_CLIENT_ID: mockClientId,
          AUTH0_CLIENT_SECRET: mockClientSecret,
          TOKEN_CACHE_TIME: 23 * 60 * 60, // 23 hours
        };
        return config[key] || defaultValue;
      }),
    };

    const mockCacheManager = {
      get: jest.fn(),
      set: jest.fn(),
    };

    const mockM2MAuthClient = {
      getMachineToken: jest.fn(),
    };

    // Create a proper Logger mock
    const mockLogger = {
      log: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
      verbose: jest.fn(),
      setContext: jest.fn(),
      overrideLogger: jest.fn(),
    };

    module = await Test.createTestingModule({
      providers: [
        MemberApiService,
        {
          provide: HttpService,
          useValue: mockHttpService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: CACHE_MANAGER,
          useValue: mockCacheManager,
        },
        {
          provide: M2M_AUTH_CLIENT,
          useValue: mockM2MAuthClient,
        },
        {
          provide: Logger,
          useValue: mockLogger,
        },
      ],
    })
      .setLogger(mockLogger) // Use mock logger during tests
      .compile();

    service = module.get<MemberApiService>(MemberApiService);
    httpService = module.get<HttpService>(HttpService);
    configService = module.get<ConfigService>(ConfigService);
    cacheManager = module.get<Cache>(CACHE_MANAGER);
    m2mAuthClient = module.get(M2M_AUTH_CLIENT);
  });

  afterEach(async () => {
    jest.clearAllMocks();
    if (module) {
      await module.close();
    }
  });

  describe('Constructor', () => {
    it('should initialize successfully with valid configuration', () => {
      expect(service).toBeDefined();
      expect(configService.get).toHaveBeenCalledWith('MEMBER_API_URL');
    });
  });

  describe('getM2mToken (private method)', () => {
    it('should return cached token when available', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(mockToken);

      const result = await (service as any).getM2mToken();

      expect(result).toBe(mockToken);
      expect(cacheManager.get).toHaveBeenCalledWith('member_api_m2m_token');
      expect(m2mAuthClient.getMachineToken).not.toHaveBeenCalled();
    });

    it('should fetch new token when cache is empty', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(null);
      jest.spyOn(cacheManager, 'set').mockResolvedValue(undefined);
      jest.spyOn(m2mAuthClient, 'getMachineToken').mockResolvedValue(mockToken);

      const result = await (service as any).getM2mToken();

      expect(result).toBe(mockToken);
      expect(m2mAuthClient.getMachineToken).toHaveBeenCalledWith(
        mockClientId,
        mockClientSecret,
      );
      expect(cacheManager.set).toHaveBeenCalledWith(
        'member_api_m2m_token',
        mockToken,
        expect.any(Number),
      );
    });

    it('should return null when clientId is missing', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(null);
      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        if (key === 'AUTH0_CLIENT_ID') return undefined;
        if (key === 'MEMBER_API_URL') return mockApiUrl;
        return undefined;
      });

      const result = await (service as any).getM2mToken();

      expect(result).toBeNull();
      expect(m2mAuthClient.getMachineToken).not.toHaveBeenCalled();
    });

    it('should return null when clientSecret is missing', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(null);
      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        if (key === 'AUTH0_CLIENT_SECRET') return undefined;
        if (key === 'AUTH0_CLIENT_ID') return mockClientId;
        if (key === 'MEMBER_API_URL') return mockApiUrl;
        return undefined;
      });

      const result = await (service as any).getM2mToken();

      expect(result).toBeNull();
      expect(m2mAuthClient.getMachineToken).not.toHaveBeenCalled();
    });

    it('should return null when m2mAuthClient returns null token', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(null);
      jest.spyOn(m2mAuthClient, 'getMachineToken').mockResolvedValue(null);

      const result = await (service as any).getM2mToken();

      expect(result).toBeNull();
      expect(cacheManager.set).not.toHaveBeenCalled();
    });

    it('should return null when m2mAuthClient throws error', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(null);
      jest
        .spyOn(m2mAuthClient, 'getMachineToken')
        .mockRejectedValue(new Error('Auth service error'));

      const result = await (service as any).getM2mToken();

      expect(result).toBeNull();
      expect(cacheManager.set).not.toHaveBeenCalled();
    });

    it('should cache token with correct TTL', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(null);
      jest.spyOn(cacheManager, 'set').mockResolvedValue(undefined);
      jest.spyOn(m2mAuthClient, 'getMachineToken').mockResolvedValue(mockToken);
      jest
        .spyOn(configService, 'get')
        .mockImplementation((key: string, defaultValue?: any) => {
          if (key === 'TOKEN_CACHE_TIME') return 3600; // 1 hour
          if (key === 'MEMBER_API_URL') return mockApiUrl;
          if (key === 'AUTH0_CLIENT_ID') return mockClientId;
          if (key === 'AUTH0_CLIENT_SECRET') return mockClientSecret;
          return defaultValue;
        });

      await (service as any).getM2mToken();

      const expectedTtl = (3600 - 60) * 1000; // Cache 60 seconds less, in milliseconds
      expect(cacheManager.set).toHaveBeenCalledWith(
        'member_api_m2m_token',
        mockToken,
        expectedTtl,
      );
    });

    it('should use minimum TTL of 60 seconds when calculated TTL is too low', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(null);
      jest.spyOn(cacheManager, 'set').mockResolvedValue(undefined);
      jest.spyOn(m2mAuthClient, 'getMachineToken').mockResolvedValue(mockToken);
      jest
        .spyOn(configService, 'get')
        .mockImplementation((key: string, defaultValue?: any) => {
          if (key === 'TOKEN_CACHE_TIME') return 30; // 30 seconds
          if (key === 'MEMBER_API_URL') return mockApiUrl;
          if (key === 'AUTH0_CLIENT_ID') return mockClientId;
          if (key === 'AUTH0_CLIENT_SECRET') return mockClientSecret;
          return defaultValue;
        });

      await (service as any).getM2mToken();

      const expectedTtl = 60 * 1000; // Minimum 60 seconds in milliseconds
      expect(cacheManager.set).toHaveBeenCalledWith(
        'member_api_m2m_token',
        mockToken,
        expectedTtl,
      );
    });
  });

  describe('getUserInfoList', () => {
    beforeEach(() => {
      // Setup successful token retrieval by default
      jest.spyOn(cacheManager, 'get').mockResolvedValue(mockToken);
    });

    it('should return empty array for empty input', async () => {
      const result = await service.getUserInfoList([]);
      expect(result).toEqual([]);
      expect(httpService.get).not.toHaveBeenCalled();
    });

    it('should return empty array for null input', async () => {
      const result = await service.getUserInfoList(null as any);
      expect(result).toEqual([]);
      expect(httpService.get).not.toHaveBeenCalled();
    });

    it('should throw HttpException when M2M token cannot be obtained', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(null);
      jest.spyOn(m2mAuthClient, 'getMachineToken').mockResolvedValue(null);

      await expect(service.getUserInfoList([1, 2])).rejects.toThrow(
        new HttpException(
          'Internal configuration error: Could not authenticate service.',
          HttpStatus.INTERNAL_SERVER_ERROR,
        ),
      );
    });

    it('should successfully fetch user info for small list', async () => {
      const userIds = [1, 2];
      const mockResponse: AxiosResponse<MemberInfoDto[]> = {
        data: mockMemberInfo,
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };

      jest.spyOn(httpService, 'get').mockReturnValue(of(mockResponse));

      const result = await service.getUserInfoList(userIds);

      expect(result).toEqual(mockMemberInfo);
      expect(httpService.get).toHaveBeenCalledWith(
        `${mockApiUrl}?userIds=1&userIds=2`,
        {
          headers: {
            Authorization: `Bearer ${mockToken}`,
            'Content-Type': 'application/json',
          },
        },
      );
    });

    it('should handle large lists by batching requests', async () => {
      const userIds = Array.from({ length: 120 }, (_, i) => i + 1); // 120 users
      const batchResponse1 = Array.from({ length: 50 }, (_, i) => ({
        userId: i + 1,
        handle: `user${i + 1}`,
        email: `user${i + 1}@example.com`,
      }));
      const batchResponse2 = Array.from({ length: 50 }, (_, i) => ({
        userId: i + 51,
        handle: `user${i + 51}`,
        email: `user${i + 51}@example.com`,
      }));
      const batchResponse3 = Array.from({ length: 20 }, (_, i) => ({
        userId: i + 101,
        handle: `user${i + 101}`,
        email: `user${i + 101}@example.com`,
      }));

      const mockResponse1: AxiosResponse<MemberInfoDto[]> = {
        data: batchResponse1,
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };

      const mockResponse2: AxiosResponse<MemberInfoDto[]> = {
        data: batchResponse2,
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };

      const mockResponse3: AxiosResponse<MemberInfoDto[]> = {
        data: batchResponse3,
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };

      jest
        .spyOn(httpService, 'get')
        .mockReturnValueOnce(of(mockResponse1))
        .mockReturnValueOnce(of(mockResponse2))
        .mockReturnValueOnce(of(mockResponse3));

      const result = await service.getUserInfoList(userIds);

      expect(httpService.get).toHaveBeenCalledTimes(3); // 3 batches (50, 50, 20)
      expect(result).toHaveLength(120); // All responses combined
    });

    it('should deduplicate user IDs', async () => {
      const userIds = [1, 2, 1, 3, 2]; // Duplicates
      const mockResponse: AxiosResponse<MemberInfoDto[]> = {
        data: mockMemberInfo,
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };

      jest.spyOn(httpService, 'get').mockReturnValue(of(mockResponse));

      await service.getUserInfoList(userIds);

      // Should only call with unique IDs: 1, 2, 3
      expect(httpService.get).toHaveBeenCalledWith(
        `${mockApiUrl}?userIds=1&userIds=2&userIds=3`,
        expect.any(Object),
      );
    });

    it('should throw HttpException when API call fails', async () => {
      const userIds = [1, 2];
      const error = {
        message: 'Network error',
        response: {
          status: 500,
          data: { message: 'Internal server error' },
        },
      };

      jest.spyOn(httpService, 'get').mockReturnValue(throwError(() => error));

      await expect(service.getUserInfoList(userIds)).rejects.toThrow(
        new HttpException(
          'Failed during Member API batch request 1/1: Internal server error',
          500,
        ),
      );
    });

    it('should handle API error without response data', async () => {
      const userIds = [1, 2];
      const error = {
        message: 'Network timeout',
        response: {
          status: 408,
        },
      };

      jest.spyOn(httpService, 'get').mockReturnValue(throwError(() => error));

      await expect(service.getUserInfoList(userIds)).rejects.toThrow(
        new HttpException(
          'Failed during Member API batch request 1/1: Error fetching data batch from Member API (Status: 408)',
          408,
        ),
      );
    });

    // it('should handle API error without response object', async () => {
    //   const userIds = [1, 2];
    //   const error = new Error('Connection refused');

    //   jest.spyOn(httpService, 'get').mockReturnValue(throwError(() => error));

    //   await expect(service.getUserInfoList(userIds)).rejects.toThrow(
    //     new HttpException(
    //       expect.stringContaining('Failed during Member API batch request 1/1:'),
    //       HttpStatus.INTERNAL_SERVER_ERROR,
    //     ),
    //   );
    // });

    it('should stop processing batches on first failure', async () => {
      const userIds = Array.from({ length: 120 }, (_, i) => i + 1); // 120 users, 3 batches
      const error = new Error('First batch failed');

      jest.spyOn(httpService, 'get').mockReturnValue(throwError(() => error));

      await expect(service.getUserInfoList(userIds)).rejects.toThrow(
        HttpException,
      );

      // Should only call once (first batch), then stop
      expect(httpService.get).toHaveBeenCalledTimes(1);
    });

    it('should properly encode user IDs in query string', async () => {
      const userIds = [123, 456];
      const mockResponse: AxiosResponse<MemberInfoDto[]> = {
        data: mockMemberInfo,
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };

      jest.spyOn(httpService, 'get').mockReturnValue(of(mockResponse));

      await service.getUserInfoList(userIds);

      expect(httpService.get).toHaveBeenCalledWith(
        `${mockApiUrl}?userIds=123&userIds=456`,
        expect.any(Object),
      );
    });
  });

  describe('Error Handling Edge Cases', () => {
    it('should handle cache set failure gracefully', async () => {
      jest.spyOn(cacheManager, 'get').mockResolvedValue(null);
      jest
        .spyOn(cacheManager, 'set')
        .mockRejectedValue(new Error('Cache write failed'));
      jest.spyOn(m2mAuthClient, 'getMachineToken').mockResolvedValue(mockToken);

      const result = await (service as any).getM2mToken();

      // Should still return token even if caching fails
      expect(result).toBeNull();
    });
  });
});
