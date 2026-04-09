import { Test, TestingModule } from '@nestjs/testing';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { HttpException, HttpStatus } from '@nestjs/common';
import { AxiosResponse } from 'axios';
import { of, throwError } from 'rxjs';
import { MemberApiService } from './member-api.service';
import { M2M_AUTH_CLIENT } from './member-api.constants';
import { MemberInfoDto } from '../../dto/member/member.dto';

describe('MemberApiService', () => {
  let service: MemberApiService;
  let httpService: HttpService;
  let configService: ConfigService;
  let m2mAuthClient: { getMachineToken: jest.Mock };
  let module: TestingModule;

  const mockApiUrl = 'https://api.example.com/v6/members';
  const mockClientId = 'client-id';
  const mockClientSecret = 'client-secret';
  const mockToken = 'machine-token';

  const createMockConfigService = () => ({
    get: jest.fn((key: string, defaultValue?: unknown) => {
      const values: Record<string, unknown> = {
        MEMBER_API_URL: mockApiUrl,
        AUTH0_CLIENT_ID: mockClientId,
        AUTH0_CLIENT_SECRET: mockClientSecret,
      };

      return key in values ? values[key] : defaultValue;
    }),
  });

  beforeEach(async () => {
    const mockHttpService = {
      get: jest.fn(),
    };
    const mockConfigService = createMockConfigService();
    const mockM2mAuthClient = {
      getMachineToken: jest.fn().mockResolvedValue(mockToken),
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
          provide: M2M_AUTH_CLIENT,
          useValue: mockM2mAuthClient,
        },
      ],
    }).compile();

    service = module.get<MemberApiService>(MemberApiService);
    httpService = module.get<HttpService>(HttpService);
    configService = module.get<ConfigService>(ConfigService);
    m2mAuthClient = module.get(M2M_AUTH_CLIENT);
  });

  afterEach(async () => {
    jest.clearAllMocks();
    await module.close();
  });

  describe('getUserInfoList', () => {
    it('returns an empty array for empty input', async () => {
      await expect(service.getUserInfoList([])).resolves.toEqual([]);
      expect(httpService.get).not.toHaveBeenCalled();
    });

    it('throws when the service cannot obtain an M2M token', async () => {
      m2mAuthClient.getMachineToken.mockResolvedValueOnce(null);

      await expect(service.getUserInfoList([1])).rejects.toThrow(
        new HttpException(
          'Internal configuration error: Could not authenticate service.',
          HttpStatus.INTERNAL_SERVER_ERROR,
        ),
      );
      expect(httpService.get).not.toHaveBeenCalled();
    });

    it('requests only the identity fields needed for batched lookups', async () => {
      const mockResponse: AxiosResponse<MemberInfoDto[]> = {
        data: [
          { userId: 1, handle: 'alpha', email: 'alpha@example.com' },
          { userId: 2, handle: 'beta', email: 'beta@example.com' },
        ],
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as AxiosResponse<MemberInfoDto[]>['config'],
      };

      jest.spyOn(httpService, 'get').mockReturnValue(of(mockResponse));

      const result = await service.getUserInfoList([1, 2]);

      expect(result).toEqual(mockResponse.data);
      expect(httpService.get).toHaveBeenCalledWith(
        `${mockApiUrl}?userIds=1&userIds=2&fields=userId%2Chandle%2Cemail&includeStats=false`,
        {
          headers: {
            Authorization: `Bearer ${mockToken}`,
            'Content-Type': 'application/json',
          },
          timeout: 10000,
        },
      );
    });

    it('uses the singular userId parameter and configured timeout for single-user lookups', async () => {
      jest
        .spyOn(configService, 'get')
        .mockImplementation((key: string, defaultValue?: unknown) => {
          const values: Record<string, unknown> = {
            MEMBER_API_URL: mockApiUrl,
            AUTH0_CLIENT_ID: mockClientId,
            AUTH0_CLIENT_SECRET: mockClientSecret,
            HTTP_TIMEOUT: '15000',
          };

          return key in values ? values[key] : defaultValue;
        });

      const mockResponse: AxiosResponse<MemberInfoDto[]> = {
        data: [{ userId: 7, handle: 'solo', email: 'solo@example.com' }],
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as AxiosResponse<MemberInfoDto[]>['config'],
      };

      jest.spyOn(httpService, 'get').mockReturnValue(of(mockResponse));

      await service.getUserInfoList([7]);

      expect(httpService.get).toHaveBeenCalledWith(
        `${mockApiUrl}?userId=7&fields=userId%2Chandle%2Cemail&includeStats=false`,
        expect.objectContaining({
          timeout: 15000,
        }),
      );
    });

    it('deduplicates user IDs before batching', async () => {
      const mockResponse: AxiosResponse<MemberInfoDto[]> = {
        data: [{ userId: 1, handle: 'alpha', email: 'alpha@example.com' }],
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as AxiosResponse<MemberInfoDto[]>['config'],
      };

      jest.spyOn(httpService, 'get').mockReturnValue(of(mockResponse));

      await service.getUserInfoList([1, 2, 1, 3, 2]);

      expect(httpService.get).toHaveBeenCalledWith(
        `${mockApiUrl}?userIds=1&userIds=2&userIds=3&fields=userId%2Chandle%2Cemail&includeStats=false`,
        expect.any(Object),
      );
    });

    it('wraps upstream HTTP failures in an HttpException', async () => {
      jest.spyOn(httpService, 'get').mockReturnValue(
        throwError(() => ({
          message: 'timeout of 5000ms exceeded',
          response: {
            status: 504,
            data: { message: 'Gateway Timeout' },
          },
        })),
      );

      await expect(service.getUserInfoList([1, 2])).rejects.toThrow(
        new HttpException(
          'Failed during Member API batch request 1/1: Gateway Timeout',
          504,
        ),
      );
    });
  });
});
