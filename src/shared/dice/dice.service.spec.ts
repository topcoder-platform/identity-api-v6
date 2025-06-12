import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import {
  InternalServerErrorException,
  BadRequestException,
  HttpStatus,
} from '@nestjs/common';
import { of, throwError } from 'rxjs';
import { AxiosResponse, AxiosError } from 'axios';
import { DiceService } from './dice.service';

// Mock interfaces matching the service
interface DiceTokenResponse {
  status: string;
  result: {
    token: string;
    expires_at?: string;
  };
}

interface DiceInvitationResponse {
  jobId: string;
  connectionId?: string;
  shortUrl?: string;
}

describe('DiceService', () => {
  let service: DiceService;
  let configService: jest.Mocked<ConfigService>;
  let httpService: jest.Mocked<HttpService>;

  // Test data constants
  const mockConfig = {
    DICEAUTH_DICE_API_URL: 'https://api.dice.example.com',
    DICEAUTH_DICE_API_KEY: 'dice-api-key-123',
    DICEAUTH_ORG_ID: 'org-123',
    DICEAUTH_USER_ID: 'user-456',
    DICEAUTH_TC_API_KEY: 'tc-api-key-789',
    DICEAUTH_SCHEMA_NAME: 'TestSchema',
    DICEAUTH_SCHEMA_VERSION: '1.0.0',
  };

  // Valid JWT token (expires in 1 hour from now)
  const futureTimestamp = Math.floor(Date.now() / 1000) + 3600;
  const validJwtPayload = Buffer.from(
    JSON.stringify({ exp: futureTimestamp }),
  ).toString('base64');
  const validJwtToken = `header.${validJwtPayload}.signature`;

  // Expired JWT token
  const pastTimestamp = Math.floor(Date.now() / 1000) - 3600;
  const expiredJwtPayload = Buffer.from(
    JSON.stringify({ exp: pastTimestamp }),
  ).toString('base64');
  const expiredJwtToken = `header.${expiredJwtPayload}.signature`;

  beforeEach(async () => {
    // Reset static cache before each test
    (DiceService as any).cachedDiceAuthToken = null;
    (DiceService as any).tokenExpiryTime = null;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DiceService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => mockConfig[key]),
          },
        },
        {
          provide: HttpService,
          useValue: {
            get: jest.fn(),
            post: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<DiceService>(DiceService);
    configService = module.get(ConfigService);
    httpService = module.get(HttpService);

    // Suppress console logs during tests
    jest.spyOn(service['logger'], 'log').mockImplementation();
    jest.spyOn(service['logger'], 'debug').mockImplementation();
    jest.spyOn(service['logger'], 'error').mockImplementation();
    jest.spyOn(service['logger'], 'warn').mockImplementation();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Constructor and Configuration', () => {
    it('should be defined', () => {
      expect(service).toBeDefined();
    });

    it('should throw InternalServerErrorException when required config is missing', () => {
      const incompleteConfig = { ...mockConfig };
      delete incompleteConfig.DICEAUTH_DICE_API_URL;

      const mockConfigService = {
        get: jest.fn((key: string) => incompleteConfig[key]),
      };

      expect(() => {
        new DiceService(mockConfigService as any, httpService);
      }).toThrow(InternalServerErrorException);
    });

    it('should initialize with all required configuration', () => {
      expect(service['diceApiUrl']).toBe(mockConfig.DICEAUTH_DICE_API_URL);
      expect(service['diceApiKey']).toBe(mockConfig.DICEAUTH_DICE_API_KEY);
      expect(service['diceOrgId']).toBe(mockConfig.DICEAUTH_ORG_ID);
      expect(service['diceUserId']).toBe(mockConfig.DICEAUTH_USER_ID);
      expect(service['tcApiKey']).toBe(mockConfig.DICEAUTH_TC_API_KEY);
      expect(service['diceSchemaName']).toBe(mockConfig.DICEAUTH_SCHEMA_NAME);
      expect(service['diceSchemaVersion']).toBe(
        mockConfig.DICEAUTH_SCHEMA_VERSION,
      );
    });
  });

  describe('JWT Token Management', () => {
    describe('decodeJwt', () => {
      it('should decode valid JWT token', () => {
        const result = service['decodeJwt'](validJwtToken);
        expect(result).toHaveProperty('exp', futureTimestamp);
      });

      it('should return null for invalid JWT token', () => {
        const result = service['decodeJwt']('invalid-token');
        expect(result).toBeNull();
      });

      it('should return null for token without payload', () => {
        const result = service['decodeJwt']('header..signature');
        expect(result).toBeNull();
      });

      it('should handle JSON parse errors gracefully', () => {
        const invalidPayload = 'invalid-base64';
        const invalidToken = `header.${invalidPayload}.signature`;
        const result = service['decodeJwt'](invalidToken);
        expect(result).toBeNull();
      });
    });

    describe('isTokenExpired', () => {
      it('should return true for null token', () => {
        const result = service['isTokenExpired'](null);
        expect(result).toBe(true);
      });

      it('should return false for valid unexpired token', () => {
        const result = service['isTokenExpired'](validJwtToken);
        expect(result).toBe(false);
      });

      it('should return true for expired token', () => {
        const result = service['isTokenExpired'](expiredJwtToken);
        expect(result).toBe(true);
      });

      it('should return true for token without expiry claim', () => {
        const noExpPayload = Buffer.from(
          JSON.stringify({ sub: 'user' }),
        ).toString('base64');
        const noExpToken = `header.${noExpPayload}.signature`;
        const result = service['isTokenExpired'](noExpToken);
        expect(result).toBe(true);
      });

      it('should return true for token expiring within 60 seconds', () => {
        const soonExpTimestamp = Math.floor(Date.now() / 1000) + 30; // 30 seconds from now
        const soonExpPayload = Buffer.from(
          JSON.stringify({ exp: soonExpTimestamp }),
        ).toString('base64');
        const soonExpToken = `header.${soonExpPayload}.signature`;
        const result = service['isTokenExpired'](soonExpToken);
        expect(result).toBe(true);
      });
    });
  });

  describe('getDiceAuthToken', () => {
    const mockTokenResponse: AxiosResponse<DiceTokenResponse> = {
      data: {
        status: 'success',
        result: {
          token: validJwtToken,
          expires_at: new Date(futureTimestamp * 1000).toISOString(),
        },
      },
      status: HttpStatus.OK,
      statusText: 'OK',
      headers: {},
      config: {} as any,
    };

    beforeEach(() => {
      // Reset cache before each test
      (DiceService as any).cachedDiceAuthToken = null;
      (DiceService as any).tokenExpiryTime = null;
    });

    it('should return cached token when valid and not expired', async () => {
      // Set up cached token
      (DiceService as any).cachedDiceAuthToken = validJwtToken;

      const result = await service.getDiceAuthToken();

      expect(result).toBe(validJwtToken);
      expect(httpService.get).not.toHaveBeenCalled();
    });

    it('should fetch new token when cache is empty', async () => {
      httpService.get.mockReturnValue(of(mockTokenResponse));

      const result = await service.getDiceAuthToken();

      expect(result).toBe(validJwtToken);
      expect(httpService.get).toHaveBeenCalledWith(
        `${mockConfig.DICEAUTH_DICE_API_URL}/api-token`,
        {
          headers: {
            org_id: mockConfig.DICEAUTH_ORG_ID,
            invoked_by: mockConfig.DICEAUTH_USER_ID,
            'x-api-key': mockConfig.DICEAUTH_DICE_API_KEY,
            'Content-Type': 'application/json',
          },
        },
      );
    });

    it('should fetch new token when cached token is expired', async () => {
      // Set up expired cached token
      (DiceService as any).cachedDiceAuthToken = expiredJwtToken;
      httpService.get.mockReturnValue(of(mockTokenResponse));

      const result = await service.getDiceAuthToken();

      expect(result).toBe(validJwtToken);
      expect(httpService.get).toHaveBeenCalled();
    });

    it('should cache the new token after successful fetch', async () => {
      httpService.get.mockReturnValue(of(mockTokenResponse));

      const result = await service.getDiceAuthToken();

      expect(result).toBe(validJwtToken);
      expect((DiceService as any).cachedDiceAuthToken).toBe(validJwtToken);
      expect((DiceService as any).tokenExpiryTime).toEqual(
        new Date(futureTimestamp * 1000),
      );
    });

    it('should throw InternalServerErrorException when API response is missing token', async () => {
      const invalidResponse: AxiosResponse<any> = {
        ...mockTokenResponse,
        data: { status: 'success', result: {} },
      };
      httpService.get.mockReturnValue(of(invalidResponse));

      await expect(service.getDiceAuthToken()).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should handle HTTP errors and throw InternalServerErrorException', async () => {
      const axiosError = new AxiosError('Network Error');
      axiosError.response = {
        status: 500,
        data: { error: 'Internal Server Error' },
        headers: {},
        statusText: 'Internal Server Error',
        config: {} as any,
      };
      httpService.get.mockReturnValue(throwError(() => axiosError));

      await expect(service.getDiceAuthToken()).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should handle non-Axios errors', async () => {
      const genericError = new Error('Generic error');
      httpService.get.mockReturnValue(throwError(() => genericError));

      await expect(service.getDiceAuthToken()).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('sendDiceInvitation', () => {
    const mockInvitationData = {
      inviteeEmail: 'test@example.com',
      inviteeHandle: 'testuser',
      inviteeFullName: 'Test User',
      roles: ['developer', 'reviewer'],
      validTill: '31-Dec-2024 23:59:59',
    };

    const mockInvitationResponse: AxiosResponse<DiceInvitationResponse> = {
      data: {
        jobId: 'job-123',
        connectionId: 'conn-456',
        shortUrl: 'https://short.url/abc',
      },
      status: HttpStatus.OK,
      statusText: 'OK',
      headers: {},
      config: {} as any,
    };

    beforeEach(() => {
      // Mock getDiceAuthToken to return a valid token
      jest.spyOn(service, 'getDiceAuthToken').mockResolvedValue(validJwtToken);
    });

    it('should send invitation successfully', async () => {
      httpService.post.mockReturnValue(of(mockInvitationResponse));

      const result = await service.sendDiceInvitation(
        mockInvitationData.inviteeEmail,
        mockInvitationData.inviteeHandle,
        mockInvitationData.inviteeFullName,
        mockInvitationData.roles,
        mockInvitationData.validTill,
      );

      expect(result).toEqual(mockInvitationResponse.data);
      expect(service.getDiceAuthToken).toHaveBeenCalled();
    });

    it('should send correct payload to DICE API', async () => {
      httpService.post.mockReturnValue(of(mockInvitationResponse));

      await service.sendDiceInvitation(
        mockInvitationData.inviteeEmail,
        mockInvitationData.inviteeHandle,
        mockInvitationData.inviteeFullName,
        mockInvitationData.roles,
        mockInvitationData.validTill,
      );

      const expectedPayload = {
        invitee_name: 'Topcoder',
        auto_accept: true,
        auto_offer: true,
        send_connection_invite: false,
        email: { invitee_email: mockInvitationData.inviteeEmail },
        invite_modes: ['email'],
        credential_data: {
          schema_name: mockConfig.DICEAUTH_SCHEMA_NAME,
          schema_version: mockConfig.DICEAUTH_SCHEMA_VERSION,
          attributes: [
            { name: 'Name', value: mockInvitationData.inviteeFullName },
            { name: 'Email', value: mockInvitationData.inviteeEmail },
            { name: 'Role', value: mockInvitationData.roles.join(',') },
            { name: 'Valid_Till', value: mockInvitationData.validTill },
            {
              name: 'dice_display_name',
              value: mockInvitationData.inviteeHandle,
            },
          ],
        },
      };

      expect(httpService.post).toHaveBeenCalledWith(
        `${mockConfig.DICEAUTH_DICE_API_URL}/connection/invitation`,
        expectedPayload,
        {
          headers: {
            org_id: mockConfig.DICEAUTH_ORG_ID,
            invoked_by: mockConfig.DICEAUTH_USER_ID,
            'x-api-key': mockConfig.DICEAUTH_DICE_API_KEY,
            Authorization: `Bearer ${validJwtToken}`,
            'Content-Type': 'application/json',
          },
        },
      );
    });

    it('should handle HTTP errors and throw InternalServerErrorException', async () => {
      const axiosError = new AxiosError('Bad Request');
      axiosError.response = {
        status: 400,
        data: { error: 'Invalid payload' },
        headers: {},
        statusText: 'Bad Request',
        config: {} as any,
      };
      httpService.post.mockReturnValue(throwError(() => axiosError));

      await expect(
        service.sendDiceInvitation(
          mockInvitationData.inviteeEmail,
          mockInvitationData.inviteeHandle,
          mockInvitationData.inviteeFullName,
          mockInvitationData.roles,
          mockInvitationData.validTill,
        ),
      ).rejects.toThrow(InternalServerErrorException);
    });

    it('should handle roles as empty array', async () => {
      httpService.post.mockReturnValue(of(mockInvitationResponse));

      await service.sendDiceInvitation(
        mockInvitationData.inviteeEmail,
        mockInvitationData.inviteeHandle,
        mockInvitationData.inviteeFullName,
        [], // Empty roles array
        mockInvitationData.validTill,
      );

      const postCall = httpService.post.mock.calls[0];
      const payload = postCall[1] as any;
      const roleAttribute = payload.credential_data.attributes.find(
        (attr: any) => attr.name === 'Role',
      );

      expect(roleAttribute.value).toBe('');
    });

    it('should handle single role correctly', async () => {
      httpService.post.mockReturnValue(of(mockInvitationResponse));

      await service.sendDiceInvitation(
        mockInvitationData.inviteeEmail,
        mockInvitationData.inviteeHandle,
        mockInvitationData.inviteeFullName,
        ['developer'], // Single role
        mockInvitationData.validTill,
      );

      const postCall = httpService.post.mock.calls[0];
      const payload = postCall[1] as any;
      const roleAttribute = payload.credential_data.attributes.find(
        (attr: any) => attr.name === 'Role',
      );

      expect(roleAttribute.value).toBe('developer');
    });
  });

  describe('isValidTopcoderApiKey', () => {
    it('should return true for valid API key', () => {
      const result = service.isValidTopcoderApiKey(
        mockConfig.DICEAUTH_TC_API_KEY,
      );
      expect(result).toBe(true);
    });

    it('should return false for invalid API key', () => {
      const result = service.isValidTopcoderApiKey('invalid-key');
      expect(result).toBe(false);
    });

    it('should return false for empty API key', () => {
      const result = service.isValidTopcoderApiKey('');
      expect(result).toBe(false);
    });

    it('should return false for null API key', () => {
      const result = service.isValidTopcoderApiKey(null as any);
      expect(result).toBe(false);
    });

    it('should return false for undefined API key', () => {
      const result = service.isValidTopcoderApiKey(undefined as any);
      expect(result).toBe(false);
    });

    it('should log warning for invalid API key', () => {
      const loggerWarnSpy = jest.spyOn(service['logger'], 'warn');

      service.isValidTopcoderApiKey('invalid-key');

      expect(loggerWarnSpy).toHaveBeenCalledWith(
        'Invalid TC API Key received for DICE webhook: invalid-key',
      );
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle malformed JWT tokens gracefully', () => {
      const malformedTokens = [
        'not.a.jwt',
        'header.only',
        '',
        'a',
        'too.many.parts.in.token.here',
      ];

      malformedTokens.forEach((token) => {
        expect(service['isTokenExpired'](token)).toBe(true);
        expect(service['decodeJwt'](token)).toBeNull();
      });
    });

    it('should handle network timeouts in getDiceAuthToken', async () => {
      const timeoutError = new AxiosError('timeout');
      timeoutError.code = 'ECONNABORTED';
      httpService.get.mockReturnValue(throwError(() => timeoutError));

      await expect(service.getDiceAuthToken()).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should handle network timeouts in sendDiceInvitation', async () => {
      jest.spyOn(service, 'getDiceAuthToken').mockResolvedValue(validJwtToken);

      const timeoutError = new AxiosError('timeout');
      timeoutError.code = 'ECONNABORTED';
      httpService.post.mockReturnValue(throwError(() => timeoutError));

      await expect(
        service.sendDiceInvitation(
          'test@example.com',
          'testuser',
          'Test User',
          ['developer'],
          '31-Dec-2024 23:59:59',
        ),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('Static Cache Management', () => {
    it('should share cache across multiple service instances', async () => {
      // Create another service instance
      const anotherService = new DiceService(configService, httpService);

      // Set up mocks
      const mockTokenResponse: AxiosResponse<DiceTokenResponse> = {
        data: {
          status: 'success',
          result: {
            token: validJwtToken,
          },
        },
        status: HttpStatus.OK,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };

      httpService.get.mockReturnValue(of(mockTokenResponse));

      // First service fetches token
      await service.getDiceAuthToken();

      // Second service should use cached token
      const result = await anotherService.getDiceAuthToken();

      expect(result).toBe(validJwtToken);
      expect(httpService.get).toHaveBeenCalledTimes(1); // Only called once
    });
  });
});
