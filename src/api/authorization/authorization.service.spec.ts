import { Test, TestingModule } from '@nestjs/testing';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { BadRequestException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { AuthorizationService } from './authorization.service';
import { Auth0Service } from '../../shared/auth0/auth0.service';
import { UserService } from '../user/user.service';
import { AuthDataStore } from './auth-data-store.service';
import { ZendeskAuthPlugin } from './zendesk.service';
import { ConfigurationService } from '../../config/configuration.service';
import { UserProfileHelper } from './user-profile.helper';
import { AuthorizationCreateDto, AuthorizationForm, GetTokenQueryDto, ValidateClientQueryDto } from '../../dto/authorization/authorization.dto';
import { UserProfileDto } from '../../dto/user/user.dto';
import { CommonUtils } from '../../shared/util/common.utils';

describe('AuthorizationService', () => {
  let service: AuthorizationService;
  let mockCacheManager = {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
  };
  let mockAuth0Service = {
    getToken: jest.fn(),
    refreshToken: jest.fn(),
    verifyToken: jest.fn(),
    revokeRefreshToken: jest.fn(),
    domain: 'test.auth0.com',
    clientId: 'test-client-id',
  };
  let mockUserService = {
    generateSSOToken: jest.fn(),
    findUserById: jest.fn(),
  };
  let mockAuthDataStore = {
    put: jest.fn(),
    get: jest.fn(),
    delete: jest.fn(),
  };
  let mockZendeskPlugin = {
    process: jest.fn(),
  };
  let mockPrismaAuth = {
    client: {
      findUnique: jest.fn(),
    },
    roleAssignment: {
      findMany: jest.fn(),
    },
  };
  let mockPrismaCommonClient = {
    user: {
      update: jest.fn(),
    },
  };
  let mockUserProfileHelper = {
    createProfile: jest.fn(),
    getUserIdByProfile: jest.fn(),
  };
  let mockConfigService = {
    getAuthorizationService: jest.fn().mockReturnValue({
      cookieExpirySeconds: 3600,
    }),
    getCommon: jest.fn().mockReturnValue({
      authDomain: 'test.com',
      jwtExpirySeconds: 3600,
      authSecret: 'secret',
      validIssuers: ['https://test.com'],
    }),
    getServiceAccounts: jest.fn().mockReturnValue([
      { clientId: 'client1', secret: 'secret1', contextUserId: '123' }
    ]),
  };

  let parseHeaderSpy: jest.SpyInstance;
  let parseClaimsSpy: jest.SpyInstance;
  let generateJwtSpy: jest.SpyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();

    parseHeaderSpy = jest.spyOn(CommonUtils, 'parseJWTHeader')
      .mockImplementation((token) => {
        return { alg: 'HS256' };
      });
    parseClaimsSpy = jest.spyOn(CommonUtils, 'parseJWTClaims')
      .mockImplementation((token) => {
        return {
          'iss': 'https://api.test.com'
        };
      });
    jest.spyOn(CommonUtils, 'verifyJwtToken').mockResolvedValue({});
    generateJwtSpy = jest.spyOn(CommonUtils, 'generateJwt').mockImplementation(() => {
      return '';
    });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthorizationService,
        { provide: CACHE_MANAGER, useValue: mockCacheManager },
        { provide: Auth0Service, useValue: mockAuth0Service },
        { provide: UserService, useValue: mockUserService },
        { provide: AuthDataStore, useValue: mockAuthDataStore },
        { provide: ZendeskAuthPlugin, useValue: mockZendeskPlugin },
        { provide: 'PRISMA_CLIENT_AUTHORIZATION', useValue: mockPrismaAuth },
        { provide: 'PRISMA_CLIENT_COMMON_OLTP', useValue: mockPrismaCommonClient },
        { provide: UserProfileHelper, useValue: mockUserProfileHelper },
        { provide: ConfigurationService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<AuthorizationService>(AuthorizationService);
  });

  afterEach(async () => {
    parseHeaderSpy.mockRestore();
    parseClaimsSpy.mockRestore();
    generateJwtSpy.mockRestore();
  });

  describe('loginRedirect', () => {
    it('should redirect to auth0 login page', async () => {
      const mockReq = {
        hostname: 'test.com',
        secure: true,
        headers: { referer: 'https://test.com' },
      } as any;
      const mockRes = { redirect: jest.fn() } as any;

      await service.loginRedirect(mockReq, mockRes);

      expect(mockCacheManager.set).toHaveBeenCalled();
      expect(mockRes.redirect).toHaveBeenCalled();
      expect(mockRes.redirect.mock.calls[0][0]).toEqual(302);
      expect(mockRes.redirect.mock.calls[0][1]).toContain('test.auth0.com');
    });

    
    it('should redirect to https when hostname is in tc domains', async () => {
      const mockReq = {
        hostname: 'topcoder.com',
        secure: false,
        headers: { referer: 'https://test.com' },
      } as any;
      const mockRes = { redirect: jest.fn() } as any;

      await service.loginRedirect(mockReq, mockRes);

      expect(mockCacheManager.set).toHaveBeenCalled();
      expect(mockRes.redirect).toHaveBeenCalled();
      expect(mockRes.redirect.mock.calls[0][0]).toEqual(302);
      expect(mockRes.redirect.mock.calls[0][1]).toContain('https://test.auth0.com');
    });

    it('should redirect to "next" parameter', async () => {
      const mockReq = {
        hostname: 'topcoder.com',
        secure: false,
        headers: { referer: 'https://test.com' },
      } as any;
      const mockRes = { redirect: jest.fn() } as any;

      await service.loginRedirect(mockReq, mockRes, 'http://another-test.com');

      expect(mockCacheManager.set).toHaveBeenCalled();
      expect(mockRes.redirect).toHaveBeenCalled();
      expect(mockRes.redirect.mock.calls[0][0]).toEqual(302);
      expect(mockRes.redirect.mock.calls[0][1]).toContain('http://another-test.com');
    });

    it('should redirect to topcoder if redirect url is empty', async () => {
      const mockReq = {
        hostname: 'topcoder.com',
        secure: false,
        headers: {},
      } as any;
      const mockRes = { redirect: jest.fn() } as any;

      await service.loginRedirect(mockReq, mockRes);

      expect(mockCacheManager.set).toHaveBeenCalled();
      expect(mockRes.redirect).toHaveBeenCalled();
      expect(mockRes.redirect.mock.calls[0][0]).toEqual(302);
      expect(mockRes.redirect.mock.calls[0][1]).toContain('https://www.topcoder.com');
    });
  });

  describe('getTokenByAuthorizationCode', () => {
    it('should handle login_required error by redirecting', async () => {
      const mockReq = { hostname: 'test.com', secure: true } as any;
      const mockRes = { redirect: jest.fn() } as any;
      const dto: GetTokenQueryDto = {
        error: 'login_required',
        state: 'state123',
        redirectUrl: 'https://test.com',
      };

      await service.getTokenByAuthorizationCode(mockReq, mockRes, dto);

      expect(mockRes.redirect).toHaveBeenCalled();
      expect(mockRes.redirect.mock.calls[0][0]).toContain('test.auth0.com');
    });

    it('should throw BadRequestException for missing code', async () => {
      const mockReq = {} as any;
      const mockRes = {} as any;
      const dto: GetTokenQueryDto = {
        code: '',
        state: 'state123',
        redirectUrl: 'https://test.com',
      };

      await expect(service.getTokenByAuthorizationCode(mockReq, mockRes, dto))
        .rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for missing redirectUrl', async () => {
      const mockReq = {} as any;
      const mockRes = {} as any;
      const dto: GetTokenQueryDto = {
        code: 'test code',
        state: 'state123',
        redirectUrl: '',
      };

      await expect(service.getTokenByAuthorizationCode(mockReq, mockRes, dto))
        .rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for missing state', async () => {
      const mockReq = {} as any;
      const mockRes = {} as any;
      const dto: GetTokenQueryDto = {
        code: 'test code',
        state: '',
        redirectUrl: 'https://test.com',
      };

      await expect(service.getTokenByAuthorizationCode(mockReq, mockRes, dto))
        .rejects.toThrow(BadRequestException);
    });

    it('should throw InternalServerErrorException if no cache state found', async () => {
      const mockReq = {} as any;
      const mockRes = {} as any;
      const dto: GetTokenQueryDto = {
        code: 'test code',
        state: 'test-state',
        redirectUrl: 'https://test.com',
      };
      mockCacheManager.get.mockResolvedValue(null);

      await expect(service.getTokenByAuthorizationCode(mockReq, mockRes, dto))
        .rejects.toThrow(InternalServerErrorException);
    });

    it('should process valid authorization code', async () => {
      const mockReq = { hostname: 'test.com' } as any;
      const mockRes = {
        cookie: jest.fn(),
        redirect: jest.fn(),
      } as any;
      const dto: GetTokenQueryDto = {
        code: 'valid-code',
        state: 'valid-state',
        redirectUrl: 'https://test.com',
      };

      mockCacheManager.get.mockResolvedValue('valid-state');
      mockAuth0Service.getToken.mockResolvedValue({
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        id_token: 'id-token',
      });

      await service.getTokenByAuthorizationCode(mockReq, mockRes, dto);

      expect(mockAuth0Service.getToken).toHaveBeenCalled();
      expect(mockCacheManager.set).toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalledTimes(3);
      expect(mockRes.redirect).toHaveBeenCalledWith(dto.redirectUrl);
    });
  });

  describe('createObject', () => {
    it('should create authorization from request', async () => {
      const mockReq = {
        headers: { 
          authorization: 'Auth0Code test-code',
          referer: 'https://topcoder-dev.com'
        },
        cookies: { rememberMe: true },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;

      mockAuth0Service.getToken.mockResolvedValue({
        id_token: 'id-token',
        refresh_token: 'refresh-token',
      });
      const profile = new UserProfileDto();
      profile.providerType = 'twitter';
      profile.provider = 'twitter';
      profile.userId = 'test-user';
      profile.name = 'test-user';
      mockUserProfileHelper.createProfile.mockResolvedValue(profile);
      mockUserProfileHelper.getUserIdByProfile.mockResolvedValue(123);
      mockUserService.findUserById.mockResolvedValue({
        status: 'A',
        handle: 'testuser',
        primaryEmailAddress: 'test@test.com',
      });
      mockPrismaAuth.roleAssignment.findMany.mockResolvedValue([]);

      const result = await service.createObject(mockReq, mockRes, null);

      expect(result).toBeDefined();
      expect(result.token).toBeDefined();
      expect(mockAuthDataStore.put).toHaveBeenCalled();
    });

    it('should create authorization from DTO', async () => {
      const mockReq = {} as any;
      const mockRes = { cookie: jest.fn() } as any;
      const dto: AuthorizationCreateDto = {
        externalToken: 'test-token',
        refreshToken: 'refresh-token',
      };

      mockUserProfileHelper.getUserIdByProfile.mockResolvedValue(123);
      mockUserService.findUserById.mockResolvedValue({
        status: 'A',
        handle: 'testuser',
        primaryEmailAddress: 'test@test.com',
      });
      mockPrismaAuth.roleAssignment.findMany.mockResolvedValue([]);
      (CommonUtils.parseJWTHeader as jest.Mock).mockResolvedValue({
        alg: 'HS256'
      });

      const result = await service.createObject(mockReq, mockRes, dto);

      expect(result).toBeDefined();
      expect(result.token).toBeDefined();
      expect(mockAuthDataStore.put).toHaveBeenCalled();
    });

    it('should create authorization from DTO for RS256 algorithm token', async () => {
      const mockReq = {} as any;
      const mockRes = { cookie: jest.fn() } as any;
      const dto: AuthorizationCreateDto = {
        externalToken: 'test-token',
        refreshToken: 'refresh-token',
      };

      mockCacheManager.del.mockResolvedValue(null);
      mockCacheManager.set.mockResolvedValue(null);
      mockAuth0Service.refreshToken.mockResolvedValue({
        access_token: 'test-token'
      });
      mockUserProfileHelper.getUserIdByProfile.mockResolvedValue(123);
      mockUserService.findUserById.mockResolvedValue({
        status: 'A',
        handle: 'testuser',
        primaryEmailAddress: 'test@test.com',
      });
      mockPrismaAuth.roleAssignment.findMany.mockResolvedValue([]);
      (CommonUtils.parseJWTHeader as jest.Mock).mockResolvedValue({
        alg: 'RS256'
      });

      const result = await service.createObject(mockReq, mockRes, dto);

      expect(result).toBeDefined();
      expect(result.token).toBeDefined();
      expect(mockAuthDataStore.put).toHaveBeenCalled();
    });
  });

  describe('createObjectForm', () => {
    it('should create authorization for valid service account', async () => {
      const form: AuthorizationForm = {
        clientId: 'client1',
        secret: 'secret1',
      };

      mockPrismaAuth.roleAssignment.findMany.mockResolvedValue([]);

      const result = await service.createObjectForm(form);

      expect(result).toBeDefined();
      expect(result.token).toBeDefined();
      expect(mockAuthDataStore.put).toHaveBeenCalled();
    });

    it('should throw UnauthorizedException for invalid service account', async () => {
      const form: AuthorizationForm = {
        clientId: 'invalid',
        secret: 'invalid',
      };

      await expect(service.createObjectForm(form))
        .rejects.toThrow(UnauthorizedException);
    });

    it('should throw error when error occurs while putting auth data store', async () => {
      const form: AuthorizationForm = {
        clientId: 'client1',
        secret: 'secret1',
      };

      mockPrismaAuth.roleAssignment.findMany.mockResolvedValue([]);
      mockAuthDataStore.put.mockRejectedValueOnce(new Error('Store error'));

      await expect(service.createObjectForm(form))
        .rejects.toThrow(Error);

      expect(mockAuthDataStore.put).toHaveBeenCalled();
    });
  });

  describe('deleteObject', () => {
    it('should directly return if no auth data store cache found', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValueOnce(null);

      await service.deleteObject(targetId, mockReq, mockRes);

      expect(mockAuthDataStore.delete).not.toHaveBeenCalled();
      expect(mockAuth0Service.revokeRefreshToken).not.toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalled();
    });

    it('should delete authorization and cookies', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });

      await service.deleteObject(targetId, mockReq, mockRes);

      expect(mockAuthDataStore.delete).toHaveBeenCalled();
      expect(mockAuth0Service.revokeRefreshToken).toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalled();
    });

    it('should delete authorization and cookies and ignore revoke token error', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });
      mockAuth0Service.revokeRefreshToken.mockRejectedValueOnce(new Error('revoke error'));

      await service.deleteObject(targetId, mockReq, mockRes);

      expect(mockAuthDataStore.delete).toHaveBeenCalled();
      expect(mockAuth0Service.revokeRefreshToken).toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalled();
    });

    it('should throw UnauthorizedException for missing token', async () => {
      const mockReq = { headers: {} } as any;
      const mockRes = {} as any;
      const targetId = '1';

      await expect(service.deleteObject(targetId, mockReq, mockRes))
        .rejects.toThrow(UnauthorizedException);
    });
  });

  describe('getObject', () => {
    it('should throw UnauthorizedException if no authorization header found', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      await expect(service.getObject('', mockReq, mockRes))
        .rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if token failed to verify', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      (CommonUtils.verifyJwtToken as jest.Mock).mockRejectedValueOnce(new Error('verified failed'));

      await expect(service.getObject('', mockReq, mockRes))
        .rejects.toThrow(UnauthorizedException);

      expect(mockAuthDataStore.put).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
    });

    it('should allow expired token to verify', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      const err = new Error('token expired');
      err.name = 'TokenExpiredError';
      (CommonUtils.verifyJwtToken as jest.Mock).mockRejectedValueOnce(err);

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });

      const result = await service.getObject(targetId, mockReq, mockRes);

      expect(result).toBeDefined();
      expect(mockAuthDataStore.put).toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalled();
    });

    it('should return authorization for valid token', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });

      const result = await service.getObject(targetId, mockReq, mockRes);

      expect(result).toBeDefined();
      expect(mockAuthDataStore.put).toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalled();
    });

    it('should throw error if created jwt token is empty', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });
      (CommonUtils.generateJwt as jest.Mock).mockResolvedValueOnce(null);

      await expect(service.getObject(targetId, mockReq, mockRes))
        .rejects.toThrow(Error);

      expect(mockAuthDataStore.put).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
    });

    it('should throw error if error occurs creating token', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });
      (CommonUtils.generateJwt as jest.Mock).mockRejectedValueOnce(new Error('jwt-error'));

      await expect(service.getObject(targetId, mockReq, mockRes))
        .rejects.toThrow(Error);

      expect(mockAuthDataStore.put).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
    });

    it('should allow token expired error while creating new token', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });
      const err = new Error('token expired');
      err.name = 'TokenExpiredError';
      (CommonUtils.generateJwt as jest.Mock).mockRejectedValueOnce(err);
      mockAuth0Service.refreshToken.mockResolvedValueOnce({
        id_token: 'id-token'
      });

      const result = await service.getObject(targetId, mockReq, mockRes);

      expect(result).toBeDefined();
      expect(mockAuthDataStore.put).toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalled();
    });

    it('should throw error if refresh token is not provided when token expires', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: null,
      });
      const err = new Error('token expired');
      err.name = 'TokenExpiredError';
      (CommonUtils.generateJwt as jest.Mock).mockRejectedValueOnce(err);

      await expect(service.getObject(targetId, mockReq, mockRes))
        .rejects.toThrow(Error);

      expect(mockAuthDataStore.put).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
    });

    it('should throw error if failed to refresh token', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });
      const err = new Error('token expired');
      err.name = 'TokenExpiredError';
      (CommonUtils.generateJwt as jest.Mock).mockRejectedValueOnce(err);
      mockAuth0Service.refreshToken.mockRejectedValueOnce(new Error('refresh error'));

      await expect(service.getObject(targetId, mockReq, mockRes))
        .rejects.toThrow(Error);

      expect(mockAuthDataStore.put).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
    });

    it('should throw error if refreshed token is empty', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });
      const err = new Error('token expired');
      err.name = 'TokenExpiredError';
      (CommonUtils.generateJwt as jest.Mock).mockRejectedValueOnce(err);
      mockAuth0Service.refreshToken.mockResolvedValueOnce({});

      await expect(service.getObject(targetId, mockReq, mockRes))
        .rejects.toThrow(Error);

      expect(mockAuthDataStore.put).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
    });

    it('should get auth if token is from other domain', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });
      (CommonUtils.parseJWTClaims as jest.Mock).mockImplementation(() => {
        return {
          iss: 'https://another-test.com'
        };
      });

      const result = await service.getObject(targetId, mockReq, mockRes);

      expect(result).toBeDefined();
      expect(mockRes.cookie).toHaveBeenCalled();
    });

    it('should pick fields on response', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer valid-token' },
      } as any;
      const mockRes = { cookie: jest.fn() } as any;
      const targetId = '1';
      const fields = 'token,target';

      mockAuthDataStore.get.mockResolvedValue({
        token: 'new-token',
        externalToken: 'ext-token',
        refreshToken: 'refresh-token',
      });
      (CommonUtils.parseJWTHeader as jest.Mock).mockResolvedValueOnce({
        iss: 'https://another-test.com'
      });

      const result = await service.getObject(targetId, mockReq, mockRes, fields);

      expect(result).toBeDefined();
      const allKeysValid = Object.keys(result).every(key => ['token', 'target'].includes(key));
      expect(allKeysValid).toBeTruthy();
      expect(mockAuthDataStore.put).toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalled();
    });

    it('should throw UnauthorizedException for invalid token', async () => {
      const mockReq = {
        headers: { authorization: 'Bearer invalid-token' },
      } as any;
      const mockRes = {
        cookie: jest.fn(),
      } as any;
      const targetId = '1';

      mockAuthDataStore.get.mockResolvedValue(null);

      await expect(service.getObject(targetId, mockReq, mockRes))
        .rejects.toThrow(UnauthorizedException);
    });
  });

  describe('validateClient', () => {
    it('should validate client with correct credentials', async () => {
      const dto: ValidateClientQueryDto = {
        clientId: 'valid-client',
        redirectUrl: 'https://valid.com',
      };

      mockPrismaAuth.client.findUnique.mockResolvedValue({
        clientId: 'valid-client',
        redirectUri: 'https://valid.com,https://another.com',
      });

      const result = await service.validateClient(dto);

      expect(result).toBe('Valid client');
    });

    it('should throw UnauthorizedException for unknown client', async () => {
      const dto: ValidateClientQueryDto = {
        clientId: 'invalid-client',
        redirectUrl: 'https://valid.com',
      };

      mockPrismaAuth.client.findUnique.mockResolvedValue(null);

      await expect(service.validateClient(dto))
        .rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if no redirect uri is configured', async () => {
      const dto: ValidateClientQueryDto = {
        clientId: 'invalid-client',
        redirectUrl: 'https://valid.com',
      };

      mockPrismaAuth.client.findUnique.mockResolvedValue({
        clientId: 'valid-client',
        redirectUri: null,
      });

      await expect(service.validateClient(dto))
        .rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException for unregistered URI', async () => {
      const dto: ValidateClientQueryDto = {
        clientId: 'valid-client',
        redirectUrl: 'https://invalid.com',
      };

      mockPrismaAuth.client.findUnique.mockResolvedValue({
        clientId: 'valid-client',
        redirectUri: 'https://valid.com',
      });

      await expect(service.validateClient(dto))
        .rejects.toThrow(UnauthorizedException);
    });
  });
});
