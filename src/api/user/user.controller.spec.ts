import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { UserProfileService } from './user-profile.service';
import { AuthFlowService } from './auth-flow.service';
import { TwoFactorAuthService } from './two-factor-auth.service';
import { ValidationService } from './validation.service';
import { RoleService } from '../role/role.service';
import { AuthGuard } from '@nestjs/passport';
import {
  ForbiddenException,
  NotFoundException,
  BadRequestException,
  UnauthorizedException,
  InternalServerErrorException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import * as DTOs from '../../dto/user/user.dto';
import { Request } from 'express';
import {
  Prisma,
  user as UserModel,
  sso_login_provider as SsoLoginProviderModel,
} from '@prisma/client-common-oltp'; // Import Prisma
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';

// --- Mock Services ---
const mockUserService = {
  findUsers: jest.fn(),
  findUserById: jest.fn(),
  registerUser: jest.fn(),
  updateBasicInfo: jest.fn(),
  deleteUser: jest.fn(),
  updateHandle: jest.fn(),
  updatePrimaryEmail: jest.fn(),
  updateStatus: jest.fn(),
  getAchievements: jest.fn(),
  updatePrimaryRole: jest.fn(),
};

const mockUserProfileService = {
  createSSOUserLogin: jest.fn(),
  updateSSOUserLogin: jest.fn(),
  deleteSSOUserLogin: jest.fn(),
  findSSOUserLoginsByUserId: jest.fn(),
  addExternalProfile: jest.fn(),
  findAllUserProfiles: jest.fn(),
  deleteExternalProfile: jest.fn(),
};

const mockAuthFlowService = {
  initiatePasswordReset: jest.fn(),
  authenticateForAuth0: jest.fn(),
  getUserProfileForAuth0: jest.fn(),
  changePasswordFromAuth0: jest.fn(),
  resetPassword: jest.fn(),
  activateUser: jest.fn(),
  requestResendActivation: jest.fn(),
  generateOneTimeToken: jest.fn(),
  updateEmailWithOneTimeToken: jest.fn(),
};

const mockTwoFactorAuthService = {
  getUser2faStatus: jest.fn(),
  updateUser2faStatus: jest.fn(),
  getDiceConnection: jest.fn(),
  handleDiceWebhook: jest.fn(),
  isValidDiceApiKey: jest.fn(),
  sendOtpFor2fa: jest.fn(),
  resendOtpEmailFor2fa: jest.fn(),
  checkOtpAndCompleteLogin: jest.fn(),
};

const mockValidationService = {
  validateHandle: jest.fn(),
  validateEmail: jest.fn(),
  validateSocial: jest.fn(),
};

const mockRoleService = {
  // Define mocks if UserController directly uses RoleService methods
};

const mockPrismaClientCommonOltp = {
  sso_login_provider: {
    findUnique: jest.fn(),
  },
};

const mockConfigService = {
  get: jest.fn(),
};

const mockCacheManager = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
};

// --- Mock Authenticated Users ---
const mockAdminUser: AuthenticatedUser = {
  userId: '1',
  roles: ['Administrator'],
  scopes: ['admin:scope', 'read:all', 'write:all'],
  isAdmin: true,
  isMachine: false,
  payload: { sub: 'auth0|admin1' },
  handle: 'adminUser',
  email: 'admin@example.com',
};

const mockRegularUser: AuthenticatedUser = {
  userId: '2',
  roles: ['User'],
  scopes: ['read:self', 'write:self'],
  isAdmin: false,
  isMachine: false,
  payload: { sub: 'auth0|user2' },
  handle: 'regularUser',
  email: 'regular@example.com',
};

// --- Helper to create mock request ---
const createMockRequest = (
  user?: AuthenticatedUser,
  headers?: Record<string, string>,
  body?: any,
  query?: any,
  params?: any,
): Request => {
  const _headers = { host: 'localhost', ...headers };
  const req = {
    user: user,
    headers: _headers,
    body: body || {},
    query: query || {},
    params: params || {},
    get: jest.fn((name: string) => _headers[name.toLowerCase()]),
    header: jest.fn((name: string) => _headers[name.toLowerCase()]),
    // Minimal http.IncomingMessage properties often expected
    httpVersion: '1.1',
    method: 'GET',
    url: '/',
    socket: {} as any, // Mock basic socket
    connection: {} as any, // Mock basic connection
    // Add other methods if specifically required by NestJS internals or other decorators
    accepts: jest.fn(),
    acceptsCharsets: jest.fn(),
    acceptsEncodings: jest.fn(),
    acceptsLanguages: jest.fn(),
    range: jest.fn(),
    param: jest.fn((nameParam, defaultValue) => {
      // A simple mock for req.param, might need adjustment based on actual usage
      if (req.params && req.params[nameParam]) return req.params[nameParam];
      if (req.body && req.body[nameParam]) return req.body[nameParam];
      if (req.query && req.query[nameParam]) return req.query[nameParam];
      return defaultValue;
    }),
    is: jest.fn(),
    flash: jest.fn(), // if connect-flash is used
    session: {} as any, // if sessions are used
    app: {} as any, // mock app
    res: {} as any, // mock res
    next: jest.fn(), // mock next
    // Add any other properties from Express.Request that are required by your setup
    baseUrl: '',
    originalUrl: '',
    path: '/',
    protocol: 'http',
    secure: false,
    ip: '127.0.0.1',
    ips: [],
    subdomains: [],
    hostname: 'localhost',
    fresh: false,
    stale: true,
    xhr: false,
    cookies: {},
    signedCookies: {},
    route: {} as any,
  };
  return req as Request;
};

// Example UserModel for service mock returns. Controller's mapUserToDto will handle mapping.
const createMockUserModel = (
  id: number,
  handle: string,
  _email?: string, // Optional param for internal use
  status?: string,
  firstName?: string,
  lastName?: string,
): Partial<UserModel> => ({
  user_id: new Prisma.Decimal(id),
  handle,
  status: status || 'Active',
  first_name: firstName || 'Test',
  last_name: lastName || 'User',
  create_date: new Date(),
  modify_date: new Date(),
});

describe('UserController', () => {
  let controller: UserController;
  let prismaOltp: typeof mockPrismaClientCommonOltp;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [
        { provide: UserService, useValue: mockUserService },
        { provide: UserProfileService, useValue: mockUserProfileService },
        { provide: AuthFlowService, useValue: mockAuthFlowService },
        { provide: TwoFactorAuthService, useValue: mockTwoFactorAuthService },
        { provide: ValidationService, useValue: mockValidationService },
        { provide: RoleService, useValue: mockRoleService },
        {
          provide: PRISMA_CLIENT_COMMON_OLTP,
          useValue: mockPrismaClientCommonOltp,
        },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: CACHE_MANAGER, useValue: mockCacheManager },
      ],
    })
      .overrideGuard(AuthGuard('jwt'))
      .useValue({
        canActivate: (context: any) => {
          const req = context.switchToHttp().getRequest();
          if (req.headers.authorization === 'Bearer admin-token') {
            req.user = mockAdminUser;
          } else if (req.headers.authorization === 'Bearer user-token') {
            req.user = mockRegularUser;
          } else if (
            req.headers.authorization === 'Bearer incomplete-user-token'
          ) {
            req.user = { userId: '3' };
          }
          return true;
        },
      })
      .compile();

    controller = module.get<UserController>(UserController);
    prismaOltp = module.get(PRISMA_CLIENT_COMMON_OLTP);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  // --- Public Endpoints ---
  describe('getResetToken', () => {
    it('should initiate password reset with email', async () => {
      mockAuthFlowService.initiatePasswordReset.mockResolvedValue(undefined);
      const result = await controller.getResetToken(
        'test@example.com',
        undefined,
        'http://localhost/reset',
      );
      expect(mockAuthFlowService.initiatePasswordReset).toHaveBeenCalledWith(
        'test@example.com',
        'http://localhost/reset',
      );
      expect(result.message).toContain('Password reset token has been sent');
    });

    it('should throw BadRequestException if no email or handle provided', async () => {
      await expect(
        controller.getResetToken(undefined, undefined),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('validateHandle', () => {
    it('should validate handle successfully', async () => {
      const mockResponse: DTOs.ValidationResponseDto = {
        valid: true,
        reason: 'Available',
      };
      mockValidationService.validateHandle.mockResolvedValue(mockResponse);
      const result = await controller.validateHandle('newhandle');
      expect(mockValidationService.validateHandle).toHaveBeenCalledWith(
        'newhandle',
      );
      expect(result).toEqual(mockResponse);
    });

    it('should throw BadRequestException if handle is not provided', async () => {
      await expect(controller.validateHandle(undefined as any)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('validateEmail', () => {
    it('should validate email successfully', async () => {
      const mockResponse: DTOs.ValidationResponseDto = {
        valid: false,
        reason: 'Already taken',
      };
      mockValidationService.validateEmail.mockResolvedValue(mockResponse);
      const result = await controller.validateEmail('taken@example.com');
      expect(mockValidationService.validateEmail).toHaveBeenCalledWith(
        'taken@example.com',
      );
      expect(result).toEqual(mockResponse);
    });

    it('should throw BadRequestException if email is not provided', async () => {
      await expect(controller.validateEmail(undefined as any)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('validateSocial', () => {
    it('should validate social profile successfully', async () => {
      const mockResponse: DTOs.ValidationResponseDto = {
        valid: true,
        reason: 'Available',
      };
      mockValidationService.validateSocial.mockResolvedValue(mockResponse);
      const result = await controller.validateSocial('social123', 'google');
      expect(mockValidationService.validateSocial).toHaveBeenCalledWith(
        'google',
        'social123',
      );
      expect(result).toEqual(mockResponse);
    });

    it('should throw BadRequestException if socialUserId or socialProvider is not provided', async () => {
      await expect(controller.validateSocial('', 'google')).rejects.toThrow(
        BadRequestException,
      );
      await expect(controller.validateSocial('social123', '')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  // --- Authenticated Endpoints ---
  describe('findUsers', () => {
    it('should allow admin to find users and return mapped DTOs', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      const query: DTOs.UserSearchQueryDto = { limit: 10, offset: 0 };
      const mockRawUsers = [createMockUserModel(3, 'foundUser') as UserModel];
      mockUserService.findUsers.mockResolvedValue(mockRawUsers);

      const result = await controller.findUsers(query, mockReq);
      expect(mockUserService.findUsers).toHaveBeenCalledWith(query);
      expect(result.length).toBe(1);
      expect(result[0].id).toBe('3'); // mapUserToDto converts user_id (Decimal) to string id
      expect(result[0].handle).toBe('foundUser');
    });

    it('should forbid non-admin from finding users', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      await expect(controller.findUsers({}, mockReq)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('findUserById', () => {
    const targetUserIdStr = '3';
    const targetUserIdNum = 3;
    const mockRawUser = createMockUserModel(
      targetUserIdNum,
      'targetUser',
    ) as UserModel;

    it('should allow admin to find any user by ID and return mapped DTO', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      mockUserService.findUserById.mockResolvedValue(mockRawUser);

      const result = await controller.findUserById(targetUserIdStr, mockReq);
      expect(mockUserService.findUserById).toHaveBeenCalledWith(
        targetUserIdNum,
      );
      expect(result.id).toBe(targetUserIdStr);
      expect(result.handle).toBe('targetUser');
    });

    it('should throw BadRequestException for invalid user ID format', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      await expect(controller.findUserById('abc', mockReq)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('registerUser', () => {
    it('should register a new user and return mapped DTO', async () => {
      const createUserDto: DTOs.CreateUserBodyDto = {
        param: {
          handle: 'newuser',
          email: 'new@example.com',
          firstName: 'New',
          lastName: 'User',
          credential: { password: 'Password123!' },
        },
      };
      const mockRegisteredRawUser = createMockUserModel(
        10,
        'newuser',
        'new@example.com',
        'Pending Activation',
      ) as UserModel;
      mockUserService.registerUser.mockResolvedValue(mockRegisteredRawUser);

      const result = await controller.registerUser(createUserDto);
      expect(mockUserService.registerUser).toHaveBeenCalledWith(createUserDto);
      expect(result.id).toBe('10');
      expect(result.handle).toBe('newuser');
    });

    it('should throw if param is missing in DTO', async () => {
      const createUserDto = {} as DTOs.CreateUserBodyDto;
      await expect(controller.registerUser(createUserDto)).rejects.toThrow(
        TypeError,
      );
    });
  });

  describe('updateBasicInfo', () => {
    const userIdToUpdate = mockRegularUser.userId;
    const updateUserDto: DTOs.UpdateUserBodyDto = {
      param: { firstName: 'UpdatedFirst', lastName: 'UpdatedLast' },
    };
    const mockUpdatedRawUser = createMockUserModel(
      parseInt(userIdToUpdate, 10),
      mockRegularUser.handle,
      mockRegularUser.email,
      'Active',
      'UpdatedFirst',
      'UpdatedLast',
    ) as UserModel;

    it('should allow user to update their own basic info', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      mockUserService.updateBasicInfo.mockResolvedValue(mockUpdatedRawUser);

      const result = await controller.updateBasicInfo(
        userIdToUpdate,
        updateUserDto,
        mockReq,
      );
      expect(mockUserService.updateBasicInfo).toHaveBeenCalledWith(
        userIdToUpdate,
        updateUserDto,
        mockRegularUser,
      );
      expect(result.firstName).toBe('UpdatedFirst');
    });
  });

  describe('deleteUser', () => {
    it('should throw HttpException with 501 for admin user', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      await expect(controller.deleteUser('5', mockReq)).rejects.toThrow(
        new HttpException('Not Implemented', HttpStatus.NOT_IMPLEMENTED),
      );
    });
  });

  // --- SSO Login Endpoints ---
  describe('createSSOUserLogin', () => {
    const userId = 123;
    const createSSODto: DTOs.CreateUpdateSSOBodyDto = {
      param: { provider: 'google', userId: 'google123', name: 'Google User' },
    };
    const mockProfileResponse: DTOs.UserProfileDto = {
      provider: 'google',
      userId: 'google123',
      name: 'Google User',
    };

    it('should allow admin to link SSO profile', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      mockUserProfileService.createSSOUserLogin.mockResolvedValue(
        mockProfileResponse,
      );

      const result = await controller.createSSOUserLogin(
        userId,
        createSSODto,
        mockReq,
      );
      expect(mockUserProfileService.createSSOUserLogin).toHaveBeenCalledWith(
        userId,
        createSSODto.param,
        mockAdminUser.userId,
      );
      expect(result).toEqual(mockProfileResponse);
    });

    it('should throw BadRequestException if param is missing', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      await expect(
        controller.createSSOUserLogin(
          userId,
          {} as DTOs.CreateUpdateSSOBodyDto,
          mockReq,
        ),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('updateSSOUserLogin', () => {
    const userId = parseInt(mockRegularUser.userId, 10);
    const updateSSODto: DTOs.CreateUpdateSSOBodyDto = {
      param: { provider: 'okta', userId: 'okta123', name: 'Okta User Updated' },
    };
    const mockProfileResponse: DTOs.UserProfileDto = { ...updateSSODto.param };

    beforeEach(() => {
      const mockExistingUser = createMockUserModel(
        userId,
        'userHandle',
      ) as UserModel;
      mockUserService.findUserById.mockResolvedValue(mockExistingUser);
      mockUserProfileService.updateSSOUserLogin.mockResolvedValue(
        mockProfileResponse,
      );
    });

    it('should allow user to update their own SSO login', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      const result = await controller.updateSSOUserLogin(
        userId,
        updateSSODto,
        mockReq,
      );
      expect(mockUserService.findUserById).toHaveBeenCalledWith(userId);
      expect(mockUserProfileService.updateSSOUserLogin).toHaveBeenCalledWith(
        userId,
        updateSSODto.param,
        mockRegularUser.userId.toString(),
      );
      expect(result).toEqual(mockProfileResponse);
    });

    it('should throw TypeError if param is missing in DTO', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      await expect(
        controller.updateSSOUserLogin(
          userId,
          {} as DTOs.CreateUpdateSSOBodyDto,
          mockReq,
        ),
      ).rejects.toThrow(TypeError);
    });
  });

  describe('deleteSSOUserLogin', () => {
    const userId = parseInt(mockRegularUser.userId, 10);
    const ssoUserId = 'external123';

    beforeEach(() => {
      const mockExistingUser = createMockUserModel(
        userId,
        'userHandle',
      ) as UserModel;
      mockUserService.findUserById.mockResolvedValue(mockExistingUser);
      mockUserProfileService.deleteSSOUserLogin.mockResolvedValue(undefined);
    });

    it('should allow user to delete their own SSO login (by provider name)', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      const query: DTOs.DeleteSSOUserLoginQueryDto = {
        provider: 'myProvider',
        ssoUserId,
      };

      await controller.deleteSSOUserLogin(userId, query, mockReq);
      expect(mockUserProfileService.deleteSSOUserLogin).toHaveBeenCalledWith(
        userId,
        'myProvider',
        ssoUserId,
        mockRegularUser.userId.toString(),
      );
    });

    it('should lookup provider name if only providerId is given', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      const query: DTOs.DeleteSSOUserLoginQueryDto = {
        providerId: 1,
        ssoUserId,
      };
      const mockProviderRecord: SsoLoginProviderModel = {
        sso_login_provider_id: new Prisma.Decimal(1),
        name: 'resolvedProvider',
        type: 'OIDC',
        identify_email_enabled: true,
        identify_handle_enabled: false,
      };

      prismaOltp.sso_login_provider.findUnique.mockResolvedValue(
        mockProviderRecord,
      );

      await controller.deleteSSOUserLogin(userId, query, mockReq);
      expect(prismaOltp.sso_login_provider.findUnique).toHaveBeenCalledWith({
        where: { sso_login_provider_id: 1 },
      });
      expect(mockUserProfileService.deleteSSOUserLogin).toHaveBeenCalledWith(
        userId,
        'resolvedProvider',
        ssoUserId,
        mockAdminUser.userId.toString(),
      );
    });

    it('should throw BadRequestException if ssoUserId is missing from query', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      const query = { provider: 'myProvider' } as any;
      await expect(
        controller.deleteSSOUserLogin(userId, query, mockReq),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('getSSOUserLogins', () => {
    it('should allow admin to get SSO logins for any user', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      const mockProfiles: DTOs.UserProfileDto[] = [
        { provider: 'google', userId: 'google123', name: 'Test' },
      ];
      mockUserProfileService.findSSOUserLoginsByUserId.mockResolvedValue(
        mockProfiles,
      );
      const result = await controller.getSSOUserLogins(123, mockReq);
      expect(result).toEqual(mockProfiles);
    });
  });

  // --- External Profiles ---
  describe('addExternalProfile', () => {
    const userId = 123;
    const createProfileDto: DTOs.CreateProfileBodyDto = {
      param: { provider: 'github', userId: 'github123', name: 'GitHub User' },
    };
    const mockProfileResponse: DTOs.UserProfileDto = {
      ...createProfileDto.param,
    };

    it('should allow admin to add external profile', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      mockUserProfileService.addExternalProfile.mockResolvedValue(
        mockProfileResponse,
      );
      const result = await controller.addExternalProfile(
        userId,
        createProfileDto,
        mockReq,
      );
      expect(mockUserProfileService.addExternalProfile).toHaveBeenCalledWith(
        userId,
        createProfileDto.param,
        mockAdminUser.userId,
      );
      expect(result).toEqual(mockProfileResponse);
    });
    it('should throw BadRequestException if param is missing from DTO', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      await expect(
        controller.addExternalProfile(
          userId,
          {} as DTOs.CreateProfileBodyDto,
          mockReq,
        ),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('getAllExternalProfiles', () => {
    const targetUserId = parseInt(mockRegularUser.userId, 10);
    const mockProfiles: DTOs.UserProfileDto[] = [
      { provider: 'linkedin', userId: 'li456', name: 'LinkedIn User' },
    ];

    it('should allow user to get their own external profiles', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      mockUserProfileService.findAllUserProfiles.mockResolvedValue(
        mockProfiles,
      );
      const result = await controller.getAllExternalProfiles(
        targetUserId,
        mockReq,
      );
      expect(mockUserProfileService.findAllUserProfiles).toHaveBeenCalledWith(
        targetUserId,
      );
      expect(result).toEqual(mockProfiles);
    });
  });

  describe('deleteExternalProfile', () => {
    it('should allow admin to delete external profile by provider name', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      mockUserProfileService.deleteExternalProfile.mockResolvedValue(undefined);
      await controller.deleteExternalProfile(123, 'github', mockReq);
      expect(mockUserProfileService.deleteExternalProfile).toHaveBeenCalledWith(
        123,
        'github',
      );
    });
  });

  // --- Auth0 Custom DB/Rules/Actions ---
  describe('auth0Login', () => {
    it('should authenticate user for Auth0', async () => {
      const loginData = { handleOrEmail: 'testuser', password: 'password123' };
      mockAuthFlowService.authenticateForAuth0.mockResolvedValue({
        id: '1',
        email: 'test@test.com',
      });
      await controller.auth0Login(loginData);
      expect(mockAuthFlowService.authenticateForAuth0).toHaveBeenCalledWith(
        loginData.handleOrEmail,
        loginData.password,
      );
    });
    it('should throw BadRequestException if params missing', async () => {
      await expect(controller.auth0Login({})).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('auth0Roles', () => {
    it('should get user profile and roles for Auth0 with email', async () => {
      const rolesData = { email: 'test@example.com' };
      mockAuthFlowService.getUserProfileForAuth0.mockResolvedValue({
        userId: '1',
        roles: ['User'],
      });
      await controller.auth0Roles(rolesData);
      expect(mockAuthFlowService.getUserProfileForAuth0).toHaveBeenCalledWith(
        rolesData.email,
      );
    });
    it('should throw BadRequestException if params missing', async () => {
      await expect(controller.auth0Roles({})).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('auth0ChangePassword', () => {
    it('should change password for Auth0', async () => {
      const changePasswordData = {
        email: 'test@example.com',
        password: 'newPassword123',
      };
      mockAuthFlowService.changePasswordFromAuth0.mockResolvedValue({
        message: 'Password changed',
      });
      await controller.auth0ChangePassword(changePasswordData);
      expect(mockAuthFlowService.changePasswordFromAuth0).toHaveBeenCalledWith(
        changePasswordData.email,
        changePasswordData.password,
      );
    });
    it('should throw BadRequestException if params missing', async () => {
      await expect(controller.auth0ChangePassword({})).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  // --- Password/Activation Flows (Public) ---
  describe('activateUser', () => {
    const activateUserDto: DTOs.ActivateUserBodyDto = {
      param: { userId: 10, otp: '123456', resendToken: 'resend123' },
    };
    const mockActivatedRawUser = createMockUserModel(
      10,
      'activated',
      'act@example.com',
      'Active',
    ) as UserModel;

    it('should activate user and return mapped DTO', async () => {
      mockAuthFlowService.activateUser.mockResolvedValue(mockActivatedRawUser);
      const result = await controller.activateUser(activateUserDto);
      expect(mockAuthFlowService.activateUser).toHaveBeenCalledWith(
        activateUserDto,
      );
      expect(result.id).toBe('10');
      expect(result.handle).toBe('activated');
    });

    it('should throw if activateUser does not return a user object suitable for mapping', async () => {
      mockAuthFlowService.activateUser.mockResolvedValue({
        message: 'Some info message, no user',
      });
      await expect(controller.activateUser(activateUserDto)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('resendActivationEmail', () => {
    const resendDto: DTOs.UserOtpDto = { userId: 10, resendToken: 'token123' };
    it('should resend activation email', async () => {
      mockAuthFlowService.requestResendActivation.mockResolvedValue({
        message: 'Activation email resent',
      });
      const result = await controller.resendActivationEmail(resendDto);
      expect(mockAuthFlowService.requestResendActivation).toHaveBeenCalledWith(
        resendDto,
      );
      expect(result.message).toContain('Activation email resent');
    });
  });

  // --- Profile Updates (Require Auth) ---
  describe('updateHandle', () => {
    const userIdToUpdate = '3';
    const updateHandleDto: DTOs.UpdateHandleBodyDto = {
      param: { handle: 'newAdminHandle' },
    };
    const mockUpdatedRawUser = createMockUserModel(
      parseInt(userIdToUpdate, 10),
      'newAdminHandle',
    ) as UserModel;

    it('should allow admin to update handle', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      mockUserService.updateHandle.mockResolvedValue(mockUpdatedRawUser);
      const result = await controller.updateHandle(
        userIdToUpdate,
        updateHandleDto,
        mockReq,
      );
      expect(mockUserService.updateHandle).toHaveBeenCalledWith(
        userIdToUpdate,
        updateHandleDto.param.handle,
        mockAdminUser,
      );
      expect(result.handle).toBe('newAdminHandle');
    });
    it('should throw BadRequestException if param.handle is missing', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      await expect(
        controller.updateHandle(userIdToUpdate, { param: {} } as any, mockReq),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('updatePrimaryEmail (by Admin)', () => {
    const userIdToUpdate = '3';
    const updateEmailDto: DTOs.UpdateEmailBodyDto = {
      param: { email: 'newadmin@example.com' },
    };
    const mockUpdatedRawUser = createMockUserModel(
      parseInt(userIdToUpdate, 10),
      'adminHandle',
      'newadmin@example.com',
    ) as UserModel;

    it('should allow admin to update primary email', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      mockUserService.updatePrimaryEmail.mockResolvedValue(mockUpdatedRawUser);
      const result = await controller.updatePrimaryEmail(
        userIdToUpdate,
        updateEmailDto,
        mockReq,
      );
      expect(mockUserService.updatePrimaryEmail).toHaveBeenCalledWith(
        userIdToUpdate,
        updateEmailDto.param.email,
        mockAdminUser,
      );
    });
    it('should throw BadRequestException if param.email is missing', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      await expect(
        controller.updatePrimaryEmail(
          userIdToUpdate,
          { param: {} } as any,
          mockReq,
        ),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('getOneTimeToken', () => {
    it('should get a one-time token successfully', async () => {
      const tokenData = { userId: '2', password: 'password123' };
      mockAuthFlowService.generateOneTimeToken.mockResolvedValue('ott123xyz');
      const result = await controller.getOneTimeToken(tokenData);
      expect(result.token).toBe('ott123xyz');
    });
    it('should throw BadRequestException if userId or password missing', async () => {
      await expect(
        controller.getOneTimeToken({ userId: '2' } as any),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('updateEmailWithOneTimeToken', () => {
    it('should update email using one-time token', async () => {
      const mockReq = createMockRequest(undefined, {
        authorization: 'Bearer ott123xyz',
      });
      mockAuthFlowService.updateEmailWithOneTimeToken.mockResolvedValue(
        undefined,
      );
      const result = await controller.updateEmailWithOneTimeToken(
        '2',
        'new@example.com',
        mockReq,
      );
      expect(result.message).toContain('Email updated successfully');
    });
    it('should throw UnauthorizedException if token is missing', async () => {
      const mockReq = createMockRequest(undefined, {});
      await expect(
        controller.updateEmailWithOneTimeToken('2', 'new@example.com', mockReq),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('updateStatus', () => {
    const userIdToUpdate = '3';
    const updateStatusDto: DTOs.UpdateStatusBodyDto = {
      param: { status: 'Inactive' },
    };
    const mockUpdatedRawUser = createMockUserModel(
      parseInt(userIdToUpdate, 10),
      'somehandle',
      'some@email.com',
      'Inactive',
    ) as UserModel;

    it('should allow admin to update status', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      mockUserService.updateStatus.mockResolvedValue(mockUpdatedRawUser);
      const result = await controller.updateStatus(
        userIdToUpdate,
        updateStatusDto,
        mockReq,
      );
      expect(mockUserService.updateStatus).toHaveBeenCalledWith(
        userIdToUpdate,
        updateStatusDto.param.status,
        mockAdminUser,
      );
      expect(result.status).toBe('Inactive');
    });
    it('should throw BadRequestException if param.status is missing', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      await expect(
        controller.updateStatus(userIdToUpdate, { param: {} } as any, mockReq),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // --- Roles ---
  describe('updatePrimaryRole', () => {
    const updateRoleDto: DTOs.UpdatePrimaryRoleBodyDto = {
      param: { primaryRole: 'Manager' },
    };

    it('should allow authenticated user to update their own primary role', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      mockUserService.updatePrimaryRole.mockResolvedValue(undefined);
      const result = await controller.updatePrimaryRole(mockReq, updateRoleDto);
      expect(mockUserService.updatePrimaryRole).toHaveBeenCalledWith(
        parseInt(mockRegularUser.userId, 10),
        updateRoleDto.param.primaryRole,
        parseInt(mockRegularUser.userId, 10),
      );
      expect(result.message).toContain('Primary role updated successfully');
    });
    it('should throw BadRequestException if param.primaryRole is missing', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      await expect(
        controller.updatePrimaryRole(mockReq, { param: {} } as any),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // --- 2FA / DICE Endpoints ---
  describe('getUser2faStatus', () => {
    it('should allow user to get their own 2FA status', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      const mockStatus: DTOs.User2faDto = {
        mfaEnabled: true,
        diceEnabled: false,
      };
      mockTwoFactorAuthService.getUser2faStatus.mockResolvedValue(mockStatus);
      const result = await controller.getUser2faStatus(
        mockRegularUser.userId,
        mockReq,
      );
      expect(result).toEqual(mockStatus);
    });
  });

  describe('updateUser2faStatus', () => {
    const updateDto: DTOs.UpdateUser2faBodyDto = {
      param: { mfaEnabled: true, diceEnabled: false },
    };
    const mockUpdatedStatus: DTOs.User2faDto = {
      mfaEnabled: true,
      diceEnabled: false,
    };

    it('should allow user to update their own 2FA status', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      mockTwoFactorAuthService.updateUser2faStatus.mockResolvedValue(
        mockUpdatedStatus,
      );
      const result = await controller.updateUser2faStatus(
        mockRegularUser.userId,
        updateDto,
        mockReq,
      );
      expect(mockTwoFactorAuthService.updateUser2faStatus).toHaveBeenCalledWith(
        mockRegularUser.userId,
        updateDto.param,
        mockRegularUser,
      );
      expect(result).toEqual(mockUpdatedStatus);
    });
    it('should throw BadRequestException if param is missing', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      await expect(
        controller.updateUser2faStatus(
          mockRegularUser.userId,
          {} as any,
          mockReq,
        ),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('getDiceConnection', () => {
    it('should allow user to get their own DICE connection', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      });
      const mockResponse: DTOs.DiceConnectionResponseDto = {
        diceEnabled: true,
        connection: 'dice-url',
        accepted: false,
      };
      mockTwoFactorAuthService.getDiceConnection.mockResolvedValue(
        mockResponse,
      );
      const result = await controller.getDiceConnection(
        mockRegularUser.userId,
        mockReq,
      );
      expect(result).toEqual(mockResponse);
    });
  });

  describe('handleDiceWebhook', () => {
    it('should handle DICE webhook successfully', async () => {
      const diceDto: DTOs.DiceStatusWebhookBodyDto = {
        event: 'completed',
        connectionId: 'conn123',
        emailId: 'test@dice.com',
      }; // Corrected: removed userId
      mockTwoFactorAuthService.handleDiceWebhook.mockResolvedValue({
        message: 'Webhook processed',
      });
      const result = await controller.handleDiceWebhook(
        diceDto,
        'valid-api-key',
      );
      expect(mockTwoFactorAuthService.handleDiceWebhook).toHaveBeenCalledWith(
        diceDto,
      );
      expect(result.message).toBe('Webhook processed');
    });
  });

  describe('sendOtp (2FA)', () => {
    const sendOtpDto: DTOs.SendOtpBodyDto = { param: { userId: 123 } };
    const mockOtpResponse: DTOs.UserOtpResponseDto = {
      resendToken: 'resendXYZ',
    }; // Corrected: removed message
    it('should send 2FA OTP', async () => {
      mockTwoFactorAuthService.sendOtpFor2fa.mockResolvedValue(mockOtpResponse);
      const result = await controller.sendOtp(sendOtpDto);
      expect(mockTwoFactorAuthService.sendOtpFor2fa).toHaveBeenCalledWith(
        sendOtpDto.param.userId!.toString(),
      );
      expect(result).toEqual(mockOtpResponse);
    });
    it('should throw BadRequestException if param.userId is missing', async () => {
      await expect(controller.sendOtp({ param: {} } as any)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('resendOtpEmail (2FA)', () => {
    const resendDto: DTOs.ResendOtpEmailBodyDto = {
      param: { resendToken: 'tokenXYZ' },
    };
    it('should resend 2FA OTP email', async () => {
      mockTwoFactorAuthService.resendOtpEmailFor2fa.mockResolvedValue({
        message: '2FA OTP resent',
      });
      const result = await controller.resendOtpEmail(resendDto);
      expect(
        mockTwoFactorAuthService.resendOtpEmailFor2fa,
      ).toHaveBeenCalledWith(resendDto.param.resendToken);
      expect(result.message).toContain('2FA OTP resent');
    });
    it('should throw BadRequestException if param.resendToken is missing', async () => {
      await expect(
        controller.resendOtpEmail({ param: {} } as any),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('checkOtp (2FA)', () => {
    const checkOtpDto: DTOs.CheckOtpBodyDto = {
      param: { userId: 123, otp: '654321' },
    };
    const mockLoginCompletion = { accessToken: 'jwt.token.here' };
    it('should check 2FA OTP and complete login', async () => {
      mockTwoFactorAuthService.checkOtpAndCompleteLogin.mockResolvedValue(
        mockLoginCompletion,
      );
      const result = await controller.checkOtp(checkOtpDto);
      expect(
        mockTwoFactorAuthService.checkOtpAndCompleteLogin,
      ).toHaveBeenCalledWith(
        checkOtpDto.param.userId!.toString(),
        checkOtpDto.param.otp,
      );
      expect(result).toEqual(mockLoginCompletion);
    });
    it('should throw BadRequestException if param.userId or param.otp is missing', async () => {
      await expect(
        controller.checkOtp({ param: { userId: 1 } } as any),
      ).rejects.toThrow(BadRequestException);
      await expect(
        controller.checkOtp({ param: { otp: '111' } } as any),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // --- Other Endpoints ---
  describe('getAchievements', () => {
    it('should allow admin to get achievements', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      });
      const mockAchievements: DTOs.AchievementDto[] = [
        {
          achievement_type_id: 1,
          achievement_desc: 'Winner',
          date: new Date(),
        },
      ];
      mockUserService.getAchievements.mockResolvedValue(mockAchievements);
      const result = await controller.getAchievements('3', mockReq);
      expect(result).toEqual(mockAchievements);
    });
  });

  // Test internal getAuthenticatedUser behavior via an endpoint
  describe('getAuthenticatedUser internal behavior', () => {
    it('should throw UnauthorizedException via endpoint if req.user is undefined', async () => {
      const mockReq = createMockRequest(undefined, {
        authorization: 'Bearer token-that-results-in-no-user',
      });
      const updateRoleDto: DTOs.UpdatePrimaryRoleBodyDto = {
        param: { primaryRole: 'Test' },
      };
      await expect(
        controller.updatePrimaryRole(mockReq, updateRoleDto),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw InternalServerErrorException via endpoint if req.user is incomplete', async () => {
      const mockReq = createMockRequest({ userId: '3' } as AuthenticatedUser, {
        authorization: 'Bearer incomplete-user-token',
      });
      const updateRoleDto: DTOs.UpdatePrimaryRoleBodyDto = {
        param: { primaryRole: 'Test' },
      };
      await expect(
        controller.updatePrimaryRole(mockReq, updateRoleDto),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });
});
