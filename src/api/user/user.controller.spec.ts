import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller'; // mapUserToDto is not exported, will test output structure
import { UserService } from './user.service';
import { UserProfileService } from './user-profile.service';
import { AuthFlowService } from './auth-flow.service';
import { TwoFactorAuthService } from './two-factor-auth.service';
import { ValidationService } from './validation.service';
import { RoleService } from '../role/role.service';
import { ConfigService } from '@nestjs/config'; // Often needed implicitly
import { CACHE_MANAGER } from '@nestjs/cache-manager'; // If caching is used
import { AuthGuard } from '@nestjs/passport';
import {
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import * as DTOs from '../../dto/user/user.dto';
import { user as UserModel } from '@prisma/client-common-oltp';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';

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
  authenticateForAuth0: jest.fn(),
  getUserProfileForAuth0: jest.fn(),
  changePasswordFromAuth0: jest.fn(),
  resetPassword: jest.fn(),
  initiatePasswordReset: jest.fn(),
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
  sendOtpFor2fa: jest.fn(),
  resendOtpEmailFor2fa: jest.fn(),
  checkOtpAndCompleteLogin: jest.fn(),
  isValidDiceApiKey: jest.fn(), // Added for webhook test
};

const mockValidationService = {
  validateHandle: jest.fn(),
  validateEmail: jest.fn(),
  validateSocial: jest.fn(),
};

const mockRoleService = {
  updateUserPrimaryRole: jest.fn(),
};

const mockConfigService = {
  get: jest.fn(),
};

const mockPrismaClientCommonOltp = {
  // Add mock implementations for any prismaOltp methods directly used by UserController
  // For now, an empty object or specific mocks if known.
  // Example:
  // user_sso_login: {
  //   findUnique: jest.fn(),
  //   create: jest.fn(),
  // },
  // sso_login_provider: {
  //   findUnique: jest.fn(),
  // }
};

const mockCacheManager = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
};

// Mock Authenticated Users
const mockAdminUser: AuthenticatedUser = {
  userId: '1',
  roles: ['Administrator'],
  scopes: ['read:all', 'write:all'],
  isAdmin: true,
  payload: { sub: 'auth0|admin' },
  handle: 'admin',
  email: 'admin@example.com',
};

const mockRegularUser: AuthenticatedUser = {
  userId: '2',
  roles: ['User'],
  scopes: ['read:self'],
  isAdmin: false,
  payload: { sub: 'auth0|user2' },
  handle: 'user2',
  email: 'user2@example.com',
};

// --- Helper to create mock request & response ---
const createMockRequest = (
  user?: AuthenticatedUser,
  headers?: Record<string, string>,
  cookies?: Record<string, string>,
): Partial<Request> => ({
  user: user,
  headers: { host: 'localhost', ...headers },
  cookies: cookies || {},
  query: {},
  body: {},
});

const createMockResponse = (): Partial<Response> & {
  cookie: jest.Mock;
  clearCookie: jest.Mock;
  redirect: jest.Mock;
  status: jest.Mock;
  json: jest.Mock;
  send: jest.Mock;
} => {
  const res: Partial<Response> & {
    cookie: jest.Mock;
    clearCookie: jest.Mock;
    redirect: jest.Mock;
    status: jest.Mock;
    json: jest.Mock;
    send: jest.Mock;
  } = {} as any;
  res.cookie = jest.fn().mockReturnThis();
  res.clearCookie = jest.fn().mockReturnThis();
  res.redirect = jest.fn().mockReturnThis();
  res.status = jest.fn().mockReturnThis();
  res.json = jest.fn().mockReturnThis();
  res.send = jest.fn().mockReturnThis();
  return res;
};

describe('UserController', () => {
  let controller: UserController;

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
        { provide: ConfigService, useValue: mockConfigService }, // Default mock
        { provide: CACHE_MANAGER, useValue: mockCacheManager }, // Default mock
        {
          provide: PRISMA_CLIENT_COMMON_OLTP,
          useValue: mockPrismaClientCommonOltp,
        },
      ],
    })
      .overrideGuard(AuthGuard('jwt'))
      .useValue({
        canActivate: (context) => {
          const req = context.switchToHttp().getRequest();
          if (req.headers.authorization === 'Bearer admin-token') {
            req.user = mockAdminUser;
          } else if (req.headers.authorization === 'Bearer user-token') {
            req.user = mockRegularUser;
          } else {
            // For public routes or to test unauthenticated access explicitly
            req.user = undefined;
          }
          return true;
        },
      })
      .compile();

    controller = module.get<UserController>(UserController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  // --- Core User Endpoints Tests ---
  describe('findUsers', () => {
    it('should allow admin to find users', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      const query: DTOs.UserSearchQueryDto = { limit: 10, offset: 0 };
      const mockUsers = [
        { user_id: 1, handle: 'test1' } as unknown as UserModel,
      ];
      mockUserService.findUsers.mockResolvedValue(mockUsers);

      const result = await controller.findUsers(query, mockReq);
      expect(mockUserService.findUsers).toHaveBeenCalledWith(query);
      expect(result.length).toBe(1);
      expect(result[0].handle).toBe('test1');
    });

    it('should forbid non-admin from finding users', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      }) as Request;
      const query: DTOs.UserSearchQueryDto = {};
      await expect(controller.findUsers(query, mockReq)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('findUserById', () => {
    it('should allow admin to find any user by ID', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      const targetUserId = '3';
      const mockUser = {
        user_id: 3,
        handle: 'targetUser',
      } as unknown as UserModel;
      mockUserService.findUserById.mockResolvedValue(mockUser);

      const result = await controller.findUserById(targetUserId, mockReq);
      expect(mockUserService.findUserById).toHaveBeenCalledWith(3);
      expect(result.handle).toBe('targetUser');
    });

    it('should allow regular user to find their own profile', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      }) as Request;
      const targetUserId = mockRegularUser.userId; // '2'
      const mockUser = {
        user_id: 2,
        handle: mockRegularUser.handle,
      } as unknown as UserModel;
      mockUserService.findUserById.mockResolvedValue(mockUser);

      const result = await controller.findUserById(targetUserId, mockReq);
      expect(mockUserService.findUserById).toHaveBeenCalledWith(2);
      expect(result.handle).toBe(mockRegularUser.handle);
    });

    it("should forbid regular user from finding another user's profile", async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      }) as Request;
      const targetUserId = '3'; // Different from mockRegularUser.userId
      await expect(
        controller.findUserById(targetUserId, mockReq),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw NotFoundException if user not found', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      const targetUserId = '999';
      mockUserService.findUserById.mockRejectedValue(new NotFoundException());
      await expect(
        controller.findUserById(targetUserId, mockReq),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException for invalid user ID format', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      await expect(controller.findUserById('abc', mockReq)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('registerUser', () => {
    it('should register a new user', async () => {
      const createUserDto: DTOs.CreateUserBodyDto = {
        param: {
          handle: 'newuser',
          email: 'new@example.com',
          firstName: 'New',
          lastName: 'User',
          credential: { password: 'Password123!' },
        },
      };
      const mockRegisteredUser = {
        user_id: 10,
        handle: 'newuser',
      } as unknown as UserModel;
      mockUserService.registerUser.mockResolvedValue(mockRegisteredUser);

      const result = await controller.registerUser(createUserDto);
      expect(mockUserService.registerUser).toHaveBeenCalledWith(createUserDto);
      expect(result.handle).toBe('newuser');
      expect(result.id).toBe('10');
    });
  });

  describe('deleteUser', () => {
    it('should throw HttpException with 501 status for deleteUser', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      const userIdToDelete = '5';
      // The controller method itself throws, so the service method mock might not be strictly necessary
      // unless we want to ensure it's NOT called.
      // mockUserService.deleteUser.mockResolvedValue(undefined);

      try {
        await controller.deleteUser(userIdToDelete, mockReq);
        fail('Expected deleteUser to throw HttpException, but it did not.');
      } catch (error) {
        expect(error).toBeInstanceOf(HttpException);
        expect(error.getStatus()).toBe(HttpStatus.NOT_IMPLEMENTED); // 501

        const response = error.getResponse();
        if (typeof response === 'string') {
          // If the response is a simple string, check if it's the default status message
          expect(response).toBe('Not Implemented');
        } else if (
          typeof response === 'object' &&
          response !== null &&
          'message' in response
        ) {
          // If the response is an object, check its message property
          // Allow either the custom message or the default status message
          expect(response.message).toMatch(
            /Not Implemented|This feature is not implemented as per legacy system behavior./,
          );
        } else {
          // Fallback for other structures, primarily check error.message
          expect(error.message).toMatch(
            /Not Implemented|This feature is not implemented as per legacy system behavior./,
          );
        }
      }
      // Ensure the service method was NOT called
      expect(mockUserService.deleteUser).not.toHaveBeenCalled();
    });

    it('should forbid non-admin from attempting to delete a user', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      }) as Request;
      const userIdToDelete = '5';
      await expect(
        controller.deleteUser(userIdToDelete, mockReq),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  // --- SSO Login Endpoints Tests ---
  describe('createSSOUserLogin', () => {
    it('should allow admin to link SSO profile', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      const userId = 123;
      // param is UserProfileDto, which doesn't have isPrimary.
      // The service UserProfileService.createSSOUserLogin expects a second arg `ssoDto: UserProfileDto & { isPrimary?: boolean }`
      // This means the controller passes a UserProfileDto, and the service handles optional isPrimary.
      const createSSODtoParam: DTOs.UserProfileDto = {
        provider: 'google',
        userId: 'google123',
        name: 'Google User',
      };
      const createSSODto: DTOs.CreateUpdateSSOBodyDto = {
        param: createSSODtoParam,
      };

      const mockProfile = {
        provider: 'google',
        userId: 'google123',
      } as DTOs.UserProfileDto;
      mockUserProfileService.createSSOUserLogin.mockResolvedValue(mockProfile);

      const result = await controller.createSSOUserLogin(
        userId,
        createSSODto,
        mockReq,
      );
      // The controller calls service with `createSSODto.param`. If service needs `isPrimary` it must handle it or have a default.
      expect(mockUserProfileService.createSSOUserLogin).toHaveBeenCalledWith(
        userId,
        createSSODto.param,
        mockAdminUser.userId,
      );
      expect(result).toEqual(mockProfile);
    });
    it('should throw BadRequestException if param is missing in createSSOUserLogin', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      const userId = 123;
      await expect(
        controller.createSSOUserLogin(userId, {} as any, mockReq),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // --- Auth0 Custom DB Endpoints Tests ---
  describe('auth0Login', () => {
    it('should call authFlowService.authenticateForAuth0', async () => {
      const loginData = { handleOrEmail: 'test', password: 'pass' };
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
    it('should throw BadRequestException if params missing for auth0Login', async () => {
      await expect(controller.auth0Login({})).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  // --- Password/Activation Flow Tests ---
  describe('resetPassword', () => {
    it('should call authFlowService.resetPassword', async () => {
      const resetDto: DTOs.ResetPasswordBodyDto = {
        param: {
          handle: 'testuser',
          credential: { resetToken: 'token123', password: 'NewPass!@#' },
        },
      };
      mockAuthFlowService.resetPassword.mockResolvedValue({
        message: 'Password has been reset successfully.',
      });
      const result = await controller.resetPassword(resetDto);
      expect(mockAuthFlowService.resetPassword).toHaveBeenCalledWith({
        handleOrEmail: 'testuser',
        resetToken: 'token123',
        newPassword: 'NewPass!@#',
      });
      expect(result.message).toContain('Password has been reset');
    });
    it('should throw BadRequestException if credential missing for resetPassword', async () => {
      const resetDto: DTOs.ResetPasswordBodyDto = {
        param: { handle: 'testuser' } as any,
      };
      await expect(controller.resetPassword(resetDto)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  // --- Validation Endpoint Tests ---
  describe('validateHandle', () => {
    it('should call validationService.validateHandle', async () => {
      const handle = 'testHandle';
      const response: DTOs.ValidationResponseDto = {
        valid: true,
        reason: 'Available',
      }; // Corrected: valid, not isValid
      mockValidationService.validateHandle.mockResolvedValue(response);
      const result = await controller.validateHandle(handle);
      expect(mockValidationService.validateHandle).toHaveBeenCalledWith(handle);
      expect(result).toEqual(response);
    });
    it('should throw BadRequestException if handle missing for validateHandle', async () => {
      await expect(controller.validateHandle(undefined as any)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  // --- 2FA/DICE Endpoint Tests ---
  describe('getUser2faStatus', () => {
    it('should allow admin to get 2FA status for any user', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      const targetUserId = '3';
      const mockStatus: DTOs.User2faDto = {
        mfaEnabled: true,
        diceEnabled: false,
      }; // Corrected: diceEnabled
      mockTwoFactorAuthService.getUser2faStatus.mockResolvedValue(mockStatus);

      const result = await controller.getUser2faStatus(targetUserId, mockReq);
      expect(mockTwoFactorAuthService.getUser2faStatus).toHaveBeenCalledWith(
        targetUserId,
      );
      expect(result).toEqual(mockStatus);
    });
  });

  describe('getDiceConnection', () => {
    it('should allow user to get their own DICE connection', async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      }) as Request;
      const mockResponse: DTOs.DiceConnectionResponseDto = {
        diceEnabled: true,
        connection: 'dice-url',
        accepted: false,
      }; // Corrected: connection, not connectionUrl
      mockTwoFactorAuthService.getDiceConnection.mockResolvedValue(
        mockResponse,
      );

      const result = await controller.getDiceConnection(
        mockRegularUser.userId,
        mockReq,
      );
      expect(mockTwoFactorAuthService.getDiceConnection).toHaveBeenCalledWith(
        mockRegularUser.userId,
        mockRegularUser,
      );
      expect(result).toEqual(mockResponse);
    });

    it("should forbid user from getting another user's DICE connection", async () => {
      const mockReq = createMockRequest(mockRegularUser, {
        authorization: 'Bearer user-token',
      }) as Request;
      await expect(
        controller.getDiceConnection('other-user-id', mockReq),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  // --- Other Endpoint Tests ---
  describe('getAchievements', () => {
    it('should allow admin to get achievements', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      const targetUserId = '3';
      const achievements: DTOs.AchievementDto[] = [
        {
          achievement_type_id: 1,
          achievement_desc: 'Winner',
          date: new Date(),
        },
      ]; // Corrected field names
      mockUserService.getAchievements.mockResolvedValue(achievements);

      const result = await controller.getAchievements(targetUserId, mockReq);
      expect(mockUserService.getAchievements).toHaveBeenCalledWith(
        parseInt(targetUserId, 10),
      );
      expect(result).toEqual(achievements);
    });
  });

  // Example of testing an endpoint that requires `param` in body
  describe('updateHandle', () => {
    it('should throw BadRequestException if param.handle is missing', async () => {
      const mockReq = createMockRequest(mockAdminUser, {
        authorization: 'Bearer admin-token',
      }) as Request;
      const updateDto: DTOs.UpdateHandleBodyDto = { param: {} } as any; // Missing handle
      await expect(
        controller.updateHandle('1', updateDto, mockReq),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
