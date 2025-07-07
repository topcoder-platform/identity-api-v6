import { Test, TestingModule } from '@nestjs/testing';
import { AuthFlowService } from './auth-flow.service';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import { UserService } from './user.service';
import { EventService } from '../../shared/event/event.service';
import { RoleService } from '../role/role.service';
import {
  BadRequestException,
  ForbiddenException,
  GoneException,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import {
  user as UserModel,
  email as EmailModel,
  security_user as SecurityUserModel,
} from '@prisma/client-common-oltp';
import { ActivateUserBodyDto, UserOtpDto } from '../../dto/user/user.dto';
import { RoleResponseDto } from 'src/dto/role/role.dto';
import {
  ACTIVATION_OTP_CACHE_PREFIX_KEY,
  ACTIVATION_OTP_EXPIRY_SECONDS,
} from './user.service'; // Constants from UserService
import { Decimal } from '@prisma/client/runtime/library';
import * as jwt from 'jsonwebtoken';
import * as CryptoJS from 'crypto-js';
import { v4 as uuidv4 } from 'uuid';

// Constants from AuthFlowService
const OTP_ACTIVATION_JWT_AUDIENCE = 'emailactivation';
const ONE_TIME_TOKEN_JWT_AUDIENCE = 'onetime_email_update';
const PASSWORD_RESET_TOKEN_CACHE_PREFIX = 'PWD_RESET_TOKEN';

// Null logger
const nullLogger = {
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  verbose: jest.fn(),
  fatal: jest.fn(),
  setLogLevels: jest.fn(),
};

// Mock dependent services and clients
const mockPrismaOltp = {
  user: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    update: jest.fn(),
  },
  email: {
    findFirst: jest.fn(),
    update: jest.fn(),
    create: jest.fn(),
  },
  security_user: {
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  $transaction: jest
    .fn()
    .mockImplementation(async (callback) =>
      Promise.resolve(callback(mockPrismaOltp)),
    ),
  $queryRaw: jest.fn(),
};

const mockCacheManager = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
};

const mockConfigService = {
  get: jest.fn((key: string, defaultValue?: any) => {
    const configValues = {
      JWT_SECRET: 'test-jwt-secret',
      LEGACY_BLOWFISH_KEY: 'dGVzdEJhc2U2NEtleQ==', // "testBase64Key"
      APP_DOMAIN: 'topcoder-test.com',
      SENDGRID_WELCOME_EMAIL_TEMPLATE_ID: 'd-welcome',
      SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID: 'd-resend-activation',
      DEFAULT_RESET_PASSWORD_URL_PREFIX: 'https://test.com/reset?token=',
      EVENT_DEFAULT_SENDER_EMAIL: 'noreply@topcoder-test.com',
      ACTIVATION_OTP_EXPIRY_SECONDS: ACTIVATION_OTP_EXPIRY_SECONDS, // from UserService
    };
    return configValues[key] !== undefined ? configValues[key] : defaultValue;
  }),
};

const mockUserService = {
  findUserByEmailOrHandle: jest.fn(),
  encodePasswordLegacy: jest.fn(),
  generateSSOToken: jest.fn(),
  checkEmailAvailabilityForUser: jest.fn(),
};

const mockEventService = {
  postEnvelopedNotification: jest.fn(),
  postDirectBusMessage: jest.fn(),
};

const mockRoleService = {
  findAll: jest.fn(),
};

// Mock external libraries
jest.mock('jsonwebtoken', () => ({
  verify: jest.fn(),
  sign: jest.fn(),
  TokenExpiredError: class TokenExpiredError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'TokenExpiredError';
    }
  },
}));
jest.mock('crypto-js', () => ({
  ...jest.requireActual('crypto-js'),
  Blowfish: {
    decrypt: jest.fn(),
  },
  enc: {
    ...jest.requireActual('crypto-js').enc,
    Base64: {
      ...jest.requireActual('crypto-js').enc.Base64,
      parse: jest.fn(),
    },
    Utf8: jest.requireActual('crypto-js').enc.Utf8,
  },
  mode: jest.requireActual('crypto-js').mode,
  pad: jest.requireActual('crypto-js').pad,
}));
jest.mock('uuid', () => ({
  v4: jest.fn(),
}));

// --- Helper Functions to Create Mock Models ---
const createMockUserModel = (input: Partial<UserModel>): UserModel => {
  const userId = input.user_id ? new Decimal(input.user_id) : new Decimal(1);
  const handle = input.handle || 'testuser';
  return {
    user_id: userId,
    handle: handle,
    handle_lower: handle.toLowerCase(),
    first_name: input.first_name || 'Test',
    last_name: input.last_name || 'User',
    create_date: input.create_date || new Date(),
    modify_date: input.modify_date || new Date(),
    last_login: input.last_login || null,
    status: input.status || 'U', // Default to Unverified for activation tests
    activation_code: input.activation_code || null,
    password: input.password || 'legacyPass',
    timezone_id: input.timezone_id || null,
    name_in_another_language: input.name_in_another_language || null,
    middle_name: input.middle_name || null,
    open_id: input.open_id || null,
    reg_source: input.reg_source || null,
    utm_source: input.utm_source || null,
    utm_medium: input.utm_medium || null,
    utm_campaign: input.utm_campaign || null,
    last_site_hit_date: input.last_site_hit_date || null,
    ...input,
  };
};
const createMockEmailModel = (input: Partial<EmailModel>): EmailModel => {
  return {
    email_id: input.email_id || new Decimal(101),
    user_id: input.user_id ? new Decimal(input.user_id) : new Decimal(1),
    email_type_id: input.email_type_id || new Decimal(1),
    address: input.address || 'primary@example.com',
    create_date: input.create_date || new Date(),
    modify_date: input.modify_date || new Date(),
    primary_ind:
      input.primary_ind === undefined
        ? new Decimal(1)
        : new Decimal(input.primary_ind),
    status_id:
      input.status_id === undefined
        ? new Decimal(2)
        : new Decimal(input.status_id), // Default to Unverified
    ...input,
  };
};
const createMockSecurityUserModel = (
  input: Partial<SecurityUserModel>,
): SecurityUserModel => {
  return {
    login_id: input.login_id || new Decimal(1), // Corresponds to user_id from user table
    user_id: input.user_id || 'testuser', // This is the handle
    password: input.password || 'encryptedLegacyPassword',
    create_user_id: input.create_user_id || null,
    modify_date: input.modify_date || new Date(),
    ...input,
  };
};

describe('AuthFlowService', () => {
  let service: AuthFlowService;
  let prismaOltp: typeof mockPrismaOltp;
  let cacheManager: typeof mockCacheManager;
  let configService: typeof mockConfigService;
  let userService: jest.Mocked<UserService>;
  let eventService: jest.Mocked<EventService>;
  let roleService: jest.Mocked<RoleService>;
  let loggerErrorSpy: jest.SpyInstance;
  let loggerWarnSpy: jest.SpyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    loggerErrorSpy = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => {});
    loggerWarnSpy = jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => {});

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthFlowService,
        { provide: PRISMA_CLIENT_COMMON_OLTP, useValue: mockPrismaOltp },
        { provide: CACHE_MANAGER, useValue: mockCacheManager },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: UserService, useValue: mockUserService },
        { provide: EventService, useValue: mockEventService },
        { provide: RoleService, useValue: mockRoleService },
      ],
    })
      .setLogger(nullLogger)
      .compile();

    service = module.get<AuthFlowService>(AuthFlowService);
    prismaOltp = module.get(PRISMA_CLIENT_COMMON_OLTP);
    cacheManager = module.get(CACHE_MANAGER);
    configService = module.get(ConfigService);
    userService = module.get(UserService);
    eventService = module.get(EventService);
    roleService = module.get(RoleService);

    // Mock implementations for external libraries
    (CryptoJS.enc.Base64.parse as jest.Mock).mockImplementation((val) =>
      jest.requireActual('crypto-js').enc.Base64.parse(val),
    );
    (CryptoJS.Blowfish.decrypt as jest.Mock).mockImplementation(
      (cipherParams) => {
        // Simulate decryption success by returning a WordArray that can be stringified
        // This needs to be robust enough for the `toString(CryptoJS.enc.Utf8)` call
        const actualCryptoJS = jest.requireActual('crypto-js');
        if (cipherParams === 'expectedEncryptedPassword') {
          // A known good encrypted value for tests
          return actualCryptoJS.enc.Utf8.parse('decryptedPassword');
        }
        // Simulate decryption failure or empty result
        return { sigBytes: 0, words: [] }; // Represents an empty WordArray or failed decryption
      },
    );
    (uuidv4 as jest.Mock).mockReturnValue('mock-uuid-jti');
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('Constructor Error Handling', () => {
    it('should throw error if JWT_SECRET is not set', () => {
      configService.get.mockImplementationOnce((key: string) => {
        if (key === 'JWT_SECRET') return undefined;
        return 'dGVzdEJhc2U2NEtleQ=='; // LEGACY_BLOWFISH_KEY
      });
      expect(
        () =>
          new AuthFlowService(
            prismaOltp as any,
            cacheManager as any,
            configService as any,
            userService,
            eventService,
            roleService,
          ),
      ).toThrow('JWT_SECRET environment variable not set');
    });
    it('should throw error if LEGACY_BLOWFISH_KEY is not set', () => {
      configService.get.mockImplementationOnce((key: string) => {
        if (key === 'LEGACY_BLOWFISH_KEY') return undefined;
        return 'test-jwt-secret'; // JWT_SECRET
      });
      expect(
        () =>
          new AuthFlowService(
            prismaOltp as any,
            cacheManager as any,
            configService as any,
            userService,
            eventService,
            roleService,
          ),
      );
    });
  });

  describe('activateUser', () => {
    const userId = 1;
    const otp = '123456';
    const resendToken = 'valid.resend.token';
    const activateDto: ActivateUserBodyDto = {
      param: { userId, otp, resendToken },
    };
    const mockUser = createMockUserModel({
      user_id: new Decimal(userId),
      status: 'U',
      handle: 'unverifiedUser',
    });
    const mockPrimaryEmail = createMockEmailModel({
      user_id: new Decimal(userId),
      address: 'unverified@example.com',
      status_id: new Decimal(2),
    }); // Unverified

    beforeEach(() => {
      (jwt.verify as jest.Mock).mockReturnValue({
        sub: userId.toString(),
        aud: OTP_ACTIVATION_JWT_AUDIENCE,
      });
      cacheManager.get.mockResolvedValue(otp); // Correct OTP
      cacheManager.del.mockResolvedValue(undefined);
      prismaOltp.user.findUnique.mockResolvedValue(mockUser);
      prismaOltp.email.findFirst.mockResolvedValue(mockPrimaryEmail); // For finding primary email to verify
      prismaOltp.user.update.mockResolvedValue({ ...mockUser, status: 'A' }); // User status update
      prismaOltp.email.update.mockResolvedValue({
        ...mockPrimaryEmail,
        status_id: new Decimal(1),
      }); // Email status update
      eventService.postEnvelopedNotification.mockResolvedValue(undefined);
      eventService.postDirectBusMessage.mockResolvedValue(undefined);
    });

    it('should activate a user successfully and send welcome email', async () => {
      const result = await service.activateUser(activateDto);
      expect(jwt.verify).toHaveBeenCalledWith(resendToken, 'test-jwt-secret', {
        audience: OTP_ACTIVATION_JWT_AUDIENCE,
      });
      expect(cacheManager.get).toHaveBeenCalledWith(
        `${ACTIVATION_OTP_CACHE_PREFIX_KEY}:${userId}`,
      );
      expect(cacheManager.del).toHaveBeenCalledWith(
        `${ACTIVATION_OTP_CACHE_PREFIX_KEY}:${userId}`,
      );
      expect(prismaOltp.user.update).toHaveBeenCalledWith({
        where: { user_id: userId },
        data: { status: 'A', modify_date: expect.any(Date) },
      });
      expect(prismaOltp.email.update).toHaveBeenCalledWith({
        where: { email_id: mockPrimaryEmail.email_id },
        data: { status_id: 1, modify_date: expect.any(Date) },
      });
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'user.activated',
        { userId: userId.toString() },
      );
      expect(mockEventService.postDirectBusMessage).toHaveBeenCalledWith(
        'external.action.email',
        expect.objectContaining({ sendgrid_template_id: 'd-welcome' }),
      );
      expect(result?.status).toBe('U');
    });

    it('should throw BadRequestException if userId, otp, or resendToken is missing', async () => {
      await expect(
        service.activateUser({
          param: { userId: undefined, otp, resendToken },
        } as any),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.activateUser({
          param: { userId, otp: undefined, resendToken },
        } as any),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.activateUser({
          param: { userId, otp, resendToken: undefined },
        } as any),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw ForbiddenException for invalid resend token (sub mismatch)', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({
        sub: '2',
        aud: OTP_ACTIVATION_JWT_AUDIENCE,
      }); // Different user ID
      await expect(service.activateUser(activateDto)).rejects.toThrow(
        new ForbiddenException('Invalid or expired resend token.'),
      );
    });
    it('should throw GoneException if resend token is expired', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.TokenExpiredError('expired');
      });
      await expect(service.activateUser(activateDto)).rejects.toThrow(
        GoneException,
      );
    });
    it('should throw ForbiddenException for other jwt errors', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('jwt malformed');
      });
      await expect(service.activateUser(activateDto)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('should throw GoneException if OTP not found in cache', async () => {
      cacheManager.get.mockResolvedValue(null);
      await expect(service.activateUser(activateDto)).rejects.toThrow(
        GoneException,
      );
    });

    it('should throw BadRequestException for invalid OTP', async () => {
      cacheManager.get.mockResolvedValue('wrong-otp');
      await expect(service.activateUser(activateDto)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw NotFoundException if user not found in DB', async () => {
      prismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(service.activateUser(activateDto)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should return "User is already active" if user status is A', async () => {
      prismaOltp.user.findUnique.mockResolvedValue({
        ...mockUser,
        status: 'A',
      });
      const result = await service.activateUser(activateDto);
      expect(result.message).toBe('User is already active.');
      expect(prismaOltp.user.update).not.toHaveBeenCalled(); // No update if already active
    });
    it('should throw ForbiddenException if user status is not U or A', async () => {
      prismaOltp.user.findUnique.mockResolvedValue({
        ...mockUser,
        status: 'I',
      }); // Inactive
      await expect(service.activateUser(activateDto)).rejects.toThrow(
        ForbiddenException,
      );
    });
    it('should handle case where primary email is not found during transaction', async () => {
      prismaOltp.email.findFirst.mockResolvedValue(null); // No primary email
      await service.activateUser(activateDto);
      expect(prismaOltp.email.update).not.toHaveBeenCalled(); // Email update should not be called
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          `No primary email record (primary_ind = 1) found for user ${userId}`,
        ),
      );
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          `Could not send welcome email for user ${userId} due to missing primary email address or handle.`,
        ),
      );
    });
  });

  describe('requestResendActivation', () => {
    const userId = 1;
    const resendToken = 'valid.resend.token';
    const resendDto: UserOtpDto = { userId, resendToken };
    const mockUser = createMockUserModel({
      user_id: new Decimal(userId),
      status: 'U',
      handle: 'unverifiedUser',
    });
    const mockPrimaryUnverifiedEmail = createMockEmailModel({
      user_id: new Decimal(userId),
      address: 'unverified@example.com',
      status_id: new Decimal(2),
    });

    beforeEach(() => {
      (jwt.verify as jest.Mock).mockReturnValue({
        sub: userId.toString(),
        aud: OTP_ACTIVATION_JWT_AUDIENCE,
      });
      prismaOltp.user.findUnique.mockResolvedValue(mockUser);
      prismaOltp.email.findFirst.mockResolvedValue(mockPrimaryUnverifiedEmail);
      cacheManager.set.mockResolvedValue(undefined);
      eventService.postDirectBusMessage.mockResolvedValue(undefined);
    });

    it('should resend activation email successfully', async () => {
      const result = await service.requestResendActivation(resendDto);
      expect(jwt.verify).toHaveBeenCalledWith(resendToken, 'test-jwt-secret', {
        audience: OTP_ACTIVATION_JWT_AUDIENCE,
      });
      expect(prismaOltp.user.findUnique).toHaveBeenCalledWith({
        where: { user_id: userId },
      });
      expect(prismaOltp.email.findFirst).toHaveBeenCalledWith({
        where: { user_id: userId, primary_ind: 1, status_id: 2 },
      });
      expect(cacheManager.set).toHaveBeenCalledWith(
        `${ACTIVATION_OTP_CACHE_PREFIX_KEY}:${userId}`,
        expect.any(String),
        expect.any(Number),
      );
      expect(mockEventService.postDirectBusMessage).toHaveBeenCalledWith(
        'external.action.email',
        expect.objectContaining({
          sendgrid_template_id: 'd-resend-activation',
          recipients: [mockPrimaryUnverifiedEmail.address],
        }),
      );
      expect(result.message).toBe(
        'Activation email has been resent successfully.',
      );
    });

    it('should throw BadRequestException if userId or resendToken is missing', async () => {
      await expect(
        service.requestResendActivation({
          userId: undefined,
          resendToken,
        } as any),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.requestResendActivation({
          userId,
          resendToken: undefined,
        } as any),
      ).rejects.toThrow(BadRequestException);
    });
    it('should throw ForbiddenException for invalid resend token (sub mismatch)', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({
        sub: '2',
        aud: OTP_ACTIVATION_JWT_AUDIENCE,
      });
      await expect(service.requestResendActivation(resendDto)).rejects.toThrow(
        new ForbiddenException('Invalid or expired resend token.'),
      );
    });
    it('should throw GoneException if resend token is expired', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.TokenExpiredError('expired');
      });
      await expect(service.requestResendActivation(resendDto)).rejects.toThrow(
        GoneException,
      );
    });
    it('should throw NotFoundException if user not found', async () => {
      prismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(service.requestResendActivation(resendDto)).rejects.toThrow(
        NotFoundException,
      );
    });
    it('should throw InternalServerErrorException if primary unverified email not found', async () => {
      prismaOltp.email.findFirst.mockResolvedValue(null);
      await expect(service.requestResendActivation(resendDto)).rejects.toThrow(
        new InternalServerErrorException(
          'Primary unverified email not found for the user.',
        ),
      );
    });
    it('should return "Account is already activated" if user status is A', async () => {
      prismaOltp.user.findUnique.mockResolvedValue({
        ...mockUser,
        status: 'A',
      });
      const result = await service.requestResendActivation(resendDto);
      expect(result.message).toBe('Account is already activated.');
      expect(cacheManager.set).not.toHaveBeenCalled(); // No OTP generation if already active
    });
    it('should throw ForbiddenException if user status is not U or A', async () => {
      prismaOltp.user.findUnique.mockResolvedValue({
        ...mockUser,
        status: 'I',
      });
      await expect(service.requestResendActivation(resendDto)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('generateOneTimeToken', () => {
    const userId = 1;
    const userIdString = '1';
    const passwordPlain = 'decryptedPassword'; // This should match the mock decryption output
    const mockUser = createMockUserModel({
      user_id: new Decimal(userId),
      handle: 'activeUser',
      status: 'A',
    });
    const mockSecurityUser = createMockSecurityUserModel({
      user_id: 'activeUser',
      password: 'expectedEncryptedPassword',
    });

    let mockDecrypt;
    beforeEach(() => {
      prismaOltp.user.findUnique.mockResolvedValue(mockUser);
      prismaOltp.security_user.findUnique.mockResolvedValue(mockSecurityUser);
      (CryptoJS.enc.Base64.parse as jest.Mock).mockReturnValue(
        'parsedBlowfishKey',
      );
      // Configure Blowfish.decrypt to return a specific decrypted value for a specific encrypted input
      mockDecrypt = (CryptoJS.Blowfish.decrypt as jest.Mock).mockImplementation(
        (cipherParams, key) => {
          const actualCryptoJS = jest.requireActual('crypto-js');
          if (
            cipherParams === 'expectedEncryptedPassword' &&
            key === 'parsedBlowfishKey'
          ) {
            return actualCryptoJS.enc.Utf8.parse(passwordPlain);
          }
          return { sigBytes: 0, words: [] }; // Default to failed decryption
        },
      );
      (jwt.sign as jest.Mock).mockReturnValue('generated.one.time.token');
      (uuidv4 as jest.Mock).mockReturnValue('test-jti');
    });

    it('should generate a one-time token for valid credentials', async () => {
      const token = await service.generateOneTimeToken(
        userIdString,
        passwordPlain,
      );
      expect(prismaOltp.user.findUnique).toHaveBeenCalledWith({
        where: { user_id: userId },
        select: expect.any(Object),
      });
      expect(prismaOltp.security_user.findUnique).toHaveBeenCalledWith({
        where: { user_id: mockUser.handle },
        select: { password: true },
      });
      expect(mockDecrypt).toHaveBeenCalledWith(
        'expectedEncryptedPassword',
        'parsedBlowfishKey',
        expect.any(Object),
      );
      expect(jwt.sign).toHaveBeenCalledWith(
        {
          sub: userIdString,
          aud: ONE_TIME_TOKEN_JWT_AUDIENCE,
          jti: 'test-jti',
        },
        'test-jwt-secret',
        { expiresIn: `${(service as any).oneTimeTokenExpirySeconds}s` },
      );
      expect(token).toBe('generated.one.time.token');
    });

    it('should throw BadRequestException for missing userId or password', async () => {
      await expect(
        service.generateOneTimeToken('', passwordPlain),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.generateOneTimeToken(userIdString, ''),
      ).rejects.toThrow(BadRequestException);
    });
    it('should throw BadRequestException for invalid userId format', async () => {
      await expect(
        service.generateOneTimeToken('abc', passwordPlain),
      ).rejects.toThrow(BadRequestException);
    });
    it('should throw NotFoundException if user not found', async () => {
      prismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(
        service.generateOneTimeToken(userIdString, passwordPlain),
      ).rejects.toThrow(NotFoundException);
    });
    it('should throw ForbiddenException if user is not active', async () => {
      prismaOltp.user.findUnique.mockResolvedValue({
        ...mockUser,
        status: 'U',
      });
      await expect(
        service.generateOneTimeToken(userIdString, passwordPlain),
      ).rejects.toThrow(ForbiddenException);
    });
    it('should throw InternalServerErrorException if security record not found', async () => {
      prismaOltp.security_user.findUnique.mockResolvedValue(null);
      await expect(
        service.generateOneTimeToken(userIdString, passwordPlain),
      ).rejects.toThrow(InternalServerErrorException);
    });
    it('should throw InternalServerErrorException on Blowfish decryption error', async () => {
      (CryptoJS.Blowfish.decrypt as jest.Mock).mockImplementation(() => {
        throw new Error('Decrypt fail');
      });
      await expect(
        service.generateOneTimeToken(userIdString, passwordPlain),
      ).rejects.toThrow(InternalServerErrorException);
    });
    it('should throw UnauthorizedException for password mismatch', async () => {
      await expect(
        service.generateOneTimeToken(userIdString, 'wrongPassword'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('updateEmailWithOneTimeToken', () => {
    const userId = 1;
    const userIdString = '1';
    const newEmail = 'newprimary@example.com';
    const oneTimeToken = 'valid.one.time.token';
    const jti = 'test-jti';
    const mockUser = createMockUserModel({
      user_id: new Decimal(userId),
      handle: 'testUser',
    });
    const mockOldPrimaryEmail = createMockEmailModel({
      user_id: new Decimal(userId),
      address: 'oldprimary@example.com',
      primary_ind: new Decimal(1),
      status_id: new Decimal(1),
    });

    beforeEach(() => {
      (jwt.verify as jest.Mock).mockReturnValue({
        sub: userIdString,
        aud: ONE_TIME_TOKEN_JWT_AUDIENCE,
        jti,
      });
      cacheManager.get.mockResolvedValue(null); // JTI not used yet
      cacheManager.set.mockResolvedValue(undefined);
      userService.checkEmailAvailabilityForUser.mockResolvedValue(undefined);
      prismaOltp.email.findFirst
        .mockResolvedValueOnce(mockOldPrimaryEmail) // Find current primary
        .mockResolvedValueOnce(null); // New email does not exist globally
      prismaOltp.$queryRaw.mockResolvedValueOnce([{ nextval: BigInt(202) }]); // Next email_id
      prismaOltp.email.create.mockResolvedValue(
        createMockEmailModel({
          email_id: new Decimal(202),
          address: newEmail,
          user_id: new Decimal(userId),
          primary_ind: new Decimal(1),
          status_id: new Decimal(1),
        }),
      );
      prismaOltp.email.update.mockResolvedValue({} as EmailModel);
      prismaOltp.user.findUnique.mockResolvedValue(mockUser); // For event publishing
      eventService.postEnvelopedNotification.mockResolvedValue(undefined);
    });

    it('should throw BadRequest for invalid user ID or missing/invalid email', async () => {
      await expect(
        service.updateEmailWithOneTimeToken('abc', newEmail, oneTimeToken),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updateEmailWithOneTimeToken(userIdString, '', oneTimeToken),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updateEmailWithOneTimeToken(
          userIdString,
          'bademail',
          oneTimeToken,
        ),
      ).rejects.toThrow(BadRequestException);
    });
    it('should throw GoneException if token is expired', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.TokenExpiredError('expired');
      });
      await expect(
        service.updateEmailWithOneTimeToken(
          userIdString,
          newEmail,
          oneTimeToken,
        ),
      ).rejects.toThrow(GoneException);
    });
    it('should throw ForbiddenException if token subject mismatch', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({
        sub: '2',
        aud: ONE_TIME_TOKEN_JWT_AUDIENCE,
        jti,
      });
      await expect(
        service.updateEmailWithOneTimeToken(
          userIdString,
          newEmail,
          oneTimeToken,
        ),
      ).rejects.toThrow(ForbiddenException);
    });
    it('should throw ForbiddenException if JTI already used', async () => {
      cacheManager.get.mockResolvedValue('used');
      await expect(
        service.updateEmailWithOneTimeToken(
          userIdString,
          newEmail,
          oneTimeToken,
        ),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('initiatePasswordReset', () => {
    const emailOrHandle = 'user@example.com';
    const mockUser = {
      ...createMockUserModel({
        user_id: new Decimal(1),
        handle: 'resetUser',
        status: 'A',
      }),
      primaryEmail: { address: 'user@example.com' }, // Added for findUserByEmailOrHandle mock
      user_sso_login: [], // No SSO logins
    };

    beforeEach(() => {
      userService.findUserByEmailOrHandle.mockResolvedValue(mockUser as any);
      cacheManager.get.mockResolvedValue(null); // No existing token
      cacheManager.set.mockResolvedValue(undefined);
      eventService.postEnvelopedNotification.mockResolvedValue(undefined);
    });

    it('should initiate password reset and send notification', async () => {
      await service.initiatePasswordReset(emailOrHandle);
      expect(mockUserService.findUserByEmailOrHandle).toHaveBeenCalledWith(
        emailOrHandle,
      );
      expect(cacheManager.get).toHaveBeenCalledWith(
        `${PASSWORD_RESET_TOKEN_CACHE_PREFIX}:${mockUser.user_id.toNumber()}`,
      );
      expect(cacheManager.set).toHaveBeenCalledWith(
        `${PASSWORD_RESET_TOKEN_CACHE_PREFIX}:${mockUser.user_id.toNumber()}`,
        expect.any(String),
        expect.any(Number),
      );
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'userpasswordreset',
        expect.objectContaining({
          recipients: [
            {
              id: mockUser.user_id.toString(),
              email: mockUser.primaryEmail.address,
            },
          ],
          data: expect.objectContaining({
            handle: mockUser.handle,
            resetToken: expect.any(String),
          }),
        }),
      );
    });
    it('should throw BadRequestException if emailOrHandle is missing', async () => {
      await expect(service.initiatePasswordReset('')).rejects.toThrow(
        BadRequestException,
      );
    });
    it('should return successfully (no error) if user not found, to prevent enumeration', async () => {
      userService.findUserByEmailOrHandle.mockResolvedValue(null as any);
      await expect(
        service.initiatePasswordReset('nonexistent@example.com'),
      ).resolves.toBeUndefined();
      expect(cacheManager.set).not.toHaveBeenCalled();
    });
    it('should throw ForbiddenException if user is SSO linked', async () => {
      userService.findUserByEmailOrHandle.mockResolvedValue({
        ...mockUser,
        user_sso_login: [{}],
      } as any); // Has SSO
      await expect(
        service.initiatePasswordReset(emailOrHandle),
      ).rejects.toThrow(ForbiddenException);
    });
    it('should throw ConflictException if reset token already cached', async () => {
      cacheManager.get.mockResolvedValue('existingToken');
      await expect(
        service.initiatePasswordReset(emailOrHandle),
      ).rejects.toThrow(ConflictException);
    });
    it('should not send email if user has no primary email address, but not throw error', async () => {
      userService.findUserByEmailOrHandle.mockResolvedValue({
        ...mockUser,
        primaryEmail: undefined,
      } as any);
      await service.initiatePasswordReset(emailOrHandle);
      expect(mockEventService.postEnvelopedNotification).not.toHaveBeenCalled();
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('no primary email address is associated'),
      );
    });
  });

  describe('authenticateForAuth0', () => {
    const handle = 'auth0User';
    const email = 'oldprimary@example.com';
    const passwordPlain = 'decryptedPassword';
    const mockUserRecord = createMockUserModel({
      user_id: new Decimal(1),
      handle,
      status: 'A',
      first_name: 'Auth',
      last_name: 'Zero',
    });
    const mockSecurityUser = createMockSecurityUserModel({
      user_id: handle,
      password: 'expectedEncryptedPassword',
    });
    const mockPrimaryEmail = createMockEmailModel({
      user_id: new Decimal(1),
      address: email,
      status_id: new Decimal(1),
    }); // Verified
    const mockRoles: RoleResponseDto[] = [
      { id: 1, roleName: 'User' } as RoleResponseDto,
    ];

    beforeEach(() => {
      prismaOltp.user.findFirst.mockResolvedValue(mockUserRecord); // For handle lookup
      prismaOltp.user.findUnique.mockResolvedValue(mockUserRecord); // For email->userId->user lookup
      prismaOltp.email.findFirst
        .mockResolvedValueOnce(mockPrimaryEmail) // For initial email lookup if identifier is email
        .mockResolvedValueOnce(mockPrimaryEmail); // For attaching primary email
      prismaOltp.security_user.findUnique.mockResolvedValue(mockSecurityUser);
      (CryptoJS.enc.Base64.parse as jest.Mock).mockReturnValue(
        'parsedBlowfishKey',
      );
      (CryptoJS.Blowfish.decrypt as jest.Mock).mockImplementation(
        (cipherParams, key) => {
          const actualCryptoJS = jest.requireActual('crypto-js');
          if (
            cipherParams === 'expectedEncryptedPassword' &&
            key === 'parsedBlowfishKey'
          ) {
            return actualCryptoJS.enc.Utf8.parse(passwordPlain);
          }
          return { sigBytes: 0, words: [] };
        },
      );
      roleService.findAll.mockResolvedValue(mockRoles);
    });

    it('should throw UnauthorizedException for user not found (by handle)', async () => {
      prismaOltp.user.findFirst.mockResolvedValue(null);
      await expect(
        service.authenticateForAuth0('unknownHandle', passwordPlain),
      ).rejects.toThrow(UnauthorizedException);
    });
    it('should throw UnauthorizedException for user not found (by email)', () => {
      prismaOltp.email.findFirst.mockResolvedValueOnce(null); // Email not found
      expect(
        service.authenticateForAuth0('unknown@example.com', passwordPlain),
      );
    });
    it('should throw UnauthorizedException for deactivated account', async () => {
      prismaOltp.user.findFirst.mockResolvedValue({
        ...mockUserRecord,
        status: 'I',
      });
      await expect(
        service.authenticateForAuth0(handle, passwordPlain),
      ).rejects.toThrow(UnauthorizedException);
    });
    it('should throw UnauthorizedException if security record not found', async () => {
      prismaOltp.security_user.findUnique.mockResolvedValue(null);
      await expect(
        service.authenticateForAuth0(handle, passwordPlain),
      ).rejects.toThrow(UnauthorizedException);
    });
    it('should throw InternalServerErrorException on Blowfish decryption error', async () => {
      (CryptoJS.Blowfish.decrypt as jest.Mock).mockImplementation(() => {
        throw new Error('Decrypt fail');
      });
      await expect(
        service.authenticateForAuth0(handle, passwordPlain),
      ).rejects.toThrow(InternalServerErrorException);
    });
    it('should throw UnauthorizedException for password mismatch', async () => {
      await expect(
        service.authenticateForAuth0(handle, 'wrongPassword'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('getUserProfileForAuth0', () => {
    const handle = 'auth0User';
    const email = 'oldprimary@example.com';
    const userId = 1;
    const mockUser = createMockUserModel({
      user_id: new Decimal(userId),
      handle,
      status: 'A',
    });
    const mockPrimaryEmail = createMockEmailModel({
      user_id: new Decimal(userId),
      address: email,
      status_id: new Decimal(1),
    });
    const mockRoles: RoleResponseDto[] = [
      { id: 1, roleName: 'User' } as RoleResponseDto,
    ];
    const mockTcssoToken = 'mock.tcsso.token';
    const mockResendActivationToken = 'mock.resend.activation.jwt';

    beforeEach(() => {
      prismaOltp.user.findFirst.mockResolvedValue(mockUser); // For handle lookup
      prismaOltp.user.findUnique.mockResolvedValue(mockUser); // For email->userId->user lookup
      prismaOltp.email.findFirst
        .mockResolvedValueOnce(mockPrimaryEmail) // For initial email lookup if identifier is email
        .mockResolvedValueOnce(mockPrimaryEmail); // For attaching primary email
      roleService.findAll.mockResolvedValue(mockRoles);
      userService.generateSSOToken.mockResolvedValue(mockTcssoToken);
      (jwt.sign as jest.Mock).mockReturnValue(mockResendActivationToken);
    });

    it('should return user profile with tcsso for an active user', async () => {
      const profile = await service.getUserProfileForAuth0(handle);
      expect(profile.userId).toBe(userId.toString());
      expect(profile.handle).toBe(handle);
      expect(profile.email).toBe(email);
      expect(profile.roles).toEqual(['User']);
      expect(profile.tcsso).toBe(mockTcssoToken);
      expect(profile.status).toBe('A');
      expect(profile.resendToken).toBeUndefined();
    });
    it('should return user profile with resendToken for an unverified user (U)', async () => {
      prismaOltp.user.findFirst.mockResolvedValue({ ...mockUser, status: 'U' });
      const profile = await service.getUserProfileForAuth0(handle);
      expect(profile.status).toBe('U');
      expect(profile.resendToken).toBe(mockResendActivationToken);
      expect(profile.canResendActivation).toBe(true);
      expect(jwt.sign).toHaveBeenCalledWith(
        { sub: userId.toString(), aud: OTP_ACTIVATION_JWT_AUDIENCE },
        'test-jwt-secret',
        { expiresIn: `${(service as any).activationResendExpirySeconds}s` },
      );
    });
    it('should throw BadRequestException if handleOrEmail is missing', async () => {
      await expect(service.getUserProfileForAuth0('')).rejects.toThrow(
        BadRequestException,
      );
    });
    it('should throw NotFoundException if user not found', async () => {
      prismaOltp.user.findFirst.mockResolvedValue(null);
      await expect(
        service.getUserProfileForAuth0('unknownHandle'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('changePasswordFromAuth0', () => {
    const email = 'user@example.com';
    const newPasswordPlain = 'newStrongPassword1!';
    const mockUser = {
      ...createMockUserModel({
        user_id: new Decimal(1),
        handle: 'changePassUser',
        status: 'A',
      }),
      user_sso_login: [], // No SSO
    };
    const encodedNewPassword = 'encodedNewLegacyPasswordForAuth0';

    let mockEncode;
    let mockFindUserEmail;
    beforeEach(() => {
      mockFindUserEmail = userService.findUserByEmailOrHandle.mockResolvedValue(
        mockUser as any,
      );
      mockEncode =
        userService.encodePasswordLegacy.mockReturnValue(encodedNewPassword);
      prismaOltp.security_user.update.mockResolvedValue(
        {} as SecurityUserModel,
      );
      prismaOltp.user.update.mockResolvedValue({} as UserModel);
    });

    it('should change password successfully', async () => {
      const result = await service.changePasswordFromAuth0(
        email,
        newPasswordPlain,
      );
      expect(mockFindUserEmail).toHaveBeenCalledWith(email);
      expect(mockEncode).toHaveBeenCalledWith(newPasswordPlain);
      expect(prismaOltp.security_user.update).toHaveBeenCalledWith({
        where: { user_id: mockUser.handle },
        data: { password: encodedNewPassword },
      });
      expect(prismaOltp.user.update).toHaveBeenCalledWith({
        where: { user_id: mockUser.user_id.toNumber() },
        data: { modify_date: expect.any(Date) },
      });
      expect(result.message).toBe('Password changed successfully.');
    });
    it('should throw BadRequestException for missing email or password', async () => {
      await expect(
        service.changePasswordFromAuth0('', newPasswordPlain),
      ).rejects.toThrow(BadRequestException);
      await expect(service.changePasswordFromAuth0(email, '')).rejects.toThrow(
        BadRequestException,
      );
    });
    it('should throw NotFoundException if user not found', async () => {
      userService.findUserByEmailOrHandle.mockResolvedValue(null as any);
      await expect(
        service.changePasswordFromAuth0(email, newPasswordPlain),
      ).rejects.toThrow(NotFoundException);
    });
    it('should throw ForbiddenException if user is SSO linked', async () => {
      userService.findUserByEmailOrHandle.mockResolvedValue({
        ...mockUser,
        user_sso_login: [{}],
      } as any);
      await expect(
        service.changePasswordFromAuth0(email, newPasswordPlain),
      ).rejects.toThrow(ForbiddenException);
    });
    it('should throw BadRequestException for short new password', async () => {
      await expect(
        service.changePasswordFromAuth0(email, 'short'),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
