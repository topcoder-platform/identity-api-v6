import { Test, TestingModule } from '@nestjs/testing';
import {
  TwoFactorAuthService,
  TFA_OTP_CACHE_PREFIX_KEY,
  TFA_OTP_EXPIRY_SECONDS,
  TFA_RESEND_TOKEN_EXPIRY_SECONDS,
  // TFA_OTP_MAX_ATTEMPTS, // Not directly used in the provided service logic for assertions
} from './two-factor-auth.service';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import { EventService } from '../../shared/event/event.service';
import { UserService } from './user.service';
import { SlackService } from '../../shared/slack/slack.service';
import { AuthFlowService } from './auth-flow.service';
import { RoleService } from '../role/role.service';
import {
  BadRequestException,
  InternalServerErrorException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import {
  // Import specific Prisma models if needed for explicit typing, otherwise Prisma.ModelName suffices for mock shapes
  Prisma,
} from '@prisma/client-common-oltp';
import * as DTOs from '../../dto/user/user.dto'; // Using your DTO import
import { RoleResponseDto } from '../../dto/role/role.dto';
import { AuthenticatedUser, JwtPayload } from '../../core/auth/jwt.strategy';
import { Decimal } from '@prisma/client/runtime/library';
import * as jwt from 'jsonwebtoken';
// import { format } from 'date-fns'; // Not directly used in this spec, but service uses it

// Constants from TwoFactorAuthService
const OTP_2FA_AUDIENCE = '2faemail';

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
  JsonWebTokenError: class JsonWebTokenError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'JsonWebTokenError';
    }
  },
}));

// --- Mock Prisma Client Methods ---
const mockPrismaOltp = {
  user_2fa: {
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
  user: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
  },
  email: {
    findFirst: jest.fn(),
    count: jest.fn(),
  },
  dice_connection: {
    findFirst: jest.fn(),
    upsert: jest.fn(),
    updateMany: jest.fn(),
    deleteMany: jest.fn(),
  },
};

// --- Mock CacheManager ---
const mockCacheManager = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
};

// --- Mock ConfigService ---
const mockConfigService = {
  get: jest.fn(<T = any>(key: string, defaultValue?: T): T => {
    const configValues: Record<string, string | undefined> = {
      JWT_SECRET: 'test-2fa-jwt-secret-for-service',
      DEV_DICEAUTH_OTP_DURATION: '10',
    };
    return (configValues[key] ?? defaultValue) as T;
  }),
};

// --- Mock Other Services ---
const mockEventService = {
  postEnvelopedNotification: jest.fn().mockResolvedValue(undefined),
};
const mockUserService = {
  // No methods seem to be directly called in the provided service code
};
const mockSlackService = {
  sendNotification: jest.fn().mockResolvedValue(undefined),
};
const mockAuthFlowService = {
  // No methods seem to be directly called
};
const mockRoleService = {
  findAll: jest.fn().mockResolvedValue([] as RoleResponseDto[]),
};

// --- Helper to create Mock AuthenticatedUser ---
const createMockAuthUser = (
  userId: string,
  options: Partial<AuthenticatedUser> = {},
): AuthenticatedUser => ({
  userId,
  roles: options.roles || ['user'],
  scopes: options.scopes || [],
  isAdmin: options.isAdmin === undefined ? false : options.isAdmin,
  isMachine: options.isMachine === undefined ? false : options.isMachine,
  handle: options.handle || `handle-${userId}`,
  email: options.email || `${userId}@example.com`,
  payload: options.payload || ({ sub: userId } as JwtPayload),
  ...options,
});

// --- Helper Functions to Create Mock Prisma Models (simplified for brevity, expand as needed) ---
const createMockUserModel = (
  input: Partial<Prisma.userGetPayload<unknown>> = {},
): Prisma.userGetPayload<unknown> =>
  ({
    user_id: input.user_id ? new Decimal(input.user_id) : new Decimal(1),
    handle: input.handle || 'testuser',
    first_name: input.first_name || 'Test',
    last_name: input.last_name || 'User',
    // Add other required fields with defaults or from input
    handle_lower: (input.handle || 'testuser').toLowerCase(),
    create_date: input.create_date || new Date(),
    modify_date: input.modify_date || new Date(),
    status: input.status || 'A',
    password: input.password || 'secret',
    // Ensure all non-nullable fields have a default or are passed in 'input'
    ...input,
  }) as Prisma.userGetPayload<unknown>;

const createMockUser2faModel = (
  input: Partial<Prisma.user_2faGetPayload<unknown>> = {},
): Prisma.user_2faGetPayload<unknown> =>
  ({
    id: input.id || 1,
    user_id: input.user_id || new Decimal(1),
    mfa_enabled: input.mfa_enabled === undefined ? false : input.mfa_enabled,
    dice_enabled: input.dice_enabled === undefined ? false : input.dice_enabled,
    created_by: input.created_by || new Decimal(0), // Default to 0 as per service create logic
    modified_by: input.modified_by || new Decimal(0), // Default to 0
    created_at: input.created_at || new Date(),
    modified_at: input.modified_at || new Date(),
    ...input,
  }) as Prisma.user_2faGetPayload<unknown>;

const createMockEmailModel = (
  input: Partial<Prisma.emailGetPayload<unknown>> = {},
): Prisma.emailGetPayload<unknown> =>
  ({
    email_id: input.email_id || new Decimal(101),
    user_id: input.user_id ? new Decimal(input.user_id) : new Decimal(1),
    email_type_id: input.email_type_id || new Decimal(1),
    address: input.address || 'primary@example.com',
    primary_ind:
      input.primary_ind === undefined
        ? new Decimal(1)
        : new Decimal(input.primary_ind),
    status_id:
      input.status_id === undefined
        ? new Decimal(1)
        : new Decimal(input.status_id),
    create_date: input.create_date || new Date(),
    modify_date: input.modify_date || new Date(),
    ...input,
  }) as Prisma.emailGetPayload<unknown>;

describe('TwoFactorAuthService', () => {
  let service: TwoFactorAuthService;
  let loggerErrorSpy: jest.SpyInstance;
  let loggerWarnSpy: jest.SpyInstance;
  let loggerLogSpy: jest.SpyInstance;
  let loggerDebugSpy: jest.SpyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();

    loggerErrorSpy = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => {});
    loggerWarnSpy = jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => {});
    loggerLogSpy = jest
      .spyOn(Logger.prototype, 'log')
      .mockImplementation(() => {});
    loggerDebugSpy = jest
      .spyOn(Logger.prototype, 'debug')
      .mockImplementation(() => {});

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TwoFactorAuthService,
        { provide: PRISMA_CLIENT_COMMON_OLTP, useValue: mockPrismaOltp },
        { provide: CACHE_MANAGER, useValue: mockCacheManager },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: EventService, useValue: mockEventService },
        { provide: UserService, useValue: mockUserService },
        { provide: SlackService, useValue: mockSlackService },
        { provide: AuthFlowService, useValue: mockAuthFlowService },
        { provide: RoleService, useValue: mockRoleService },
      ],
    }).compile();

    service = module.get<TwoFactorAuthService>(TwoFactorAuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('Constructor', () => {
    it('should throw InternalServerErrorException if JWT_SECRET is not configured', () => {
      const originalGet = mockConfigService.get;
      mockConfigService.get = jest.fn((key: string) => {
        if (key === 'JWT_SECRET') return undefined;
        return '10';
      });
      expect(
        () =>
          new TwoFactorAuthService(
            mockPrismaOltp as any,
            mockCacheManager as any,
            mockConfigService as any,
            mockEventService as any,
            mockUserService as any,
            mockSlackService as any,
            mockAuthFlowService as any,
            mockRoleService as any,
          ),
      ).toThrow(
        new InternalServerErrorException(
          '2FA service is not properly configured.',
        ),
      );
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        'JWT_SECRET for 2FA resend tokens is not configured!',
      );
      mockConfigService.get = originalGet;
    });

    it('should initialize otpDurationMinutes and resendTokenSecret correctly', () => {
      const originalGet = mockConfigService.get;
      mockConfigService.get = jest.fn((key: string, defaultValue?: any) => {
        if (key === 'DEV_DICEAUTH_OTP_DURATION') return '15';
        if (key === 'JWT_SECRET') return 'a-different-valid-secret';
        return defaultValue;
      });
      const tempService = new TwoFactorAuthService(
        mockPrismaOltp as any,
        mockCacheManager as any,
        mockConfigService as any,
        mockEventService as any,
        mockUserService as any,
        mockSlackService as any,
        mockAuthFlowService as any,
        mockRoleService as any,
      );
      expect((tempService as any).otpDurationMinutes).toBe(15);
      expect((tempService as any).resendTokenSecret).toBe(
        'a-different-valid-secret',
      );
      mockConfigService.get = originalGet;
    });
  });

  describe('generateNumericOtp (private method test)', () => {
    it('should generate a 6-digit numeric OTP by default', () => {
      const otp = (service as any).generateNumericOtp();
      expect(otp).toHaveLength(6);
      expect(otp).toMatch(/^\d{6}$/);
    });

    it('should generate an OTP of specified length', () => {
      const otp = (service as any).generateNumericOtp(8);
      expect(otp).toHaveLength(8);
      expect(otp).toMatch(/^\d{8}$/);
    });
  });

  describe('getUser2faStatus', () => {
    const userIdStr = '1';
    const userIdNum = 1;

    it('should return mfaEnabled and diceEnabled from existing record', async () => {
      const mockRecord = createMockUser2faModel({
        user_id: new Decimal(userIdNum),
        mfa_enabled: true,
        dice_enabled: true,
      });
      mockPrismaOltp.user_2fa.findUnique.mockResolvedValue(mockRecord);
      const result = await service.getUser2faStatus(userIdStr);
      expect(result).toEqual({ mfaEnabled: true, diceEnabled: true });
      expect(loggerLogSpy).toHaveBeenCalledWith(
        `Getting 2FA status for user: ${userIdStr}`,
      );
    });

    it('should return default false/false if no record found and log debug message', async () => {
      mockPrismaOltp.user_2fa.findUnique.mockResolvedValue(null);
      const result = await service.getUser2faStatus(userIdStr);
      expect(result).toEqual({ mfaEnabled: false, diceEnabled: false });
      expect(loggerDebugSpy).toHaveBeenCalledWith(
        `No user_2fa record found for user ${userIdNum}, returning default false status.`,
      );
    });

    it('should throw BadRequestException for invalid user ID format', async () => {
      await expect(service.getUser2faStatus('abc')).rejects.toThrow(
        new BadRequestException('Invalid user ID format.'),
      );
    });
  });

  describe('updateUser2faStatus', () => {
    const userIdStr = '1';
    const userIdNum = 1;
    const authUser = createMockAuthUser(userIdStr, {
      handle: 'operatorHandle',
    });
    const userRecordForHandle = createMockUserModel({
      user_id: new Decimal(userIdNum),
      handle: 'targetUserHandle',
    });

    beforeEach(() => {
      mockPrismaOltp.user.findUnique.mockResolvedValue(userRecordForHandle);
    });

    it('should throw BadRequestException if userId is NaN', async () => {
      await expect(
        service.updateUser2faStatus('abc', { mfaEnabled: true }, authUser),
      ).rejects.toThrow(new BadRequestException('Invalid user ID format.'));
    });

    it('should throw BadRequestException if DTO has no relevant properties', async () => {
      await expect(
        service.updateUser2faStatus(userIdStr, {} as DTOs.User2faDto, authUser),
      ).rejects.toThrow(
        new BadRequestException(
          'At least one of mfaEnabled or diceEnabled must be provided.',
        ),
      );
    });

    it('should throw BadRequestException if dto.diceEnabled is true', async () => {
      await expect(
        service.updateUser2faStatus(userIdStr, { diceEnabled: true }, authUser),
      ).rejects.toThrow(
        new BadRequestException(
          'DICE cannot be enabled directly through this endpoint. Use DICE connection flow.',
        ),
      );
    });

    // Path: !user2fa (create new record)
    describe('when creating new user_2fa record', () => {
      beforeEach(() => {
        mockPrismaOltp.user_2fa.findUnique.mockResolvedValue(null);
        mockPrismaOltp.email.count.mockResolvedValue(1); // Default to 1 email
        mockPrismaOltp.user_2fa.create.mockImplementation((args) =>
          Promise.resolve(createMockUser2faModel(args.data)),
        );
      });

      it('should create with mfaEnabled true, diceEnabled false, and log multi-email warning if applicable', async () => {
        mockPrismaOltp.email.count.mockResolvedValue(3); // Trigger multi-email warning
        const result = await service.updateUser2faStatus(
          userIdStr,
          { mfaEnabled: true },
          authUser,
        );
        expect(loggerLogSpy).toHaveBeenCalledWith(
          expect.stringContaining(
            `No existing user_2fa record for user ${userIdNum}. Creating new record.`,
          ),
        );
        expect(loggerWarnSpy).toHaveBeenCalledWith(
          `User ${userIdNum} has multiple emails (3) and is setting up 2FA for the first time.`,
        );
        expect(mockPrismaOltp.user_2fa.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            user_id: userIdNum,
            mfa_enabled: true,
            dice_enabled: false,
            created_by: userIdNum,
            modified_by: userIdNum,
          }),
        });
        expect(result).toEqual({ mfaEnabled: true, diceEnabled: false });
      });

      it('should throw InternalServerErrorException if authUser.userId is not parseable for create', async () => {
        const invalidAuthUser = createMockAuthUser('abc-operator');
        await expect(
          service.updateUser2faStatus(
            userIdStr,
            { mfaEnabled: true },
            invalidAuthUser,
          ),
        ).rejects.toThrow(InternalServerErrorException);
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          expect.stringContaining(
            'CRITICAL: authUser.userId could not be parsed',
          ),
        );
      });

      it('should force diceEnabledForCreate to false if mfaEnabledForCreate is false', async () => {
        const dto: DTOs.User2faDto = {
          mfaEnabled: false,
          diceEnabled: undefined,
        };
        const result = await service.updateUser2faStatus(
          userIdStr,
          dto,
          authUser,
        );

        expect(mockPrismaOltp.user_2fa.create).toHaveBeenCalledWith(
          expect.objectContaining({
            data: expect.objectContaining({
              mfa_enabled: false,
              dice_enabled: false, // This is the key assertion for the first if
            }),
          }),
        );
        expect(result).toEqual({ mfaEnabled: false, diceEnabled: false });
        // The specific warning for "Attempt to create..." should NOT be called here
        expect(loggerWarnSpy).not.toHaveBeenCalledWith(
          expect.stringContaining(
            'Attempt to create 2FA record with DICE enabled but MFA disabled',
          ),
        );
      });
    });

    // Path: user2fa exists (update existing record)
    describe('when updating existing user_2fa record', () => {
      const existingUser2fa = createMockUser2faModel({
        user_id: new Decimal(userIdNum),
        mfa_enabled: true,
        dice_enabled: true,
      });
      beforeEach(() => {
        mockPrismaOltp.user_2fa.findUnique.mockResolvedValue(existingUser2fa);
        mockPrismaOltp.user_2fa.update.mockImplementation((args) =>
          Promise.resolve({ ...existingUser2fa, ...args.data }),
        );
      });

      it('should update mfa_enabled, and if mfa_enabled becomes false, set dice_enabled to false and delete dice connections', async () => {
        mockPrismaOltp.dice_connection.deleteMany.mockResolvedValue({
          count: 1,
        });
        const result = await service.updateUser2faStatus(
          userIdStr,
          { mfaEnabled: false },
          authUser,
        );

        expect(mockPrismaOltp.user_2fa.update).toHaveBeenCalledWith({
          where: { user_id: userIdNum },
          data: expect.objectContaining({
            mfa_enabled: false,
            dice_enabled: false,
            modified_by: userIdNum,
          }),
        });
        expect(loggerLogSpy).toHaveBeenCalledWith(
          expect.stringContaining(
            `DICE was enabled and is now disabled for user ${userIdNum}`,
          ),
        );
        expect(mockPrismaOltp.dice_connection.deleteMany).toHaveBeenCalledWith({
          where: { user_id: userIdNum },
        });
        expect(mockSlackService.sendNotification).toHaveBeenCalledWith(
          'DICE disabled :crying_cat_face:',
          'targetUserHandle',
        );
        expect(result).toEqual({ mfaEnabled: false, diceEnabled: false });
      });

      it('should update dice_enabled to false if mfa is true and dto specifies diceEnabled: false', async () => {
        // existing mfa_enabled: true, dice_enabled: true
        // dto: {diceEnabled: false} -> mfa_enabled remains true from existing, dice_enabled becomes false
        const result = await service.updateUser2faStatus(
          userIdStr,
          { diceEnabled: false },
          authUser,
        );
        expect(mockPrismaOltp.user_2fa.update).toHaveBeenCalledWith({
          where: { user_id: userIdNum },
          // dataToUpdate would be { dice_enabled: false, modified_by: ..., modified_at: ... }
          // as mfaEnabled is not in DTO, it's not in dataToUpdate.
          data: expect.objectContaining({
            dice_enabled: false,
            modified_by: userIdNum,
          }),
        });
        expect(result.diceEnabled).toBe(false);
        expect(result.mfaEnabled).toBe(true); // from existing record as it wasn't changed by DTO
        expect(mockSlackService.sendNotification).toHaveBeenCalledWith(
          'DICE disabled :crying_cat_face:',
          'targetUserHandle',
        );
      });

      it('should correctly handle undefined authUser.userId for modified_by (if service logic implies default or error)', async () => {
        // Service code: if (authUser && authUser.userId) { dataToUpdate.modified_by = ... }
        // If authUser or userId is undefined, modified_by won't be set by this block.
        // This test assumes Prisma schema might have a default or nullable modified_by,
        // or the service should handle it. The current service code simply doesn't set it.
        const noOperatorAuthUser = createMockAuthUser(undefined as any); // Simulate undefined userId
        await service.updateUser2faStatus(
          userIdStr,
          { mfaEnabled: false },
          noOperatorAuthUser,
        );
        expect(mockPrismaOltp.user_2fa.update).toHaveBeenCalledWith(
          expect.objectContaining({
            data: expect.not.objectContaining({
              modified_by: expect.any(Number),
            }),
          }),
        );
      });

      it('should log error if slack notification fails when DICE is disabled', async () => {
        const slackError = new Error('Slack down');
        mockSlackService.sendNotification.mockRejectedValueOnce(slackError);
        await service.updateUser2faStatus(
          userIdStr,
          { mfaEnabled: false },
          authUser,
        ); // This disables DICE
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          'Slack notification failed',
          slackError,
        );
      });
    });
  });

  describe('sendOtpFor2fa', () => {
    const userIdStr = '1';
    const userIdNum = 1;
    const userRecord = createMockUserModel({
      user_id: new Decimal(userIdNum),
      handle: 'otpUser',
    });
    const emailRecord = createMockEmailModel({
      user_id: new Decimal(userIdNum),
      address: 'otp@example.com',
    });

    beforeEach(() => {
      mockPrismaOltp.user.findUnique.mockResolvedValue(userRecord);
      mockPrismaOltp.email.findFirst.mockResolvedValue(emailRecord);
      mockCacheManager.set.mockResolvedValue(undefined);
      (mockEventService as any).postDirectBusMessage = jest
        .fn()
        .mockResolvedValue(undefined);
      (jwt.sign as jest.Mock).mockReturnValue('mocked-resend-token');
      jest
        .spyOn(TwoFactorAuthService.prototype as any, 'generateNumericOtp')
        .mockReturnValue('112233');
    });

    it('should throw BadRequestException if userId is NaN', async () => {
      await expect(service.sendOtpFor2fa('abc')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw NotFoundException if user not found', async () => {
      mockPrismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(service.sendOtpFor2fa(userIdStr)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw InternalServerErrorException if primary email not found', async () => {
      mockPrismaOltp.email.findFirst.mockResolvedValue(null);
      await expect(service.sendOtpFor2fa(userIdStr)).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should throw InternalServerErrorException if email address is empty', async () => {
      mockPrismaOltp.email.findFirst.mockResolvedValue({ address: '' });
      await expect(service.sendOtpFor2fa(userIdStr)).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should successfully generate OTP, cache it, and return resend token', async () => {
      const result = await service.sendOtpFor2fa(userIdStr);

      // Verify OTP was cached with correct key and expiry
      const expectedCacheKey = `${TFA_OTP_CACHE_PREFIX_KEY}:${userIdStr}`;
      expect(mockCacheManager.set).toHaveBeenCalledWith(
        expectedCacheKey,
        '112233',
        TFA_OTP_EXPIRY_SECONDS * 1000,
      );

      // Verify JWT token generation
      expect(jwt.sign).toHaveBeenCalledWith(
        { sub: userIdStr, aud: OTP_2FA_AUDIENCE },
        'test-2fa-jwt-secret-for-service',
        { expiresIn: `${TFA_RESEND_TOKEN_EXPIRY_SECONDS}s` },
      );

      // Verify email event was published
      expect(
        (mockEventService as any).postDirectBusMessage,
      ).toHaveBeenCalledWith(
        'external.action.email',
        expect.objectContaining({
          data: expect.objectContaining({
            userId: userIdStr,
            email: 'otp@example.com',
            handle: 'otpUser',
            code: '112233',
            durationMinutes: TFA_OTP_EXPIRY_SECONDS / 60,
          }),
          recipients: ['otp@example.com'],
        }),
      );

      expect(result).toEqual({ resendToken: 'mocked-resend-token' });
    });

    it('should log error if eventService.postDirectBusMessage throws but still return token', async () => {
      const eventError = new Error('Event publish failed');
      (mockEventService as any).postDirectBusMessage = jest
        .fn()
        .mockRejectedValueOnce(eventError);

      const result = await service.sendOtpFor2fa(userIdStr); // The method itself should not throw due to this

      expect(loggerErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to publish 2FA OTP email event'),
        eventError.stack,
      );
      expect(result).toEqual({ resendToken: 'mocked-resend-token' });
    });

    it('should use default domain when APP_DOMAIN config is not set', async () => {
      // Temporarily override config to return undefined for APP_DOMAIN
      const originalGet = mockConfigService.get;
      mockConfigService.get = jest.fn((key: string, defaultValue?: any) => {
        if (key === 'APP_DOMAIN') return undefined;
        return originalGet(key, defaultValue);
      });

      await service.sendOtpFor2fa(userIdStr);

      expect(
        (mockEventService as any).postDirectBusMessage,
      ).toHaveBeenCalledWith(
        'external.action.email',
        expect.objectContaining({
          from: { email: 'Topcoder <noreply@topcoder-dev.com>' },
        }),
      );

      // Restore original mock
      mockConfigService.get = originalGet;
    });

    it('should query user with correct select fields', async () => {
      await service.sendOtpFor2fa(userIdStr);

      expect(mockPrismaOltp.user.findUnique).toHaveBeenCalledWith({
        where: { user_id: userIdNum },
        select: { handle: true },
      });
    });

    it('should query primary email with correct filters', async () => {
      await service.sendOtpFor2fa(userIdStr);

      expect(mockPrismaOltp.email.findFirst).toHaveBeenCalledWith({
        where: { user_id: userIdNum, primary_ind: 1, status_id: 1 },
        select: { address: true },
      });
    });
  });

  describe('resendOtpEmailFor2fa', () => {
    const token = 'valid-token';
    const userIdStr = '1';
    const userRecord = createMockUserModel({
      user_id: new Decimal(1),
      handle: 'resendUser',
    });
    const emailRecord = createMockEmailModel({
      user_id: new Decimal(1),
      address: 'resend@example.com',
    });

    beforeEach(() => {
      (jwt.verify as jest.Mock).mockReturnValue({
        sub: userIdStr,
        aud: OTP_2FA_AUDIENCE,
      });
      mockPrismaOltp.user.findUnique.mockResolvedValue(userRecord);
      mockPrismaOltp.email.findFirst.mockResolvedValue(emailRecord);
      jest
        .spyOn(TwoFactorAuthService.prototype as any, 'generateNumericOtp')
        .mockReturnValue('334455');
    });

    it('should throw BadRequestException if TokenExpiredError occurs', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.TokenExpiredError('expired test');
      });
      await expect(service.resendOtpEmailFor2fa(token)).rejects.toThrow(
        new BadRequestException('Resend token has expired.'),
      );
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          '2FA resend token validation failed: expired test',
        ),
      );
    });

    it('should throw BadRequestException for other jwt.verify errors', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('generic verify error');
      });
      await expect(service.resendOtpEmailFor2fa(token)).rejects.toThrow(
        new BadRequestException('Invalid or expired resend token.'),
      );
    });

    it('should throw BadRequestException if userId (sub) not in decoded payload', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({ aud: OTP_2FA_AUDIENCE }); // No 'sub'
      await expect(service.resendOtpEmailFor2fa(token)).rejects.toThrow(
        new BadRequestException('User ID not found in resend token payload.'),
      );
    });

    it('should throw BadRequestException if userId in token is NaN', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({
        sub: 'abc',
        aud: OTP_2FA_AUDIENCE,
      });
      await expect(service.resendOtpEmailFor2fa(token)).rejects.toThrow(
        new BadRequestException('Invalid user ID format in token.'),
      );
    });

    it('should throw NotFoundException if user not found via token userId', async () => {
      mockPrismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(service.resendOtpEmailFor2fa(token)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw InternalServerErrorException if primary email not found for user', async () => {
      mockPrismaOltp.email.findFirst.mockResolvedValue(null);
      await expect(service.resendOtpEmailFor2fa(token)).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    // it('should log error if eventService.postEnvelopedNotification throws during resend', async () => {
    //     const eventError = new Error("Resend Event publish failed");
    //     mockEventService.postEnvelopedNotification.mockRejectedValueOnce(eventError);
    //     await service.resendOtpEmailFor2fa(token);
    //     expect(loggerErrorSpy).toHaveBeenCalledWith(expect.stringContaining('Failed to publish 2FA OTP resend email event'), eventError.stack);
    // });

    it('should throw NotFoundException if user not found for final response (after successful OTP ops)', async () => {
      // Setup for successful OTP operations
      (jwt.verify as jest.Mock).mockReturnValue({
        sub: userIdStr,
        aud: OTP_2FA_AUDIENCE,
      });
      mockPrismaOltp.user.findUnique.mockResolvedValueOnce(userRecord); // For initial lookup
      mockPrismaOltp.email.findFirst.mockResolvedValue(emailRecord);
      mockCacheManager.set.mockResolvedValue(undefined);
      mockEventService.postEnvelopedNotification.mockResolvedValue(undefined);
      mockCacheManager.del.mockResolvedValue(undefined);

      // Make the final user lookup fail
      mockPrismaOltp.user.findUnique.mockResolvedValueOnce(null); // For userForResponse

      await expect(service.resendOtpEmailFor2fa(token)).rejects.toThrow(
        new NotFoundException(
          'User not found after OTP check for final response.',
        ),
      );
    });
    // Successful path already covered
  });

  describe('checkOtpAndCompleteLogin', () => {
    const userIdStr = '1';
    const otp = '123456';

    it('should throw BadRequestException if OTP not in cache and log warning', async () => {
      mockCacheManager.get.mockResolvedValue(null);
      await expect(
        service.checkOtpAndCompleteLogin(userIdStr, otp),
      ).rejects.toThrow(
        new BadRequestException(
          '2FA OTP has expired or was not found. Please request a new one.',
        ),
      );
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          `2FA OTP not found or expired in cache for user ${userIdStr}`,
        ),
      );
    });

    it('should throw BadRequestException if OTP does not match and log warning', async () => {
      mockCacheManager.get.mockResolvedValue('654321'); // Wrong OTP in cache
      await expect(
        service.checkOtpAndCompleteLogin(userIdStr, otp),
      ).rejects.toThrow(new BadRequestException('Invalid 2FA OTP.'));
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          `Invalid 2FA OTP provided for user ${userIdStr}`,
        ),
      );
    });

    it('should throw NotFoundException if user not found for final response', async () => {
      mockCacheManager.get.mockResolvedValue(otp); // Correct OTP
      mockPrismaOltp.user.findUnique.mockResolvedValue(null); // User not found
      await expect(
        service.checkOtpAndCompleteLogin(userIdStr, otp),
      ).rejects.toThrow(
        new NotFoundException(
          'User not found after OTP check for final response.',
        ),
      );
    });
  });
});
