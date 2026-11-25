import { verifySignedJwt } from 'tc-core-library-js';
jest.mock('tc-core-library-js', () => ({
  ...jest.requireActual('tc-core-library-js'),
  verifySignedJwt: jest.fn(),
}));
import { Test, TestingModule } from '@nestjs/testing';
import { AuthFlowService } from './auth-flow.service';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
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
} from '@prisma/client';
import { RoleResponseDto } from 'src/dto/role/role.dto';
import { ACTIVATION_OTP_EXPIRY_SECONDS } from './user.service';
import { Decimal } from '@prisma/client/runtime/library';
import * as jwt from 'jsonwebtoken';
import { randomUUID as uuidv4 } from 'node:crypto';
import { ValidationService } from './validation.service';
import { MemberPrismaService } from '../../shared/member-prisma/member-prisma.service';

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
  user_otp_email: {
    findUnique: jest.fn(),
    upsert: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
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

const mockVerifyLegacyPassword = jest.fn();
const mockUserService = {
  findUserById: jest.fn(),
  notifyWelcome: jest.fn(),
  assignDefaultUserRole: jest.fn(),
  findUserByEmailOrHandle: jest.fn(),
  encodePasswordLegacy: jest.fn(),
  generateSSOToken: jest.fn(),
  checkEmailAvailabilityForUser: jest.fn(),
  verifyLegacyPassword: mockVerifyLegacyPassword,
};

const mockEventService = {
  postEnvelopedNotification: jest.fn(),
  postDirectBusMessage: jest.fn(),
};

const mockRoleService = {
  findAll: jest.fn(),
};
const mockValidationService = {
  validateEmail: jest.fn(),
  validatePassword: jest.fn(),
};
const mockMemberPrisma = {
  member: {
    update: jest.fn(),
  },
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
jest.mock('node:crypto', () => ({
  ...jest.requireActual('node:crypto'),
  randomUUID: jest.fn(),
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

  beforeEach(async () => {
    jest.clearAllMocks();
    mockVerifyLegacyPassword.mockReturnValue('sha256HashedValue');
    loggerErrorSpy = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => {});
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthFlowService,
        { provide: PRISMA_CLIENT, useValue: mockPrismaOltp },
        { provide: CACHE_MANAGER, useValue: mockCacheManager },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: UserService, useValue: mockUserService },
        { provide: EventService, useValue: mockEventService },
        { provide: RoleService, useValue: mockRoleService },
        { provide: ValidationService, useValue: mockValidationService },
        { provide: MemberPrismaService, useValue: mockMemberPrisma },
      ],
    })
      .setLogger(nullLogger)
      .compile();

    service = module.get<AuthFlowService>(AuthFlowService);
    prismaOltp = module.get(PRISMA_CLIENT);
    cacheManager = module.get(CACHE_MANAGER);
    configService = module.get(ConfigService);
    userService = module.get(UserService);
    eventService = module.get(EventService);
    roleService = module.get(RoleService);

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
            mockValidationService as any,
            mockMemberPrisma as any,
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
            mockValidationService as any,
            mockMemberPrisma as any,
          ),
      );
    });
  });

  describe('activation and resend', () => {
    const userId = 1;
    const otp = '012345';
    const resendToken = 'valid.resend.token';
    const email = { email_id: 2, address: 'pending@example.com' };
    const activate = () =>
      service.activateUser({ param: { userId, otp, resendToken } });
    const resend = () =>
      service.requestResendActivation({ userId, resendToken });
    const code = {
      id: 3,
      otp,
      expire_at: new Date(Date.now() + 60000),
      fail_count: 0,
      activation_sends: [],
      activation_failures: [],
    };

    beforeEach(() => {
      (verifySignedJwt as jest.Mock).mockReset();
      prismaOltp.$queryRaw.mockResolvedValue([{ status: 'U' }]);
      prismaOltp.user_otp_email.findUnique.mockResolvedValue(code);
      prismaOltp.email.findFirst.mockResolvedValue(email);
    });

    it('consumes the code, verifies the primary address and sends the welcome email', async () => {
      prismaOltp.user.findUnique.mockResolvedValue({ status: 'A' });
      await expect(activate()).resolves.toEqual({ status: 'A' });
      expect(prismaOltp.email.update).toHaveBeenCalledWith({
        where: { ...email, primary_ind: 1 },
        data: { status_id: 1, modify_date: expect.any(Date) },
      });
      expect(prismaOltp.user_otp_email.delete).toHaveBeenCalledWith({
        where: { id: code.id },
      });
      expect(mockUserService.notifyWelcome).toHaveBeenCalledWith(
        userId,
        email.address,
      );
    });

    it('persists the replacement and email job in the same write', async () => {
      await expect(resend()).resolves.toMatchObject({ message: 'SUCCESS' });
      const { create, update } =
        prismaOltp.user_otp_email.upsert.mock.calls[0][0];
      expect(create).toEqual({ ...update, user_id: userId, mode: 1 });
      expect(update.otp).toMatch(/^\d{6}$/);
      expect(update.otp).not.toBe(otp);
      expect(update.delivery_due_at).toEqual(expect.any(Date));
      expect(update.delivery_recipient).toBe(email.address);
      expect(eventService.postDirectBusMessage).not.toHaveBeenCalled();
    });

    it('rejects missing input before reading the database', async () => {
      for (const field of ['userId', 'otp', 'resendToken']) {
        await expect(
          service.activateUser({
            param: { userId, otp, resendToken, [field]: undefined },
          }),
        ).rejects.toThrow(BadRequestException);
      }
      for (const field of ['userId', 'resendToken']) {
        await expect(
          service.requestResendActivation({
            userId,
            resendToken,
            [field]: undefined,
          }),
        ).rejects.toThrow(BadRequestException);
      }
      expect(prismaOltp.$transaction).not.toHaveBeenCalled();
    });

    for (const operation of [activate, resend]) {
      describe(operation.name, () => {
        it.each([
          [new Error('Token user mismatch'), ForbiddenException],
          [new Error('jwt malformed'), ForbiddenException],
          [new jwt.TokenExpiredError('expired', new Date()), GoneException],
        ])(
          'requires a valid account-bound activation proof',
          async (error, exception) => {
            (verifySignedJwt as jest.Mock).mockImplementation(() => {
              throw error;
            });
            await expect(operation()).rejects.toThrow(exception);
            expect(verifySignedJwt).toHaveBeenCalledWith(
              resendToken,
              'test-jwt-secret',
              { audience: OTP_ACTIVATION_JWT_AUDIENCE, userId },
            );
            expect(prismaOltp.$transaction).not.toHaveBeenCalled();
          },
        );
        it.each([
          [[], NotFoundException],
          [[{ status: 'A' }], BadRequestException],
          [[{ status: 'I' }], ForbiddenException],
        ])(
          'requires an existing unverified account',
          async (rows, exception) => {
            prismaOltp.$queryRaw.mockResolvedValue(rows);
            await expect(operation()).rejects.toThrow(exception);
          },
        );
        it('requires a registered primary email', async () => {
          prismaOltp.email.findFirst.mockResolvedValue(null);
          await expect(operation()).rejects.toThrow(
            InternalServerErrorException,
          );
        });
      });
    }

    it('rejects a missing or expired code on activation', async () => {
      prismaOltp.user_otp_email.findUnique.mockResolvedValueOnce(null);
      await expect(activate()).rejects.toThrow(NotFoundException);
      prismaOltp.user_otp_email.findUnique.mockResolvedValueOnce({
        ...code,
        expire_at: new Date(0),
      });
      await expect(activate()).rejects.toThrow('Activation code expired');
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

    beforeEach(() => {
      prismaOltp.user.findUnique.mockResolvedValue(mockUser);
      prismaOltp.security_user.findUnique.mockResolvedValue(mockSecurityUser);
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
    it('should throw InternalServerErrorException on VerifyLegacyPassword decryption error', async () => {
      mockVerifyLegacyPassword.mockImplementation(() => {
        throw new InternalServerErrorException('Password encoding failed.');
      });
      await expect(
        service.generateOneTimeToken(userIdString, passwordPlain),
      ).rejects.toThrow(InternalServerErrorException);
    });
    it('should throw UnauthorizedException for password mismatch', async () => {
      mockVerifyLegacyPassword.mockReturnValue(false);
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
      (verifySignedJwt as jest.Mock).mockReturnValue({
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
      (verifySignedJwt as jest.Mock).mockImplementation(() => {
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
      (verifySignedJwt as jest.Mock).mockReturnValue({
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
    it('should replace an array or unapproved reset URL with the safe default', async () => {
      await service.initiatePasswordReset(
        emailOrHandle,
        ['https://topcoder.com.attacker.example/reset'] as any,
        ['connect'] as any,
      );

      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'userpasswordreset',
        expect.objectContaining({
          data: expect.objectContaining({
            resetPassworUrlPrefix: 'https://www.topcoder.com/reset-password',
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
        .mockReset()
        .mockResolvedValue(mockPrimaryEmail);
      prismaOltp.security_user.findUnique.mockResolvedValue(mockSecurityUser);
      roleService.findAll.mockResolvedValue(mockRoles);
    });

    it.each(['handle', 'email'])(
      'rejects unverified login by %s after checking the password',
      async (identifier) => {
        prismaOltp.user.findFirst.mockResolvedValue({
          ...mockUserRecord,
          status: 'U',
        });
        prismaOltp.user.findUnique.mockResolvedValue({
          ...mockUserRecord,
          status: 'U',
        });
        mockVerifyLegacyPassword.mockReturnValue(true);
        await expect(
          service.authenticateForAuth0(
            identifier === 'email' ? email : handle,
            passwordPlain,
          ),
        ).rejects.toMatchObject({
          response: { code: 'EMAIL_VERIFICATION_REQUIRED' },
        });
        expect(roleService.findAll).not.toHaveBeenCalled();
      },
    );

    it.each([null, 0, 2])(
      'rejects active accounts with unverified or missing primary email (%s)',
      async (status) => {
        prismaOltp.email.findFirst.mockReset().mockResolvedValue(
          status === null
            ? null
            : {
                ...mockPrimaryEmail,
                status_id: new Decimal(status),
              },
        );
        mockVerifyLegacyPassword.mockReturnValue(true);
        await expect(
          service.authenticateForAuth0(handle, passwordPlain),
        ).rejects.toThrow(ForbiddenException);
        expect(roleService.findAll).not.toHaveBeenCalled();
      },
    );

    it('allows an active account with verified email', async () => {
      mockVerifyLegacyPassword.mockReturnValue(true);
      await expect(
        service.authenticateForAuth0(handle, passwordPlain),
      ).resolves.toMatchObject({ emailActive: true, active: true });
    });

    it('should throw UnauthorizedException for user not found (by handle)', async () => {
      prismaOltp.user.findFirst.mockResolvedValue(null);
      await expect(
        service.authenticateForAuth0('unknownHandle', passwordPlain),
      ).rejects.toThrow(UnauthorizedException);
    });
    it('should throw UnauthorizedException for user not found (by email)', async () => {
      prismaOltp.email.findFirst.mockResolvedValueOnce(null); // Email not found
      await expect(
        service.authenticateForAuth0('unknown@example.com', passwordPlain),
      ).rejects.toThrow(UnauthorizedException);
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
    it('should throw InternalServerErrorException on VerifyLegacyPassword decryption error', async () => {
      mockVerifyLegacyPassword.mockImplementation(() => {
        throw new InternalServerErrorException('Password encoding failed.');
      });
      await expect(
        service.authenticateForAuth0(handle, passwordPlain),
      ).rejects.toThrow(InternalServerErrorException);
    });
    it('should throw UnauthorizedException for password mismatch', async () => {
      mockVerifyLegacyPassword.mockReturnValue(false);
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
        .mockReset()
        .mockResolvedValue(mockPrimaryEmail);
      prismaOltp.user_otp_email.findUnique.mockResolvedValue({
        fail_count: 0,
        expire_at: new Date(Date.now() + 60000),
        activation_sends: [],
        activation_failures: [],
      });
      roleService.findAll.mockResolvedValue(mockRoles);
      userService.generateSSOToken.mockResolvedValue(mockTcssoToken);
      (jwt.sign as jest.Mock).mockReturnValue(mockResendActivationToken);
    });

    it('should return user profile with tcsso for an active user', async () => {
      const profile = await service.getUserProfileForAuth0(handle);
      expect(profile.id).toBe(userId.toString());
      expect(profile.handle).toBe(handle);
      expect(profile.email).toBe(email);
      expect(profile.roles).toEqual(mockRoles);
      expect(profile.regSource).toBe(mockTcssoToken);
      expect(profile.status).toBe('A');
      expect(profile.credential.resendToken).toBeNull();
    });
    it('should return user profile with resendToken for an unverified user (U)', async () => {
      prismaOltp.user.findFirst.mockResolvedValue({ ...mockUser, status: 'U' });
      const profile = await service.getUserProfileForAuth0(handle);
      expect(profile.status).toBe('U');
      expect(profile.regSource).toBeNull();
      expect(userService.generateSSOToken).not.toHaveBeenCalled();
      expect(profile.credential.resendToken).toBe(mockResendActivationToken);
      expect(profile.credential.canResend).toBe(true);
      expect(jwt.sign).toHaveBeenCalledWith(
        {
          sub: userId.toString(),
          userId: userId.toString(),
          aud: OTP_ACTIVATION_JWT_AUDIENCE,
        },
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
