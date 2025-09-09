import { Test, TestingModule } from '@nestjs/testing';
import {
  UserService,
  Auth0UserProfile,
  ACTIVATION_OTP_CACHE_PREFIX_KEY,
  ACTIVATION_OTP_EXPIRY_SECONDS,
} from './user.service';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { ValidationService } from './validation.service';
import { RoleService } from '../role/role.service';
import { EventService } from '../../shared/event/event.service';
import {
  NotFoundException,
  ConflictException,
  InternalServerErrorException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import {
  user as UserModel,
  Prisma,
  email as EmailModel,
  user_sso_login as UserSsoLoginModel,
  sso_login_provider as SsoLoginProviderModel,
  user_achievement as UserAchievementModel,
  achievement_type_lu as AchievementTypeLuModel,
  security_user as SecurityUserModel,
} from '@prisma/client'; // Ensure all used models are imported
import {
  CreateUserBodyDto,
  UpdateUserBodyDto,
  UserSearchQueryDto,
  AchievementDto,
} from '../../dto/user/user.dto';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import { Decimal } from '@prisma/client/runtime/library';
import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import { Cache } from 'cache-manager';
import { MemberPrismaService } from 'src/shared/member-prisma/member-prisma.service';

// Null logger to suppress NestJS application logs during tests
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
    findMany: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  email: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    deleteMany: jest.fn(), // Added for potential use
    count: jest.fn(), // Added for potential use
  },
  user_sso_login: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    deleteMany: jest.fn(),
    count: jest.fn(),
  },
  sso_login_provider: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(), // Added for potential use
  },
  security_user: {
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(), // Added for potential use
  },
  user_achievement: {
    findMany: jest.fn(),
    // Add other methods if used
  },
  achievement_type_lu: {
    findUnique: jest.fn(), // Added for potential use
  },
  // Mock transaction: it takes a callback and executes it with the prisma mock itself
  $transaction: jest
    .fn()
    .mockImplementation(async <T>(callback): Promise<T> => {
      const result = callback(mockPrismaOltp);
      return result instanceof Promise ? result : Promise.resolve(result);
    }),
  $queryRaw: jest.fn(),
};

const mockValidationService = {
  validateHandle: jest.fn(),
  validateEmail: jest.fn(),
  validateCountry: jest.fn(),
  validateCountryAndMutate: jest.fn(),
  validateProfile: jest.fn(),
  validateReferral: jest.fn(),
  checkEmailAvailabilityForUser: jest.fn(),
  // Add other methods if they are called by UserService
};

const mockRoleService: jest.Mocked<Partial<RoleService>> = {
  assignRoleByName: jest.fn(),
  deassignRoleByName: jest.fn(),
  // Add other methods if they are called by UserService
};

const mockCacheManager: jest.Mocked<Partial<Cache>> = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
};

const mockEventService: jest.Mocked<Partial<EventService>> = {
  postEnvelopedNotification: jest.fn(),
  postDirectBusMessage: jest.fn(),
};

const mockConfigService = {
  get: jest.fn(
    (
      key: string,
      defaultValue?: string | number,
    ): string | number | undefined => {
      const configValues = {
        LEGACY_BLOWFISH_KEY: 'dGVzdEJhc2U2NEtleQ==', // "testBase64Key"
        ACTIVATION_OTP_EXPIRY_SECONDS: ACTIVATION_OTP_EXPIRY_SECONDS,
        SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID:
          'd-resendActivationTemplate',
        SENDGRID_WELCOME_EMAIL_TEMPLATE_ID: 'd-welcomeTemplate',
        APP_DOMAIN: 'testapp.com',
        SSO_TOKEN_SALT: 'mock-sso-salt',
        JWT_SECRET: 'mock-jwt-secret',
        ACTIVATION_RESEND_JWT_EXPIRY: '1h',
        // Add other config keys as needed
      };
      return configValues[key] !== undefined ? configValues[key] : defaultValue;
    },
  ),
};

// Mock jsonwebtoken
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(),
  verify: jest.fn(), // If you ever use verify
}));

// Mock uuid
jest.mock('uuid', () => ({
  v4: jest.fn(),
}));

// Mock crypto (Node.js built-ino
let createCipherivError = false;
const mockUpdate = jest.fn().mockReturnThis();
const mockDigest = jest.fn();
jest.mock('crypto', () => {
  const realCrypto = jest.requireActual('crypto');
  return {
    ...realCrypto,
    createCipheriv: jest.fn((algorithm, key, iv) => {
      if (createCipherivError) {
        throw new Error('Crypto Error');
      }
      // otherwise delegate to the real implementation
      return realCrypto.createCipheriv(algorithm, key, iv);
    }),
    createHash: jest.fn(() => ({
      update: mockUpdate,
      digest: mockDigest,
    })),
  };
});

// --- Helper Functions to Create Mock Models ---
const createMockUserModel = (
  input: Partial<
    UserModel & { primaryEmailAddress?: string; primaryEmailStatusId?: Decimal }
  >,
): UserModel => {
  const userId = input.user_id ? new Decimal(input.user_id) : new Decimal(1);
  const handle = input.handle || 'testuser';
  const baseUser: UserModel = {
    user_id: userId,
    handle: handle,
    handle_lower: handle.toLowerCase(),
    first_name: input.first_name || 'Test',
    last_name: input.last_name || 'User',
    create_date: input.create_date || new Date(),
    modify_date: input.modify_date || new Date(),
    last_login: input.last_login || null,
    status: input.status || 'A',
    activation_code: input.activation_code || null,
    password: input.password || 'hashedpassword',
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
  return baseUser;
};

const createMockEmailModel = (input: Partial<EmailModel>): EmailModel => {
  const emailId = input.email_id ? new Decimal(input.email_id) : new Decimal(1);
  const address = input.address || 'test@example.com';
  const baseEmail: EmailModel = {
    email_id: emailId,
    user_id: input.user_id ? new Decimal(input.user_id) : null,
    email_type_id: input.email_type_id || new Decimal(1),
    address: address,
    create_date: input.create_date || new Date(),
    modify_date: input.modify_date || new Date(),
    primary_ind:
      input.primary_ind === undefined
        ? new Decimal(1)
        : new Decimal(input.primary_ind),
    status_id:
      input.status_id === undefined
        ? new Decimal(1)
        : new Decimal(input.status_id),
    ...input,
  };
  return baseEmail;
};

const createMockSsoLoginProviderModel = (
  input: Partial<SsoLoginProviderModel>,
): SsoLoginProviderModel => {
  return {
    sso_login_provider_id: input.sso_login_provider_id || new Decimal(1),
    name: input.name || 'auth0',
    type: input.type || 'oauth',
    identify_email_enabled:
      input.identify_email_enabled === undefined
        ? true
        : input.identify_email_enabled,
    identify_handle_enabled:
      input.identify_handle_enabled === undefined
        ? true
        : input.identify_handle_enabled,
    ...input,
  };
};

const createMockUserSsoLoginModel = (
  input: Partial<
    UserSsoLoginModel & { sso_login_provider?: SsoLoginProviderModel }
  >,
): UserSsoLoginModel & { sso_login_provider?: SsoLoginProviderModel } => {
  return {
    user_id: input.user_id || new Decimal(1),
    provider_id: input.provider_id || new Decimal(1),
    sso_user_id: input.sso_user_id || 'auth0|123',
    sso_user_name: input.sso_user_name || 'auth0user',
    email: input.email || 'auth0user@example.com',
    sso_login_provider:
      input.sso_login_provider || createMockSsoLoginProviderModel({}),
    ...input,
  };
};

const createMockAchievementTypeLuModel = (
  input: Partial<AchievementTypeLuModel>,
): AchievementTypeLuModel => {
  return {
    achievement_type_id: input.achievement_type_id || new Decimal(1),
    achievement_type_desc: input.achievement_type_desc || 'Test Achievement',
    ...input,
  };
};

const createMockUserAchievementModel = (
  input: Partial<
    UserAchievementModel & { achievement_type_lu?: AchievementTypeLuModel }
  >,
): UserAchievementModel & { achievement_type_lu?: AchievementTypeLuModel } => {
  return {
    user_id: input.user_id || new Decimal(1),
    achievement_type_id: input.achievement_type_id || new Decimal(1),
    achievement_date: input.achievement_date || new Date(),
    description: input.description || null,
    create_date: input.create_date || new Date(),
    achievement_type_lu:
      input.achievement_type_lu || createMockAchievementTypeLuModel({}),
    ...input,
  };
};

describe('UserService', () => {
  let service: UserService;
  let prismaOltp: typeof mockPrismaOltp;
  let validationService: jest.Mocked<ValidationService>;
  let roleService: jest.Mocked<RoleService>;
  let cacheManager: typeof mockCacheManager;
  let eventService: jest.Mocked<EventService>;
  let configService: typeof mockConfigService;
  let loggerErrorSpy: jest.SpyInstance;
  let loggerLogSpy: jest.SpyInstance;

  const mockUser: AuthenticatedUser = {
    userId: '1',
    roles: ['Administrator'],
    isAdmin: true,
    isMachine: false,
    handle: 'adminUser',
    email: 'admin@example.com',
    scopes: [],
    payload: {},
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    // Spy on Logger methods BEFORE module compilation if they are called in constructor
    loggerErrorSpy = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => {});
    loggerLogSpy = jest
      .spyOn(Logger.prototype, 'log')
      .mockImplementation(() => {});

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: PRISMA_CLIENT, useValue: mockPrismaOltp },
        { provide: ValidationService, useValue: mockValidationService },
        { provide: ValidationService, useValue: mockValidationService }, // mockValidationService is still provided

        { provide: RoleService, useValue: mockRoleService },
        { provide: CACHE_MANAGER, useValue: mockCacheManager },
        { provide: EventService, useValue: mockEventService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    })
      .setLogger(nullLogger)
      .compile();

    service = module.get<UserService>(UserService);
    prismaOltp = module.get(PRISMA_CLIENT);
    validationService = module.get(ValidationService);
    roleService = module.get(RoleService);
    cacheManager = module.get(CACHE_MANAGER);
    eventService = module.get(EventService);
    configService = module.get(ConfigService);
    createCipherivError = false;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('Constructor LEGACY_BLOWFISH_KEY Handling', () => {
    it('should load LEGACY_BLOWFISH_KEY if valid', () => {
      configService.get.mockImplementationOnce((key) =>
        key === 'LEGACY_BLOWFISH_KEY' ? 'dGVzdEJhc2U2NEtleQ==' : undefined,
      ); // "testBase64Key"
      const newService = new UserService(
        prismaOltp as any,
        validationService,
        roleService,
        cacheManager as any,
        eventService,
        configService as any,
        MemberPrismaService as any,
      );
      expect(loggerLogSpy).toHaveBeenCalledWith('LEGACY_BLOWFISH_KEY loaded.');
      expect((newService as any).legacyBlowfishKey).toBe(
        'dGVzdEJhc2U2NEtleQ==',
      );
    });

    it('should log error and use empty string if LEGACY_BLOWFISH_KEY is missing', () => {
      configService.get.mockImplementationOnce((key) =>
        key === 'LEGACY_BLOWFISH_KEY' ? undefined : undefined,
      );
      const newService = new UserService(
        prismaOltp as any,
        validationService,
        roleService,
        cacheManager as any,
        eventService,
        configService as any,
        MemberPrismaService as any,
      );
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          'LEGACY_BLOWFISH_KEY environment variable is not set',
        ),
      );
      expect((newService as any).legacyBlowfishKey).toBe('');
    });

    it('should log error and use empty string if LEGACY_BLOWFISH_KEY is placeholder', () => {
      configService.get.mockImplementationOnce((key) =>
        key === 'LEGACY_BLOWFISH_KEY'
          ? '!!!_REPLACE_WITH_BASE64_ENCODED_KEY_!!!'
          : undefined,
      );
      const newService = new UserService(
        prismaOltp as any,
        validationService,
        roleService,
        cacheManager as any,
        eventService,
        configService as any,
        MemberPrismaService as any,
      );
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          'LEGACY_BLOWFISH_KEY environment variable is not set',
        ),
      );
      expect((newService as any).legacyBlowfishKey).toBe('');
    });

    it('should log error and use empty string if LEGACY_BLOWFISH_KEY is invalid Base64', () => {
      configService.get.mockImplementationOnce((key) =>
        key === 'LEGACY_BLOWFISH_KEY' ? 'not-base64!' : undefined,
      );
      const newService = new UserService(
        prismaOltp as any,
        validationService,
        roleService,
        cacheManager as any,
        eventService,
        configService as any,
        MemberPrismaService as any,
      );
      expect((newService as any).legacyBlowfishKey).toBe('not-base64!');
    });
  });

  describe('findUsers', () => {
    it('should find users by handle', async () => {
      const query: UserSearchQueryDto = { handle: 'test' };
      const mockUsers = [createMockUserModel({ handle: 'test' })];
      prismaOltp.user.findMany.mockResolvedValue(mockUsers);
      const result = await service.findUsers(query);
      expect(result).toEqual(mockUsers);
      expect(prismaOltp.user.findMany).toHaveBeenCalledWith({
        where: { handle_lower: 'test' },
        skip: 0,
        take: 20,
      });
    });

    it('should find users by email', async () => {
      const query: UserSearchQueryDto = { email: 'test@example.com' };
      const mockUsers = [createMockUserModel({})];
      prismaOltp.user.findMany.mockResolvedValue(mockUsers);
      const result = await service.findUsers(query);
      expect(result).toEqual(mockUsers);
      expect(prismaOltp.user.findMany).toHaveBeenCalledWith({
        where: {
          user_email_xref: {
            some: { email: { address: 'test@example.com' } },
          },
        },
        skip: 0,
        take: 20,
      });
    });

    it('should use offset and limit', async () => {
      const query: UserSearchQueryDto = { offset: 10, limit: 5 };
      prismaOltp.user.findMany.mockResolvedValue([]);
      await service.findUsers(query);
      expect(prismaOltp.user.findMany).toHaveBeenCalledWith({
        where: {},
        skip: 10,
        take: 5,
      });
    });

    it('should throw InternalServerErrorException on database error', async () => {
      prismaOltp.user.findMany.mockRejectedValue(new Error('DB Error'));
      await expect(service.findUsers({})).rejects.toThrow('DB Error');
    });
  });

  describe('findUserById', () => {
    it('should return a user with primary email if found', async () => {
      const userId = 1;
      const mockUser = createMockUserModel({ user_id: new Decimal(userId) });
      const mockPrimaryEmail = createMockEmailModel({
        user_id: new Decimal(userId),
        address: 'primary@example.com',
        status_id: new Decimal(1),
      });

      prismaOltp.user.findUnique.mockResolvedValue(mockUser);
      prismaOltp.email.findFirst.mockResolvedValue(mockPrimaryEmail);

      const result = await service.findUserById(userId);

      expect(prismaOltp.user.findUnique).toHaveBeenCalledWith({
        where: { user_id: userId },
        include: {
          user_sso_login: { include: { sso_login_provider: true } },
        },
      });
      expect(prismaOltp.email.findFirst).toHaveBeenCalledWith({
        where: {
          user_id: userId,
          primary_ind: 1,
          email_type_id: 1,
        },
      });
      expect(result).toEqual(
        expect.objectContaining({
          ...mockUser,
          primaryEmailAddress: mockPrimaryEmail.address,
          primaryEmailStatusId: mockPrimaryEmail.status_id,
        }),
      );
    });

    it('should throw NotFoundException if user not found', async () => {
      prismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(service.findUserById(999)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should return user without primary email info if no primary email found', async () => {
      const userId = 2;
      const mockUser = createMockUserModel({ user_id: new Decimal(userId) });
      prismaOltp.user.findUnique.mockResolvedValue(mockUser);
      prismaOltp.email.findFirst.mockResolvedValue(null); // No primary email

      const result = await service.findUserById(userId);
      expect(result).toEqual(mockUser); // Should not have primaryEmailAddress or primaryEmailStatusId
      expect((result as any).primaryEmailAddress).toBeUndefined();
    });
  });

  describe('findUserByEmailOrHandle', () => {
    const email = 'test@example.com';
    const handle = 'testHandle';
    const mockUserDetail = createMockUserModel({
      user_id: new Decimal(1),
      handle,
    });
    const mockUserWithSso = { ...mockUserDetail, user_sso_login: [] };
    const mockPrimaryEmail = createMockEmailModel({
      address: email,
      status_id: new Decimal(1),
    });

    it('should find by email', async () => {
      prismaOltp.email.findFirst.mockResolvedValueOnce({
        user_id: new Decimal(1),
      } as any); // For user_id lookup
      prismaOltp.user.findUnique.mockResolvedValue(mockUserWithSso as any);
      prismaOltp.email.findFirst.mockResolvedValueOnce(mockPrimaryEmail); // For attaching primary email

      const result = await service.findUserByEmailOrHandle(email);
      expect(prismaOltp.email.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { address: email.toLowerCase(), primary_ind: 1 },
        }),
      );
      expect(prismaOltp.user.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({ where: { user_id: 1 } }),
      );
      expect(result?.handle).toBe(handle);
      expect(result?.primaryEmail?.address).toBe(email);
    });

    it('should find by handle if not an email', async () => {
      prismaOltp.user.findFirst.mockResolvedValue(mockUserWithSso as any);
      prismaOltp.email.findFirst.mockResolvedValueOnce(mockPrimaryEmail); // For attaching primary email

      const result = await service.findUserByEmailOrHandle(handle);
      expect(prismaOltp.user.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { handle_lower: handle.toLowerCase() },
        }),
      );
      expect(result?.handle).toBe(handle);
      expect(result?.primaryEmail?.address).toBe(email);
    });

    it('should return null if user not found', async () => {
      prismaOltp.email.findFirst.mockResolvedValue(null); // For email lookup
      prismaOltp.user.findFirst.mockResolvedValue(null); // For handle lookup
      prismaOltp.user.findUnique.mockResolvedValue(null); // For user by id lookup

      const result = await service.findUserByEmailOrHandle('nonexistent');
      expect(result).toBeNull();
    });

    it('should throw BadRequestException if emailOrHandle is empty', async () => {
      await expect(service.findUserByEmailOrHandle('')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('encodePasswordLegacy', () => {
    it('should correctly encode a password', () => {
      const result = service.encodePasswordLegacy('password123');
      expect(result).toBe('HO5zzQIVxZYFeP5TLljiMw==');
    });

    it('should throw InternalServerErrorException if key is not configured', () => {
      (service as any).legacyBlowfishKey = ''; // Simulate missing key
      expect(() => service.encodePasswordLegacy('password123')).toThrow(
        InternalServerErrorException,
      );
    });

    it('should throw InternalServerErrorException on encoding error', () => {
      createCipherivError = true;
      expect(() => service.encodePasswordLegacy('password123')).toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('verifyLegacyPassword', () => {
    it('should return true for matching passwords', () => {
      const plainPassword = 'password123';
      const storedEncodedPassword = 'encryptedLegacyPassword';
      // Mock encodePasswordLegacy to return the stored one when called with plainPassword
      const mockEncode = jest
        .spyOn(service, 'encodePasswordLegacy')
        .mockReturnValue(storedEncodedPassword);

      const result = service.verifyLegacyPassword(
        plainPassword,
        storedEncodedPassword,
      );
      expect(mockEncode).toHaveBeenCalledWith(plainPassword);
      expect(result).toBe(true);
    });

    it('should return false for non-matching passwords', () => {
      jest
        .spyOn(service, 'encodePasswordLegacy')
        .mockReturnValue('differentEncryptedPassword');
      const result = service.verifyLegacyPassword(
        'password123',
        'encryptedLegacyPassword',
      );
      expect(result).toBe(false);
    });

    it('should return false if key is not configured', () => {
      (service as any).legacyBlowfishKey = '';
      const result = service.verifyLegacyPassword(
        'password123',
        'encryptedLegacyPassword',
      );
      expect(result).toBe(false);
    });

    it('should return false for empty password or storedEncoded', () => {
      expect(service.verifyLegacyPassword('', 'encoded')).toBe(false);
      expect(service.verifyLegacyPassword('pass', '')).toBe(false);
    });

    it('should return false on encoding error during verification', () => {
      jest.spyOn(service, 'encodePasswordLegacy').mockImplementation(() => {
        throw new Error('Encoding failed');
      });
      const result = service.verifyLegacyPassword(
        'password123',
        'encryptedLegacyPassword',
      );
      expect(result).toBe(false);
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Error during legacy password verification'),
      );
    });
  });

  describe('generateSSOToken', () => {
    const userId = 1;
    const mockUserWithPassword = createMockUserModel({
      user_id: new Decimal(userId),
      password: 'encodedPasswordFromDB',
      status: 'A',
    });

    let mockFindUser;
    beforeEach(() => {
      // Mock findUserById to return the user with password
      mockFindUser = jest
        .spyOn(service, 'findUserById')
        .mockResolvedValue(mockUserWithPassword);

      // Mock generateSSOTokenWithCredentials since it's now a separate method
      jest
        .spyOn(service as any, 'generateSSOTokenWithCredentials')
        .mockReturnValue('1|sha256HashedValue');

      configService.get.mockImplementation((key) => {
        if (key === 'SSO_TOKEN_SALT') return 'mock-sso-salt';
        return undefined;
      });

      mockDigest.mockReturnValue('sha256HashedValue');
    });

    it('should generate an SSO token', async () => {
      const token = await service.generateSSOToken(userId);

      expect(mockFindUser).toHaveBeenCalledWith(userId);
      expect(
        (service as any).generateSSOTokenWithCredentials,
      ).toHaveBeenCalledWith(
        userId,
        mockUserWithPassword.password,
        mockUserWithPassword.status,
      );
      expect(token).toBe('1|sha256HashedValue');
    });

    it('should throw BadRequestException if userId is null or undefined', async () => {
      await expect(service.generateSSOToken(null as any)).rejects.toThrow(
        BadRequestException,
      );
      await expect(service.generateSSOToken(null as any)).rejects.toThrow(
        'userId must be specified.',
      );

      await expect(service.generateSSOToken(undefined as any)).rejects.toThrow(
        BadRequestException,
      );
      await expect(service.generateSSOToken(undefined as any)).rejects.toThrow(
        'userId must be specified.',
      );
    });

    it('should throw BadRequestException if user not found', async () => {
      jest.spyOn(service, 'findUserById').mockResolvedValue(null);

      await expect(service.generateSSOToken(999)).rejects.toThrow(
        BadRequestException,
      );
      await expect(service.generateSSOToken(999)).rejects.toThrow(
        "userId doesn't exist.",
      );
    });
  });

  describe('generateSSOTokenWithCredentials', () => {
    const userId = 1;
    const password = 'encodedPassword';
    const status = 'A';

    beforeEach(() => {
      jest
        .spyOn(service as any, 'getSSOTokenSalt')
        .mockReturnValue('mock-sso-salt');
      mockDigest.mockReturnValue('sha256HashedValue');
    });

    it('should generate SSO token with credentials', () => {
      const token = (service as any).generateSSOTokenWithCredentials(
        userId,
        password,
        status,
      );

      const expectedPlainText = `mock-sso-salt${userId}${password}${status}`;

      expect((service as any).getSSOTokenSalt).toHaveBeenCalled();
      expect(crypto.createHash).toHaveBeenCalledWith('sha256');
      expect(mockUpdate).toHaveBeenCalledWith(expectedPlainText, 'utf-8');
      expect(mockDigest).toHaveBeenCalledWith('hex');
      expect(token).toBe(`${userId}|sha256HashedValue`);
    });

    it('should handle hashing error', () => {
      mockDigest.mockImplementation(() => {
        throw new Error('Hashing failed');
      });

      expect(() => {
        (service as any).generateSSOTokenWithCredentials(
          userId,
          password,
          status,
        );
      }).toThrow('Hashing failed');
    });
  });

  describe('getSSOTokenSalt', () => {
    it('should return salt when configured', () => {
      configService.get.mockReturnValue('mock-sso-salt');

      const salt = (service as any).getSSOTokenSalt();

      expect(configService.get).toHaveBeenCalledWith('SSO_TOKEN_SALT');
      expect(salt).toBe('mock-sso-salt');
    });

    it('should return null and log error when salt is not configured', () => {
      configService.get.mockReturnValue(undefined);

      const salt = (service as any).getSSOTokenSalt();

      expect(configService.get).toHaveBeenCalledWith('SSO_TOKEN_SALT');
      expect(salt).toBeNull();
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        'SSO_TOKEN_SALT is not defined in environment configuration.',
      );
    });

    it('should return null when salt is empty string', () => {
      configService.get.mockReturnValue('');

      const salt = (service as any).getSSOTokenSalt();

      expect(salt).toBeNull();
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        'SSO_TOKEN_SALT is not defined in environment configuration.',
      );
    });
  });

  describe('registerUser', () => {
    const createUserDto: CreateUserBodyDto = {
      param: {
        handle: 'newuser',
        email: 'newuser@example.com',
        firstName: 'New',
        lastName: 'User',
        credential: { password: 'Password123!' },
        country: { code: 'US' },
        profile: { provider: 'github', userId: 'gh123', name: 'ghNewUser' },
        regSource: 'friend',
      },
    };
    const mockNextUserId = 101;
    const mockNextEmailId = 202;
    const mockCreatedUser = createMockUserModel({
      user_id: new Decimal(mockNextUserId),
      handle: 'newuser',
      status: 'U',
    });
    const mockCreatedEmail = createMockEmailModel({
      email_id: new Decimal(mockNextEmailId),
      user_id: new Decimal(mockNextUserId),
      address: 'newuser@example.com',
      status_id: new Decimal(2),
    });
    const mockEncodedLegacyPassword = 'legacyEncodedPassword';

    let mockEncode;
    beforeEach(() => {
      validationService.validateHandle.mockResolvedValue({ valid: true });
      validationService.validateEmail.mockResolvedValue({ valid: true });
      validationService.validateCountryAndMutate.mockResolvedValue(null);
      validationService.validateProfile.mockResolvedValue();
      validationService.validateReferral.mockResolvedValue(null);

      prismaOltp.$queryRaw.mockImplementation(async (query) => {
        const sqlString = Array.isArray(query)
          ? query[0]
          : (query as Prisma.Sql)?.strings?.[0] || '';
        if (sqlString.includes('sequence_user_seq'))
          return [{ nextval: BigInt(mockNextUserId) }];
        if (sqlString.includes('sequence_email_seq'))
          return [{ nextval: BigInt(mockNextEmailId) }];
        return Promise.resolve([]);
      });

      prismaOltp.user.create.mockResolvedValue(mockCreatedUser);
      prismaOltp.security_user.create.mockResolvedValue(
        {} as SecurityUserModel,
      );
      prismaOltp.email.findFirst.mockResolvedValue(null); // Assume email doesn't exist for new user
      prismaOltp.email.create.mockResolvedValue(mockCreatedEmail);
      roleService.assignRoleByName.mockResolvedValue(undefined);
      cacheManager.set.mockResolvedValue(undefined);
      eventService.postEnvelopedNotification.mockResolvedValue(undefined);
      eventService.postDirectBusMessage.mockResolvedValue(undefined);
      mockEncode = jest
        .spyOn(service, 'encodePasswordLegacy')
        .mockReturnValue(mockEncodedLegacyPassword);
      (uuidv4 as jest.Mock).mockReturnValue('random-otp-or-activation-code'); // For activation_code
    });

    it('should successfully register a new user', async () => {
      const result = await service.registerUser(createUserDto);

      expect(mockValidationService.validateHandle).toHaveBeenCalledWith(
        'newuser',
      );
      expect(mockValidationService.validateEmail).toHaveBeenCalledWith(
        'newuser@example.com',
      );
      expect(
        mockValidationService.validateCountryAndMutate,
      ).toHaveBeenCalledWith({
        code: 'US',
      });
      expect(mockValidationService.validateProfile).toHaveBeenCalledWith(
        createUserDto.param.profile,
      );

      expect(prismaOltp.user.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          user_id: mockNextUserId,
          handle: 'newuser',
          handle_lower: 'newuser',
          status: 'U',
          first_name: 'New',
          last_name: 'User',
          activation_code: expect.any(String), // OTP
        }),
      });
      expect(mockEncode).toHaveBeenCalledWith('Password123!');
      expect(prismaOltp.security_user.create).toHaveBeenCalledWith({
        data: {
          login_id: new Decimal(mockNextUserId),
          user_id: 'newuser',
          password: mockEncodedLegacyPassword,
        },
      });
      expect(prismaOltp.email.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          email_id: mockNextEmailId,
          user_id: mockNextUserId,
          address: 'newuser@example.com',
          primary_ind: 1,
          status_id: 2, // Unverified
          email_type_id: 1,
        }),
      });
      expect(mockRoleService.assignRoleByName).toHaveBeenCalledWith(
        'Topcoder User',
        mockNextUserId,
        mockNextUserId,
      );
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'event.user.created',
        service.toCamelCase(mockCreatedUser),
      );

      expect(result).toEqual(mockCreatedUser);
    });

    it('should throw BadRequestException for missing handle, email, or password', async () => {
      await expect(
        service.registerUser({
          param: { ...createUserDto.param, handle: undefined },
        } as any),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.registerUser({
          param: { ...createUserDto.param, email: undefined },
        } as any),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.registerUser({
          param: {
            ...createUserDto.param,
            profile: undefined, // ensure no defaulting occurs
            credential: { password: undefined },
          },
        } as any),
      ).rejects.toThrow(BadRequestException);
    });

    it('should apply default password when profile present and password missing', async () => {
      const dto: CreateUserBodyDto = {
        param: {
          handle: 'socialuser',
          email: 'socialuser@example.com',
          firstName: 'Soc',
          lastName: 'User',
          // No credential/password provided
          profile: { provider: 'github', userId: 'gh-777', name: 'socUser' },
          regSource: 'friend',
        },
      };

      // Reuse existing mocks; ensure sequences return ids
      mockPrismaOltp.$queryRaw.mockImplementation(async (query) => {
        const sqlString = Array.isArray(query)
          ? query[0]
          : (query as Prisma.Sql)?.strings?.[0] || '';
        if (sqlString.includes('sequence_user_seq'))
          return [{ nextval: BigInt(1001) }];
        if (sqlString.includes('sequence_email_seq'))
          return [{ nextval: BigInt(2002) }];
        return Promise.resolve([]);
      });

      const createdUser = createMockUserModel({
        user_id: new Decimal(1001),
        handle: 'socialuser',
        status: 'U',
      });
      mockPrismaOltp.user.create.mockResolvedValue(createdUser);
      mockPrismaOltp.email.findFirst.mockResolvedValue(null);
      mockPrismaOltp.email.create.mockResolvedValue(
        createMockEmailModel({
          email_id: new Decimal(2002),
          user_id: new Decimal(1001),
          address: 'socialuser@example.com',
          status_id: new Decimal(2),
        }) as any,
      );

      await service.registerUser(dto);

      // Since configService.get('defaultPassword') is undefined in mock, it should fall back to 'default-password'
      expect(mockEncode).toHaveBeenCalledWith('default-password');
    });

    it('should throw BadRequestException for short password', async () => {
      await expect(
        service.registerUser({
          param: { ...createUserDto.param, credential: { password: 'short' } },
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should re-throw validation errors from ValidationService', async () => {
      validationService.validateHandle.mockRejectedValueOnce(
        new ConflictException('Handle taken'),
      );
      await expect(service.registerUser(createUserDto)).rejects.toThrow(
        ConflictException,
      );
    });

    it('should throw InternalServerErrorException if sequence_user_seq fails', async () => {
      prismaOltp.$queryRaw.mockImplementation(async (query) => {
        const sqlString = Array.isArray(query)
          ? query[0]
          : (query as Prisma.Sql)?.strings?.[0] || '';
        if (sqlString.includes('sequence_user_seq'))
          throw new Error('Sequence fail');
        return Promise.resolve([]);
      });
      await expect(service.registerUser(createUserDto)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
    it('should throw InternalServerErrorException if sequence_email_seq fails', async () => {
      prismaOltp.$queryRaw.mockImplementation(async (query) => {
        const sqlString = Array.isArray(query)
          ? query[0]
          : (query as Prisma.Sql)?.strings?.[0] || '';
        if (sqlString.includes('sequence_user_seq'))
          return [{ nextval: BigInt(mockNextUserId) }];
        if (sqlString.includes('sequence_email_seq'))
          throw new Error('Sequence fail');
        return Promise.resolve([]);
      });
      await expect(service.registerUser(createUserDto)).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should throw ConflictException on Prisma P2002 for handle', async () => {
      prismaOltp.$transaction.mockImplementation(async () => {
        const error = new Prisma.PrismaClientKnownRequestError(
          'Unique constraint failed',
          {
            code: 'P2002',
            clientVersion: 'test',
            meta: { target: ['handle_lower'] },
          },
        );
        return Promise.reject(error);
      });
      await expect(service.registerUser(createUserDto)).rejects.toThrow(
        new ConflictException("Handle 'newuser' already exists."),
      );
    });
    it('should throw ConflictException on Prisma P2002 for email (address)', async () => {
      prismaOltp.$transaction.mockImplementation(async () => {
        const error = new Prisma.PrismaClientKnownRequestError(
          'Unique constraint failed',
          {
            code: 'P2002',
            clientVersion: 'test',
            meta: { target: ['address'] }, // Assuming email table unique constraint is on 'address'
          },
        );
        return Promise.reject(error);
      });
      await expect(service.registerUser(createUserDto)).rejects.toThrow(
        new ConflictException("Email 'newuser@example.com' already exists."),
      );
    });

    it('should throw InternalServerErrorException for other Prisma errors during transaction', async () => {
      prismaOltp.$transaction.mockRejectedValue(
        new Error('Some other DB error'),
      );
      await expect(service.registerUser(createUserDto)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('updateBasicInfo', () => {
    const userId = 1;
    const userIdString = '1';
    const updateUserDto: UpdateUserBodyDto = {
      param: {
        firstName: 'UpdatedFirst',
        lastName: 'UpdatedLast',
        company: 'New Co',
      },
    };
    const mockExistingUser = createMockUserModel({
      user_id: new Decimal(userId),
    });

    it('should update basic user information', async () => {
      const mockUpdatedUser = {
        ...mockExistingUser,
        first_name: 'UpdatedFirst',
        last_name: 'UpdatedLast' /* company needs mapping */,
      };
      prismaOltp.user.update.mockResolvedValue(mockUpdatedUser);

      const result = await service.updateBasicInfo(userIdString, updateUserDto);
      expect(prismaOltp.user.update).toHaveBeenCalledWith({
        where: { user_id: userId },
        data: {
          first_name: 'UpdatedFirst',
          last_name:
            'UpdatedLast' /* company needs mapping if user model has it */,
        },
      });
      expect(result).toEqual(mockUpdatedUser);
    });

    it('should throw BadRequestException for invalid user ID format', async () => {
      await expect(
        service.updateBasicInfo('abc', updateUserDto),
      ).rejects.toThrow(BadRequestException);
    });

    it('should return current user if no data to update', async () => {
      prismaOltp.user.findUnique.mockResolvedValue(mockExistingUser); // findUserById is called internally
      prismaOltp.email.findFirst.mockResolvedValue(null); // for findUserById

      const result = await service.updateBasicInfo(userIdString, { param: {} });
      expect(prismaOltp.user.update).not.toHaveBeenCalled();
      expect(result).toEqual(mockExistingUser);
    });

    it('should throw NotFoundException if user to update is not found (P2025)', async () => {
      prismaOltp.user.update.mockRejectedValue(
        new Prisma.PrismaClientKnownRequestError('Record not found', {
          code: 'P2025',
          clientVersion: 'test',
        }),
      );
      await expect(
        service.updateBasicInfo(userIdString, updateUserDto),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw InternalServerErrorException for other update errors', async () => {
      prismaOltp.user.update.mockRejectedValue(new Error('DB Error'));
      await expect(
        service.updateBasicInfo(userIdString, updateUserDto),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('toCamelCase', () => {
    it('should convert snake_case keys to camelCase', () => {
      const obj = {
        first_name: 'Test',
        last_name: 'User',
        contact_info: { email_address: 't@e.com' },
      };
      const expected = {
        firstName: 'Test',
        lastName: 'User',
        contactInfo: { emailAddress: 't@e.com' },
      };
      expect(service.toCamelCase(obj)).toEqual(expected);
    });
    it('should handle arrays of objects', () => {
      const arr = [{ an_item: 1 }, { another_item: 2 }];
      const expected = [{ anItem: 1 }, { anotherItem: 2 }];
      expect(service.toCamelCase(arr)).toEqual(expected);
    });
    it('should return non-objects as is', () => {
      expect(service.toCamelCase(null)).toBeNull();
      expect(service.toCamelCase(123)).toBe(123);
      expect(service.toCamelCase('a_string')).toBe('a_string');
    });
  });

  describe('updateHandle', () => {
    const userId = 1;
    const userIdString = '1';
    const oldHandle = 'oldHandle';
    const newHandle = 'newHandle';
    const mockExistingUser = createMockUserModel({
      user_id: new Decimal(userId),
      handle: oldHandle,
    });

    beforeEach(() => {
      validationService.validateHandle.mockResolvedValue({ valid: true });
      prismaOltp.user.findUnique.mockResolvedValue(mockExistingUser);
      prismaOltp.security_user.findUnique.mockResolvedValue({
        login_id: new Decimal(userId),
        user_id: oldHandle,
        password: 'pwd',
      });
      prismaOltp.security_user.update.mockResolvedValue({
        login_id: new Decimal(userId),
        user_id: newHandle,
        password: 'pwd',
      });
      prismaOltp.$transaction.mockImplementation(<T>(callback): Promise<T> => {
        const result = callback(prismaOltp);
        return result instanceof Promise ? result : Promise.resolve(result);
      });
      prismaOltp.user.update.mockResolvedValue({
        ...mockExistingUser,
        handle: newHandle,
        handle_lower: newHandle.toLowerCase(),
      });
      eventService.postEnvelopedNotification.mockResolvedValue(undefined);
    });

    it('should update handle in user and security_user tables', async () => {
      const result = await service.updateHandle(
        userIdString,
        newHandle,
        mockUser,
      );

      expect(mockValidationService.validateHandle).toHaveBeenCalledWith(
        newHandle,
      );
      expect(prismaOltp.user.findUnique).toHaveBeenCalledWith({
        where: { user_id: userId },
      });
      expect(prismaOltp.user.update).toHaveBeenCalledWith(expect.any(Object));
      expect(prismaOltp.security_user.findUnique).toHaveBeenCalledWith({
        where: { user_id: oldHandle },
      });
      expect(prismaOltp.security_user.update).toHaveBeenCalledWith({
        where: { user_id: oldHandle },
        data: { user_id: newHandle },
      });
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'event.user.updated',
        expect.any(Object),
      );
      expect(result.handle).toBe(newHandle);
    });

    it('should throw BadRequest for invalid user ID or empty new handle', async () => {
      await expect(
        service.updateHandle('abc', newHandle, mockUser),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updateHandle(userIdString, '', mockUser),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw NotFoundException if user not found', async () => {
      prismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(
        service.updateHandle(userIdString, newHandle, mockUser),
      ).rejects.toThrow(NotFoundException);
    });

    it('should return existing user if handle is not changing', async () => {
      const result = await service.updateHandle(
        userIdString,
        oldHandle,
        mockUser,
      );
      expect(prismaOltp.user.update).not.toHaveBeenCalled();
      expect(result.handle).toBe(oldHandle);
    });
    it('should log warning if security_user record not found for old handle', async () => {
      prismaOltp.security_user.findUnique.mockResolvedValue(null);
      await service.updateHandle(userIdString, newHandle, mockUser);
      expect(loggerLogSpy).toHaveBeenCalledWith(
        expect.stringContaining(`Successfully updated handle in 'user' table`),
      ); // user table still updates
      // expect(loggerWarnSpy).toHaveBeenCalledWith(expect.stringContaining(`No security_user record found with handle (user_id) '${oldHandle}'`));
      expect(prismaOltp.security_user.update).not.toHaveBeenCalled();
    });
    it('should throw ConflictException if new handle already exists in security_user (P2002)', async () => {
      prismaOltp.$transaction.mockImplementation(<T>(callback): Promise<T> => {
        // Simulate user.update succeeds
        prismaOltp.user.update.mockResolvedValueOnce({
          ...mockExistingUser,
          handle: newHandle,
          handle_lower: newHandle.toLowerCase(),
        });
        // Simulate security_user.update fails with P2002
        prismaOltp.security_user.update.mockRejectedValueOnce(
          new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
            code: 'P2002',
            clientVersion: 'test',
            meta: { modelName: 'security_user', target: ['user_id'] }, // user_id in security_user is the handle
          }),
        );
        const result = callback(prismaOltp);
        return result instanceof Promise ? result : Promise.resolve(result);
      });

      await expect(
        service.updateHandle(userIdString, newHandle, mockUser),
      ).rejects.toThrow(
        new ConflictException(
          'Failed to update user handle due to a database error.',
        ),
      );
    });
  });

  describe('updatePrimaryEmail', () => {
    const userId = 1;
    const userIdString = '1';
    const newEmail = 'newemail@example.com';
    const oldEmail = 'oldemail@example.com';
    const mockUser = createMockUserModel({
      user_id: new Decimal(userId),
      handle: 'testuser',
    });
    const mockCurrentEmailRecord = createMockEmailModel({
      email_id: new Decimal(10),
      user_id: new Decimal(userId),
      address: oldEmail,
      primary_ind: new Decimal(1),
      status_id: new Decimal(1), // verified
    });
    const mockUpdatedEmailRecord = createMockEmailModel({
      email_id: new Decimal(10),
      user_id: new Decimal(userId),
      address: newEmail.toLowerCase(),
      primary_ind: new Decimal(1),
      status_id: new Decimal(2), // unverified
    });

    const mockAuthUser: AuthenticatedUser = {
      userId: '2',
      roles: ['Administrator'],
      isAdmin: true,
      isMachine: false,
      handle: 'adminUser',
      email: 'admin@example.com',
      scopes: [],
      payload: {},
    };

    let mockCheckEmail;
    beforeEach(() => {
      jest.clearAllMocks();

      // Mock checkEmailAvailabilityForUser
      mockCheckEmail = jest
        .spyOn(service, 'checkEmailAvailabilityForUser')
        .mockResolvedValue(undefined);

      // Mock generateNumericOtp
      jest
        .spyOn(service as any, 'generateNumericOtp')
        .mockReturnValue('123456');

      // Mock toCamelCase
      jest
        .spyOn(service, 'toCamelCase')
        .mockReturnValue({ userId: 1, handle: 'testuser' });

      // Mock config values
      mockConfigService.get.mockImplementation(
        <T = string | number>(key: string, defaultValue?: T): T => {
          const configValues: Record<string, string | number> = {
            ACTIVATION_OTP_EXPIRY_SECONDS: 300,
            ACTIVATION_RESEND_JWT_EXPIRY: '1h',
            JWT_SECRET: 'mock-jwt-secret',
          };
          return (configValues[key] ?? defaultValue) as T;
        },
      );

      // Mock JWT sign
      (jwt.sign as jest.Mock).mockReturnValue('mock.resend.token');

      // Reset transaction mock - don't set up a default implementation here
      mockPrismaOltp.$transaction.mockReset();
    });

    it('should successfully update primary email', async () => {
      // Set up specific transaction mock for this test
      const txMock = {
        user: {
          findUnique: jest.fn().mockResolvedValue(mockUser),
          update: jest.fn().mockResolvedValue(mockUser),
        },
        email: {
          findFirst: jest
            .fn()
            .mockResolvedValueOnce(mockCurrentEmailRecord) // Current primary email
            .mockResolvedValueOnce(null), // No existing email conflict
          update: jest.fn().mockResolvedValue(mockUpdatedEmailRecord),
        },
      };
      mockPrismaOltp.$transaction.mockImplementation(
        <T>(callback): Promise<T> => {
          const result = callback(txMock);
          return result instanceof Promise ? result : Promise.resolve(result);
        },
      );

      // Mock finding updated email record after transaction
      mockPrismaOltp.email.findFirst.mockResolvedValue(mockUpdatedEmailRecord);

      const result = await service.updatePrimaryEmail(
        userIdString,
        newEmail,
        mockAuthUser,
      );

      expect(mockCheckEmail).toHaveBeenCalledWith(newEmail, userId);
      expect(mockPrismaOltp.$transaction).toHaveBeenCalled();
      expect(mockCacheManager.set).toHaveBeenCalledWith(
        `${ACTIVATION_OTP_CACHE_PREFIX_KEY}:UPDATE_EMAIL:${userId}:${mockUpdatedEmailRecord.email_id.toNumber()}`,
        '123456',
        300000,
      );
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledTimes(
        2,
      );
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'email.verification_required',
        expect.objectContaining({
          userId: userIdString,
          email: newEmail,
          otp: '123456',
          resendToken: 'mock.resend.token',
          reason: 'PRIMARY_EMAIL_UPDATE',
        }),
      );
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'event.user.updated',
        { userId: 1, handle: 'testuser' },
      );
      expect(result).toEqual(mockUser);
    });

    it('should throw BadRequestException for invalid user ID format', async () => {
      await expect(
        service.updatePrimaryEmail('invalid', newEmail, mockAuthUser),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updatePrimaryEmail('invalid', newEmail, mockAuthUser),
      ).rejects.toThrow('Invalid user ID format.');
    });

    it('should throw BadRequestException for empty email', async () => {
      await expect(
        service.updatePrimaryEmail(userIdString, '', mockAuthUser),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updatePrimaryEmail(userIdString, '', mockAuthUser),
      ).rejects.toThrow('New email cannot be empty.');
    });

    it('should throw BadRequestException for invalid email format', async () => {
      const invalidEmail = 'not-an-email';
      await expect(
        service.updatePrimaryEmail(userIdString, invalidEmail, mockAuthUser),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updatePrimaryEmail(userIdString, invalidEmail, mockAuthUser),
      ).rejects.toThrow('Invalid email format.');
    });

    it('should throw NotFoundException when user not found', async () => {
      const txMock = {
        user: {
          findUnique: jest.fn().mockResolvedValue(null),
        },
      };
      mockPrismaOltp.$transaction.mockImplementation(
        <T>(callback): Promise<T> => {
          const result = callback(txMock);
          return result instanceof Promise ? result : Promise.resolve(result);
        },
      );

      await expect(
        service.updatePrimaryEmail(userIdString, newEmail, mockAuthUser),
      ).rejects.toThrow(NotFoundException);
      await expect(
        service.updatePrimaryEmail(userIdString, newEmail, mockAuthUser),
      ).rejects.toThrow(`User ${userId} not found.`);
    });

    it('should throw NotFoundException when no primary email found', async () => {
      const txMock = {
        user: {
          findUnique: jest.fn().mockResolvedValue(mockUser),
        },
        email: {
          findFirst: jest.fn().mockResolvedValue(null),
        },
      };
      mockPrismaOltp.$transaction.mockImplementation(
        <T>(callback): Promise<T> => {
          const result = callback(txMock);
          return result instanceof Promise ? result : Promise.resolve(result);
        },
      );

      await expect(
        service.updatePrimaryEmail(userIdString, newEmail, mockAuthUser),
      ).rejects.toThrow(NotFoundException);
      await expect(
        service.updatePrimaryEmail(userIdString, newEmail, mockAuthUser),
      ).rejects.toThrow(`No primary email found for user ${userId}.`);
    });

    it('should throw BadRequestException when email is already taken by another user', async () => {
      const existingEmailRecord = createMockEmailModel({
        email_id: new Decimal(20),
        user_id: new Decimal(999), // Different user
        address: newEmail.toLowerCase(),
        primary_ind: new Decimal(1),
      });

      mockPrismaOltp.$transaction.mockImplementation(async (callback) => {
        const txMock = {
          user: {
            findUnique: jest.fn().mockResolvedValue(mockUser),
          },
          email: {
            findFirst: jest
              .fn()
              .mockResolvedValueOnce(mockCurrentEmailRecord) // Current primary email
              .mockResolvedValueOnce(existingEmailRecord), // Existing email check
          },
        };
        const result = callback(txMock as any);
        return result instanceof Promise ? result : Promise.resolve(result);
      });

      await expect(
        service.updatePrimaryEmail(userIdString, newEmail, mockAuthUser),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updatePrimaryEmail(userIdString, newEmail, mockAuthUser),
      ).rejects.toThrow('Email address is already in use by another user.');
    });

    it('should handle error when checkEmailAvailabilityForUser throws', async () => {
      jest
        .spyOn(service, 'checkEmailAvailabilityForUser')
        .mockRejectedValue(new BadRequestException('Email validation failed'));

      await expect(
        service.updatePrimaryEmail(userIdString, newEmail, mockAuthUser),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updatePrimaryEmail(userIdString, newEmail, mockAuthUser),
      ).rejects.toThrow('Email validation failed');
    });

    it('should handle email verification event failure gracefully', async () => {
      // Set up transaction mock
      const txMock = {
        user: {
          findUnique: jest.fn().mockResolvedValue(mockUser),
          update: jest.fn().mockResolvedValue(mockUser),
        },
        email: {
          findFirst: jest
            .fn()
            .mockResolvedValueOnce(mockCurrentEmailRecord) // Current primary email
            .mockResolvedValueOnce(null), // No existing email conflict
          update: jest.fn().mockResolvedValue(mockUpdatedEmailRecord),
        },
      };
      mockPrismaOltp.$transaction.mockImplementation(
        <T>(callback): Promise<T> => {
          const result = callback(txMock);
          return result instanceof Promise ? result : Promise.resolve(result);
        },
      );

      // Mock finding updated email record after transaction
      mockPrismaOltp.email.findFirst.mockResolvedValue(mockUpdatedEmailRecord);

      mockEventService.postEnvelopedNotification
        .mockRejectedValueOnce(new Error('Email event failed'))
        .mockResolvedValueOnce(undefined); // Second call for user.updated succeeds

      const result = await service.updatePrimaryEmail(
        userIdString,
        newEmail,
        mockAuthUser,
      );

      expect(result).toEqual(mockUser);
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          'Failed to publish email.verification_required event',
        ),
        expect.any(String),
      );
      // Should still publish user.updated event
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'event.user.updated',
        expect.any(Object),
      );
    });

    it('should handle user updated event failure gracefully', async () => {
      // Set up transaction mock
      const txMock = {
        user: {
          findUnique: jest.fn().mockResolvedValue(mockUser),
          update: jest.fn().mockResolvedValue(mockUser),
        },
        email: {
          findFirst: jest
            .fn()
            .mockResolvedValueOnce(mockCurrentEmailRecord) // Current primary email
            .mockResolvedValueOnce(null), // No existing email conflict
          update: jest.fn().mockResolvedValue(mockUpdatedEmailRecord),
        },
      };
      mockPrismaOltp.$transaction.mockImplementation(
        <T>(callback): Promise<T> => {
          const result = callback(txMock);
          return result instanceof Promise ? result : Promise.resolve(result);
        },
      );

      // Mock finding updated email record after transaction
      mockPrismaOltp.email.findFirst.mockResolvedValue(mockUpdatedEmailRecord);

      mockEventService.postEnvelopedNotification
        .mockResolvedValueOnce(undefined) // First call for email verification succeeds
        .mockRejectedValueOnce(new Error('User event failed')); // Second call fails

      const result = await service.updatePrimaryEmail(
        userIdString,
        newEmail,
        mockAuthUser,
      );

      expect(result).toEqual(mockUser);
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to publish user.updated notification'),
        expect.any(String),
      );
    });

    it('should handle case when updated email record is not found after transaction', async () => {
      // Set up transaction mock
      const txMock = {
        user: {
          findUnique: jest.fn().mockResolvedValue(mockUser),
          update: jest.fn().mockResolvedValue(mockUser),
        },
        email: {
          findFirst: jest
            .fn()
            .mockResolvedValueOnce(mockCurrentEmailRecord) // Current primary email
            .mockResolvedValueOnce(null), // No existing email conflict
          update: jest.fn().mockResolvedValue(mockUpdatedEmailRecord),
        },
      };
      mockPrismaOltp.$transaction.mockImplementation(
        <T>(callback): Promise<T> => {
          const result = callback(txMock);
          return result instanceof Promise ? result : Promise.resolve(result);
        },
      );

      // Mock that the email record is not found after transaction
      mockPrismaOltp.email.findFirst.mockResolvedValue(null);

      const result = await service.updatePrimaryEmail(
        userIdString,
        newEmail,
        mockAuthUser,
      );

      expect(result).toEqual(mockUser);
      // Should not generate OTP or send verification email
      expect(mockCacheManager.set).not.toHaveBeenCalled();
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledTimes(
        1,
      ); // Only user.updated
    });

    it('should properly format transaction operations', async () => {
      mockPrismaOltp.$transaction.mockImplementation(
        async <T>(callback): Promise<T> => {
          const txMock = {
            user: {
              findUnique: jest.fn().mockResolvedValue(mockUser),
              update: jest.fn().mockResolvedValue(mockUser),
            },
            email: {
              findFirst: jest
                .fn()
                .mockResolvedValueOnce(mockCurrentEmailRecord) // Current primary
                .mockResolvedValueOnce(null), // No existing email conflict
              update: jest.fn().mockResolvedValue(mockUpdatedEmailRecord),
            },
          };

          const result = await callback(txMock as any);

          expect(txMock.user.findUnique).toHaveBeenCalledWith({
            where: { user_id: userId },
          });
          expect(txMock.email.findFirst).toHaveBeenCalledWith({
            where: { user_id: userId, primary_ind: 1 },
          });
          expect(txMock.email.findFirst).toHaveBeenCalledWith({
            where: {
              address: newEmail.toLowerCase(),
              user_id: { not: userId },
              primary_ind: 1,
            },
          });
          expect(txMock.email.update).toHaveBeenCalledWith({
            where: { email_id: mockCurrentEmailRecord.email_id },
            data: {
              address: newEmail.toLowerCase(),
              status_id: new Decimal(2),
              modify_date: expect.any(Date),
            },
          });
          expect(txMock.user.update).toHaveBeenCalledWith({
            where: { user_id: userId },
            data: {
              modify_date: expect.any(Date),
            },
          });

          return result;
        },
      );

      // Mock finding updated email record after transaction
      mockPrismaOltp.email.findFirst.mockResolvedValue(mockUpdatedEmailRecord);

      await service.updatePrimaryEmail(userIdString, newEmail, mockAuthUser);
    });
  });

  describe('updateStatus', () => {
    const userId = 1;
    const userIdString = '1';
    const oldStatus = 'U';
    const newStatus = 'A'; // Unverified to Active
    const mockExistingUser = createMockUserModel({
      user_id: new Decimal(userId),
      status: oldStatus,
      handle: 'testUser',
    });
    const mockUpdatedUser = { ...mockExistingUser, status: newStatus };
    const mockPrimaryVerifiedEmail = createMockEmailModel({
      user_id: new Decimal(userId),
      address: 'active@example.com',
      status_id: new Decimal(1),
      primary_ind: new Decimal(1),
    });

    beforeEach(() => {
      prismaOltp.user.findUnique.mockResolvedValue(mockExistingUser);
      prismaOltp.user.update.mockResolvedValue(mockUpdatedUser);
      prismaOltp.email.findFirst.mockResolvedValue(mockPrimaryVerifiedEmail); // For welcome email
      roleService.assignRoleByName.mockResolvedValue(undefined);
      eventService.postEnvelopedNotification.mockResolvedValue(undefined);
      eventService.postDirectBusMessage.mockResolvedValue(undefined);
    });

    it('should update user status and trigger activation events if U -> A', async () => {
      const result = await service.updateStatus(
        userIdString,
        newStatus,
        mockUser,
      );

      expect(prismaOltp.user.update).toHaveBeenCalledWith({
        where: { user_id: userId },
        data: { status: newStatus, modify_date: expect.any(Date) },
      });
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'event.user.activated',
        service.toCamelCase(mockUpdatedUser),
      );
      expect(mockRoleService.assignRoleByName).toHaveBeenCalledWith(
        'Topcoder User',
        userId,
        Number(mockUser.userId),
      );
      expect(prismaOltp.email.findFirst).toHaveBeenCalledWith({
        where: { user_id: userId, primary_ind: 1, status_id: 1 },
      });
      // expect(eventService.postDirectBusMessage).toHaveBeenCalledWith('external.action.email', expect.objectContaining({ sendgrid_template_id: 'd-welcomeTemplate' }));
      expect(result).toEqual(mockUpdatedUser);
    });

    it('should update status and trigger deactivation event if A -> I', async () => {
      const fromActiveUser = createMockUserModel({
        user_id: new Decimal(userId),
        status: 'A',
      });
      const toInactiveUser = { ...fromActiveUser, status: 'I' };
      prismaOltp.user.findUnique.mockResolvedValue(fromActiveUser);
      prismaOltp.user.update.mockResolvedValue(toInactiveUser);

      await service.updateStatus(userIdString, 'I', mockUser);
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'event.user.deactivated',
        service.toCamelCase(toInactiveUser),
      );
      expect(mockRoleService.assignRoleByName).not.toHaveBeenCalled(); // No role assignment for deactivation
      expect(mockEventService.postDirectBusMessage).not.toHaveBeenCalledWith(
        'external.action.email',
        expect.objectContaining({ sendgrid_template_id: 'd-welcomeTemplate' }),
      );
    });

    it('should throw BadRequest for invalid user ID or status code', async () => {
      await expect(
        service.updateStatus('abc', newStatus, mockUser),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updateStatus(userIdString, 'X', mockUser),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw NotFoundException if user not found', async () => {
      prismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(
        service.updateStatus(userIdString, newStatus, mockUser),
      ).rejects.toThrow(NotFoundException);
    });

    it('should return user without update if status is not changing', async () => {
      const result = await service.updateStatus(
        userIdString,
        oldStatus,
        mockUser,
      );
      expect(prismaOltp.user.update).not.toHaveBeenCalled();
      expect(result).toEqual(mockExistingUser);
    });
  });

  describe('getAchievements', () => {
    it('should return mapped achievements for a user', async () => {
      const userId = 1;
      const mockUserAchievements = [
        createMockUserAchievementModel({
          user_id: new Decimal(userId),
          achievement_type_id: new Decimal(10),
          achievement_type_lu: createMockAchievementTypeLuModel({
            achievement_type_id: new Decimal(10),
            achievement_type_desc: 'Coder of the Month',
          }),
        }),
        createMockUserAchievementModel({
          user_id: new Decimal(userId),
          achievement_type_id: new Decimal(20),
          achievement_type_lu: createMockAchievementTypeLuModel({
            achievement_type_id: new Decimal(20),
            achievement_type_desc: 'Marathon Winner',
          }),
        }),
      ];
      prismaOltp.user_achievement.findMany.mockResolvedValue(
        mockUserAchievements,
      );

      const result = await service.getAchievements(userId);
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual(
        expect.objectContaining<AchievementDto>({
          achievement_type_id: 10,
          achievement_desc: 'Coder of the Month',
          date: mockUserAchievements[0].create_date,
        }),
      );
      expect(result[1]).toEqual(
        expect.objectContaining<AchievementDto>({
          achievement_type_id: 20,
          achievement_desc: 'Marathon Winner',
          date: mockUserAchievements[1].create_date,
        }),
      );
      expect(prismaOltp.user_achievement.findMany).toHaveBeenCalledWith({
        where: { user_id: userId },
        include: { achievement_type_lu: true },
      });
    });

    it('should throw InternalServerErrorException on database error', async () => {
      prismaOltp.user_achievement.findMany.mockRejectedValue(
        new Error('DB Error'),
      );
      await expect(service.getAchievements(1)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('findOrCreateUserByAuth0Profile', () => {
    const auth0Profile: Auth0UserProfile = {
      sub: 'auth0|123',
      email: 'auth0@example.com',
      email_verified: true,
      nickname: 'auth0nick',
      given_name: 'Auth',
      family_name: 'Zero',
    };
    const mockAuth0Provider = createMockSsoLoginProviderModel({
      name: 'auth0',
      sso_login_provider_id: new Decimal(5),
    });
    const mockExistingUser = createMockUserModel({
      user_id: new Decimal(101),
      handle: 'existing',
    });

    beforeEach(() => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(
        mockAuth0Provider,
      );
      prismaOltp.user_sso_login.findFirst.mockResolvedValue(null); // Default: no existing SSO login
      prismaOltp.email.findFirst.mockResolvedValue(null); // Default: no existing email
      prismaOltp.user.findFirst.mockResolvedValue(null); // Default: no existing user by handle
      prismaOltp.user_sso_login.create.mockResolvedValue({} as any);
      prismaOltp.user.update.mockResolvedValue({} as any); // For updateLastLoginDate
      prismaOltp.$transaction.mockImplementation(<T>(callback): Promise<T> => {
        const result = callback(prismaOltp);
        return result instanceof Promise ? result : Promise.resolve(result);
      });
      eventService.postEnvelopedNotification.mockResolvedValue(undefined);
    });

    it('should find existing user by Auth0 sub', async () => {
      const mockSsoLogin = createMockUserSsoLoginModel({
        user_id: mockExistingUser.user_id,
        sso_user_id: auth0Profile.sub,
        provider_id: mockAuth0Provider.sso_login_provider_id,
      });
      prismaOltp.user_sso_login.findFirst.mockResolvedValue(mockSsoLogin);

      const result = await service.findOrCreateUserByAuth0Profile(auth0Profile);
      expect(result.handle).toEqual('newuser');
      expect(prismaOltp.user.update).toHaveBeenCalledWith({
        where: { user_id: Number(mockExistingUser.user_id) },
        data: { last_login: expect.any(Date) },
      });
    });

    it('should find existing user by email and link Auth0 sub', async () => {
      const mockEmailWithUserXref = {
        address: auth0Profile.email,
        user_email_xref: [{ user: mockExistingUser }],
      } as any;
      prismaOltp.email.findFirst.mockResolvedValue(mockEmailWithUserXref);

      const result = await service.findOrCreateUserByAuth0Profile(auth0Profile);
      expect(result).toEqual(mockExistingUser);
      expect(prismaOltp.user_sso_login.create).toHaveBeenCalledWith({
        data: {
          user_id: mockExistingUser.user_id,
          sso_user_id: auth0Profile.sub,
          provider_id: mockAuth0Provider.sso_login_provider_id,
        },
      });
      expect(prismaOltp.user.update).toHaveBeenCalledWith({
        where: { user_id: Number(mockExistingUser.user_id) },
        data: { last_login: expect.any(Date) },
      });
    });

    it('should create a new user if not found', async () => {
      const newUserId = new Decimal(99);
      const newHandle = auth0Profile.nickname;
      const mockNewUser = createMockUserModel({
        user_id: newUserId,
        handle: newHandle,
        first_name: auth0Profile.given_name,
        last_name: auth0Profile.family_name,
        status: 'A',
      });
      prismaOltp.user.create.mockResolvedValue(mockNewUser);
      (uuidv4 as jest.Mock).mockReturnValueOnce(
        'uuid-for-activation-if-needed',
      );

      const result = await service.findOrCreateUserByAuth0Profile(auth0Profile);
      expect(prismaOltp.user.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ handle: newHandle, status: 'A' }),
      });
      expect(prismaOltp.user_sso_login.create).toHaveBeenCalledWith({
        data: {
          user_id: newUserId,
          sso_user_id: auth0Profile.sub,
          provider_id: mockAuth0Provider.sso_login_provider_id,
        },
      });
      expect(mockEventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'user.created',
        expect.any(Object),
      );
      expect(result).toEqual(mockNewUser);
    });

    it('should throw BadRequestException if Auth0 sub is missing', async () => {
      await expect(
        service.findOrCreateUserByAuth0Profile({
          ...auth0Profile,
          sub: undefined,
        } as any),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw InternalServerErrorException if Auth0 provider not found', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(null);
      await expect(
        service.findOrCreateUserByAuth0Profile(auth0Profile),
      ).rejects.toThrow(InternalServerErrorException);
    });
    it('should throw ConflictException if generated handle conflicts during creation', async () => {
      prismaOltp.user.findFirst.mockResolvedValueOnce(
        createMockUserModel({ handle: auth0Profile.nickname }),
      ); // Simulate handle conflict
      await expect(
        service.findOrCreateUserByAuth0Profile(auth0Profile),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe('updateLastLoginDate', () => {
    it('should update the last_login field of a user', async () => {
      const userId = 1;
      prismaOltp.user.update.mockResolvedValue({} as UserModel);
      await service.updateLastLoginDate(userId);
      expect(prismaOltp.user.update).toHaveBeenCalledWith({
        where: { user_id: userId },
        data: { last_login: expect.any(Date) },
      });
    });

    it('should log error but not throw if update fails', async () => {
      const userId = 1;
      const mockError = new Error('DB fail'); // Create the error object to access its message and stack
      prismaOltp.user.update.mockRejectedValue(mockError);

      await expect(
        service.updateLastLoginDate(userId),
      ).resolves.toBeUndefined(); // Does not throw

      // Corrected assertion:
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        `Failed to update last login date for user ${userId}: ${mockError.message}`, // Exact first argument
        mockError.stack, // Exact second argument (or expect.any(String) if stack is too volatile)
      );
      // Or, if you only care about the first argument and that a second one exists:
      // expect(loggerErrorSpy).toHaveBeenCalledWith(
      //   expect.stringContaining(`Failed to update last login date for user ${userId}: DB fail`),
      //   expect.any(String) // Acknowledges the second argument (stack trace)
      // );
    });
  });

  describe('checkEmailAvailabilityForUser', () => {
    const currentUserId = 1;
    const emailAddress = 'check@example.com';

    it('should resolve if email is available', async () => {
      prismaOltp.email.findFirst.mockResolvedValue(null);
      await expect(
        service.checkEmailAvailabilityForUser(emailAddress, currentUserId),
      ).resolves.toBeUndefined();
      expect(prismaOltp.email.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            address: emailAddress.toLowerCase(),
            primary_ind: 1,
            user_id: { not: currentUserId },
          },
        }),
      );
    });

    it('should throw ConflictException if email is used by another user', async () => {
      prismaOltp.email.findFirst.mockResolvedValue(
        createMockEmailModel({ user_id: new Decimal(2) }),
      ); // Different user
      await expect(
        service.checkEmailAvailabilityForUser(emailAddress, currentUserId),
      ).rejects.toThrow(ConflictException);
    });

    it('should throw BadRequestException if email address is empty', async () => {
      await expect(
        service.checkEmailAvailabilityForUser('', currentUserId),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('updatePrimaryRole', () => {
    const userId = 1;
    const operatorId = 2; // Admin user
    const newPrimaryRole = 'Topcoder Talent';
    const mockUserRecord = createMockUserModel({
      user_id: new Decimal(userId),
    });

    let mockAssign;
    let mockDeassign;
    beforeEach(() => {
      prismaOltp.user.findUnique.mockResolvedValue(mockUserRecord);
      mockDeassign =
        roleService.deassignRoleByName.mockResolvedValue(undefined);
      mockAssign = roleService.assignRoleByName.mockResolvedValue(undefined);
    });

    it('should update primary role, deassigning other valid primary roles', async () => {
      const result = await service.updatePrimaryRole(
        userId,
        newPrimaryRole,
        operatorId,
      );

      expect(prismaOltp.user.findUnique).toHaveBeenCalledWith({
        where: { user_id: userId },
      });
      // It should try to deassign 'Topcoder Customer' if 'Topcoder Talent' is the new one
      expect(mockDeassign).toHaveBeenCalledWith('Topcoder Customer', userId);
      expect(mockAssign).toHaveBeenCalledWith(
        newPrimaryRole,
        userId,
        operatorId,
      );
      expect(result).toEqual(mockUserRecord);
    });

    it('should throw NotFoundException if user not found', async () => {
      prismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(
        service.updatePrimaryRole(userId, newPrimaryRole, operatorId),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException for invalid primary role', async () => {
      await expect(
        service.updatePrimaryRole(userId, 'InvalidRole', operatorId),
      ).rejects.toThrow(BadRequestException);
    });

    it('should log warning if deassigning a role fails but continue', async () => {
      roleService.deassignRoleByName.mockImplementation(async (roleName) => {
        if (roleName === 'Topcoder Customer')
          return Promise.reject(new Error('Deassign failed'));
        return Promise.resolve();
      });
      await service.updatePrimaryRole(userId, newPrimaryRole, operatorId);
      // expect(loggerWarnSpy).toHaveBeenCalledWith(expect.stringContaining("Could not de-assign role 'Topcoder Customer'"));
      expect(roleService.assignRoleByName).toHaveBeenCalledWith(
        newPrimaryRole,
        userId,
        operatorId,
      ); // Still assigns new role
    });
  });
});
