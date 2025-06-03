import { Test, TestingModule } from '@nestjs/testing';
import {
  UserService,
  ACTIVATION_OTP_CACHE_PREFIX_KEY,
  ACTIVATION_OTP_EXPIRY_SECONDS,
  Auth0UserProfile,
} from './user.service';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import { ValidationService } from './validation.service';
import { RoleService } from '../role/role.service';
import { EventService } from '../../shared/event/event.service';
import {
  NotFoundException,
  ConflictException,
  InternalServerErrorException,
  BadRequestException,
} from '@nestjs/common';
import {
  PrismaClient as PrismaClientCommonOltp,
  user as UserModel,
  Prisma,
  email as EmailModel,
  user_sso_login as UserSsoLoginModel,
  sso_login_provider as SsoLoginProviderModel,
} from '@prisma/client-common-oltp';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import {
  CreateUserBodyDto,
  UpdateUserBodyDto,
  UserSearchQueryDto,
} from '../../dto/user/user.dto';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import { Decimal } from '@prisma/client/runtime/library';

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
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
  user_email_xref: {
    create: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    updateMany: jest.fn(),
    deleteMany: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  sso_login_provider: {
    findFirst: jest.fn(),
    findUnique: jest.fn(),
  },
  user_sso_login: {
    create: jest.fn(),
    findFirst: jest.fn(),
  },
  security_user: {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  user_achievement: {
    findMany: jest.fn(),
  },
  $transaction: jest.fn(),
  $queryRaw: jest.fn(),
};

const mockValidationService = {
  validateHandle: jest.fn(),
  validateEmail: jest.fn(),
  checkEmailAvailabilityForUser: jest.fn(),
};

const mockRoleService = {
  getSubjectRoles: jest.fn(),
  ensureDefaultRoleAssigned: jest.fn(),
  getRoleByName: jest.fn(),
  assignRoleByName: jest.fn(),
  deassignRoleByName: jest.fn(),
};

const mockCacheManager = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
};

const mockEventService = {
  postEnvelopedNotification: jest.fn(),
  postDirectBusMessage: jest.fn(),
};

const mockConfigService = {
  get: jest.fn((key: string, defaultValue?: any) => {
    if (key === 'BCRYPT_SALT_ROUNDS') return 10;
    if (key === 'LEGACY_JWT_SECRET') return 'legacy-secret';
    if (key === 'LEGACY_JWT_EXPIRY_DAYS') return 90;
    if (key === 'SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID')
      return 'mock-resend-activation-template-id';
    if (key === 'SENDGRID_WELCOME_EMAIL_TEMPLATE_ID')
      return 'mock-welcome-template-id';
    if (key === 'LEGACY_BLOWFISH_KEY') return 'testBase64Key=';
    if (key === 'ACTIVATION_OTP_EXPIRY_SECONDS')
      return ACTIVATION_OTP_EXPIRY_SECONDS;
    return defaultValue;
  }),
};

// Mock bcryptjs
jest.mock('bcryptjs', () => ({
  hash: jest.fn(),
  compare: jest.fn(),
}));

// Mock jsonwebtoken
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(),
}));

const createMockUserModel = (input: Partial<UserModel>): UserModel => {
  const { user_id, handle, ...restData } = input;
  const baseUser: Omit<UserModel, 'user_id' | 'handle' | 'handle_lower'> & {
    user_id: Decimal;
    handle: string;
    handle_lower: string;
  } = {
    user_id: new Decimal(user_id),
    handle: handle,
    handle_lower: handle.toLowerCase(),
    first_name: null,
    last_name: null,
    create_date: new Date(),
    modify_date: new Date(),
    last_login: null,
    status: 'A',
    activation_code: null,
    password: 'hashedpassword',
    timezone_id: null,
    name_in_another_language: null,
    middle_name: null,
    open_id: null,
    reg_source: null,
    utm_source: null,
    utm_medium: null,
    utm_campaign: null,
    last_site_hit_date: null,
  };
  return { ...baseUser, ...restData } as UserModel;
};

const createMockEmailModel = (input: Partial<EmailModel>): EmailModel => {
  const { email_id, address, ...restData } = input;
  const baseEmail: Omit<EmailModel, 'email_id' | 'address'> & {
    email_id: Decimal;
    address: string;
  } = {
    email_id: new Decimal(email_id),
    address: address,
    user_id: null, // Default user_id to null, can be overridden by restData if needed and if it's Decimal
    email_type_id: new Decimal(1),
    primary_ind: new Decimal(1),
    status_id: new Decimal(1),
    create_date: new Date(),
    modify_date: new Date(),
  };
  // If restData contains user_id, it must be a Decimal or null for EmailModel
  if (restData.user_id && typeof restData.user_id === 'number') {
    (restData as any).user_id = new Decimal(restData.user_id);
  }
  return { ...baseEmail, ...restData } as EmailModel;
};

describe('UserService', () => {
  let service: UserService;
  let prismaOltp: typeof mockPrismaOltp;
  let cacheManager: typeof mockCacheManager;
  let eventService: jest.Mocked<EventService>;

  const mockAdminUser: AuthenticatedUser = {
    userId: '1',
    roles: ['Administrator'],
    isAdmin: true,
    handle: 'admin',
    email: 'a@b.com',
    scopes: [],
    payload: {},
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: PRISMA_CLIENT_COMMON_OLTP, useValue: mockPrismaOltp },
        { provide: ValidationService, useValue: mockValidationService },
        { provide: RoleService, useValue: mockRoleService },
        { provide: CACHE_MANAGER, useValue: mockCacheManager },
        { provide: EventService, useValue: mockEventService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    })
      .setLogger(nullLogger) // Suppress logs
      .compile();

    service = module.get<UserService>(UserService);
    prismaOltp = module.get(PRISMA_CLIENT_COMMON_OLTP);
    cacheManager = module.get(CACHE_MANAGER);
    eventService = module.get(EventService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('findUserById', () => {
    it('should return a user if found', async () => {
      const userId = 1;
      const mockUser = createMockUserModel({
        user_id: new Decimal(userId),
        handle: 'test',
      });
      prismaOltp.user.findUnique.mockResolvedValue(mockUser);
      const result = await service.findUserById(userId);
      expect(result).toEqual(mockUser);
      expect(prismaOltp.user.findUnique).toHaveBeenCalledWith({
        where: { user_id: userId },
        include: expect.any(Object),
      });
    });

    it('should throw NotFoundException if user not found', async () => {
      prismaOltp.user.findUnique.mockResolvedValue(null);
      await expect(service.findUserById(999)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('findUserByEmailOrHandle', () => {
    it('should find by email if email is provided', async () => {
      const email = 'test@example.com';
      const mockUserRecord = createMockUserModel({
        user_id: new Prisma.Decimal(1),
        handle: 'byemail',
      });
      // Mock finding the email record first
      prismaOltp.email.findFirst.mockResolvedValueOnce({
        user_id: new Decimal(1),
        address: email,
        primary_ind: new Decimal(1),
        status_id: new Decimal(1),
      } as any);
      // Then mock finding the user by the user_id from the email record
      prismaOltp.user.findUnique.mockResolvedValueOnce(mockUserRecord as any);
      // Mock finding the primary email again for attaching to the result (as per current service logic)
      prismaOltp.email.findFirst.mockResolvedValueOnce({
        address: email,
        status_id: new Decimal(1),
      } as any);

      const result = await service.findUserByEmailOrHandle(email);

      expect(prismaOltp.email.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { address: email.toLowerCase(), primary_ind: 1 },
          select: { user_id: true },
        }),
      );
      expect(prismaOltp.user.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { user_id: 1 },
        }),
      );
      expect(result?.handle).toBe('byemail');
      expect(result?.primaryEmail?.address).toBe(email);
    });

    it('should find by handle if non-email is provided', async () => {
      const handle = 'testHandle';
      const mockUserRecord = createMockUserModel({
        user_id: new Decimal('2'),
        handle: handle,
      });
      prismaOltp.user.findFirst.mockResolvedValue(mockUserRecord as any);

      const result = await service.findUserByEmailOrHandle(handle);
      expect(prismaOltp.user.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { handle_lower: handle.toLowerCase() },
        }),
      );
      expect(result?.handle).toBe(handle);
    });

    it('should return null if user not found by email or handle', async () => {
      prismaOltp.user_email_xref.findFirst.mockResolvedValue(null);
      prismaOltp.user.findFirst.mockResolvedValue(null);
      const result = await service.findUserByEmailOrHandle('nonexistent');
      expect(result).toBeNull();
    });

    it('should throw BadRequestException if emailOrHandle is empty', async () => {
      await expect(service.findUserByEmailOrHandle('')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('registerUser', () => {
    const createUserDto: CreateUserBodyDto = {
      param: {
        handle: 'newbie',
        email: 'newbie@example.com',
        firstName: 'New',
        lastName: 'Bie',
        credential: { password: 'Password123!' },
      },
    };
    const hashedPassword = 'hashedPassword123';
    // Align mock IDs with sequence mocks
    const mockNextUserId = 12345;
    const mockNextEmailId = 67890;
    const createdUserMock = createMockUserModel({
      user_id: new Prisma.Decimal(mockNextUserId),
      handle: 'newbie',
    });
    const emailRecordMock = createMockEmailModel({
      email_id: new Prisma.Decimal(mockNextEmailId),
      address: 'newbie@example.com',
      user_id: new Prisma.Decimal(mockNextUserId), // Ensure user_id is linked
    });

    beforeEach(() => {
      (bcrypt.hash as jest.Mock).mockResolvedValue(hashedPassword); // bcrypt.hash is not used by registerUser anymore
      mockValidationService.validateHandle.mockResolvedValue({ valid: true });
      mockValidationService.validateEmail.mockResolvedValue({ valid: true });
      prismaOltp.$transaction.mockImplementation(async (callback) =>
        callback(prismaOltp),
      );
      prismaOltp.$queryRaw.mockImplementation((query) => {
        // More robust check for TemplateStringsArray
        const sqlString = Array.isArray(query)
          ? query[0]
          : (query as Prisma.Sql)?.strings?.[0] || '';
        if (sqlString.includes('sequence_user_seq')) {
          return Promise.resolve([{ nextval: BigInt(mockNextUserId) }]);
        } else if (sqlString.includes('sequence_email_seq')) {
          return Promise.resolve([{ nextval: BigInt(mockNextEmailId) }]);
        }
        return Promise.resolve([]);
      });
      prismaOltp.user.create.mockResolvedValue(createdUserMock);
      prismaOltp.security_user.create.mockResolvedValue({} as any); // Mock for security_user.create
      prismaOltp.email.findFirst.mockResolvedValue(null); // For new user, assume email doesn't exist
      prismaOltp.email.create.mockResolvedValue(emailRecordMock); // Mock the email creation
      mockRoleService.assignRoleByName.mockResolvedValue(undefined); // Replaced ensureDefaultRoleAssigned
    });

    it('should successfully register a new user', async () => {
      // Spy on encodePasswordLegacy
      const encodePasswordLegacySpy = jest.spyOn(
        service,
        'encodePasswordLegacy',
      );
      // Mock its return value for consistent testing of security_user.create
      const mockLegacyEncodedPassword = 'legacyEncodedPassword123';
      encodePasswordLegacySpy.mockReturnValue(mockLegacyEncodedPassword);

      const result = await service.registerUser(createUserDto);

      expect(mockValidationService.validateHandle).toHaveBeenCalledWith(
        'newbie',
      );
      expect(mockValidationService.validateEmail).toHaveBeenCalledWith(
        'newbie@example.com',
      );
      expect(encodePasswordLegacySpy).toHaveBeenCalledWith(
        createUserDto.param.credential.password,
      );

      expect(prismaOltp.user.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            user_id: mockNextUserId,
            handle: 'newbie',
            activation_code: expect.any(String),
          }),
        }),
      );
      expect(prismaOltp.security_user.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            login_id: createdUserMock.user_id, // Expecting the Decimal user_id from createdUserMock
            user_id: createUserDto.param.handle,
            password: mockLegacyEncodedPassword,
          }),
        }),
      );
      expect(prismaOltp.email.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            email_id: mockNextEmailId,
            user_id: mockNextUserId,
            address: 'newbie@example.com',
            primary_ind: 1,
            status_id: 2, // Unverified
          }),
        }),
      );
      expect(mockRoleService.assignRoleByName).toHaveBeenCalledWith(
        'Topcoder User',
        Number(createdUserMock.user_id),
        Number(createdUserMock.user_id),
      );
      expect(
        eventService.postEnvelopedNotification as jest.Mock,
      ).toHaveBeenCalledWith(
        'event.user.created',
        expect.objectContaining(service.toCamelCase(createdUserMock)),
      );
      expect(
        eventService.postDirectBusMessage as jest.Mock,
      ).toHaveBeenCalledWith(
        'external.action.email',
        expect.objectContaining({
          data: {
            handle: createUserDto.param.handle,
            code: expect.any(String),
          },
          recipients: [createUserDto.param.email],
          sendgrid_template_id: 'mock-resend-activation-template-id', // Matched to mockConfigService
        }),
      );
      expect(cacheManager.set).toHaveBeenCalledWith(
        `${ACTIVATION_OTP_CACHE_PREFIX_KEY}:${createdUserMock.user_id}`,
        expect.any(String), // The OTP
        ACTIVATION_OTP_EXPIRY_SECONDS * 1000, // Expect TTL in milliseconds
      );
      expect(result).toEqual(createdUserMock);
    });

    it('should throw ConflictException if handle validation fails with Conflict', async () => {
      mockValidationService.validateHandle.mockRejectedValue(
        new ConflictException('Handle taken'),
      );
      await expect(service.registerUser(createUserDto)).rejects.toThrow(
        ConflictException,
      );
    });

    it('should throw BadRequestException if password is too short', async () => {
      const shortPassDto: CreateUserBodyDto = {
        param: { ...createUserDto.param, credential: { password: 'short' } },
      };
      await expect(service.registerUser(shortPassDto)).rejects.toThrow(
        BadRequestException,
      );
    });
  });
});
