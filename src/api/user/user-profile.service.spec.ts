import { Test, TestingModule } from '@nestjs/testing';
import { UserProfileService } from './user-profile.service';
import { ConfigService } from '@nestjs/config';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import { EventService } from '../../shared/event/event.service';
import {
  NotFoundException,
  ConflictException,
  InternalServerErrorException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import {
  PrismaClient as PrismaClientCommonOltp,
  user_sso_login as UserSsoLoginModel,
  sso_login_provider as SsoLoginProviderModel,
  user_social_login as UserSocialLoginModel,
  social_login_provider as SocialLoginProviderModel,
  Prisma,
} from '@prisma/client-common-oltp';
import { UserProfileDto } from '../../dto/user/user.dto';
import { Decimal } from '@prisma/client/runtime/library';

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
  user_sso_login: {
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(), // Changed from deleteMany as PK is used
  },
  sso_login_provider: {
    findFirst: jest.fn(),
  },
  user_social_login: {
    findMany: jest.fn(),
    create: jest.fn(),
    deleteMany: jest.fn(),
  },
  social_login_provider: {
    findFirst: jest.fn(),
  },
};

const mockEventService = {
  postEnvelopedNotification: jest.fn(),
};

const mockConfigService = {
  get: jest.fn(), // No specific config values used directly in this service's logic
};

// --- Helper Functions to Create Mock Models ---
const createMockSsoLoginProviderModel = (
  input: Partial<SsoLoginProviderModel>,
): SsoLoginProviderModel => {
  return {
    sso_login_provider_id: input.sso_login_provider_id || new Decimal(1),
    name: input.name || 'mock-sso-provider',
    type: input.type || 'saml',
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
    UserSsoLoginModel & { sso_login_provider: SsoLoginProviderModel }
  >,
): UserSsoLoginModel & { sso_login_provider: SsoLoginProviderModel } => {
  const provider =
    input.sso_login_provider || createMockSsoLoginProviderModel({});
  return {
    user_id: input.user_id || new Decimal(1),
    provider_id: provider.sso_login_provider_id,
    sso_user_id: input.sso_user_id || 'sso-user-123',
    sso_user_name: input.sso_user_name || 'SSO User',
    email: input.email || 'sso@example.com',
    sso_login_provider: provider,
    ...input,
  };
};

const createMockSocialLoginProviderModel = (
  input: Partial<SocialLoginProviderModel>,
): SocialLoginProviderModel => {
  return {
    social_login_provider_id: input.social_login_provider_id || new Decimal(10),
    name: input.name || 'mock-social-provider',
    ...input,
  };
};

const createMockUserSocialLoginModel = (
  input: Partial<
    UserSocialLoginModel & { social_login_provider: SocialLoginProviderModel }
  >,
): UserSocialLoginModel & {
  social_login_provider: SocialLoginProviderModel;
} => {
  const provider =
    input.social_login_provider || createMockSocialLoginProviderModel({});
  return {
    user_id: input.user_id || new Decimal(1),
    social_login_provider_id: provider.social_login_provider_id,
    social_user_id: input.social_user_id || 'social-user-123',
    social_user_name: input.social_user_name || 'Social User',
    social_email: input.social_email || null,
    social_email_verified: input.social_email_verified || null,
    create_date: input.create_date || new Date(),
    modify_date: input.modify_date || null,
    social_login_provider: provider,
    ...input,
  };
};

describe('UserProfileService', () => {
  let service: UserProfileService;
  let prismaOltp: typeof mockPrismaOltp;
  let eventService: jest.Mocked<EventService>;
  let loggerErrorSpy: jest.SpyInstance;

  const operatorId = 'operator-1';

  beforeEach(async () => {
    jest.clearAllMocks();
    loggerErrorSpy = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => {});

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserProfileService,
        { provide: PRISMA_CLIENT_COMMON_OLTP, useValue: mockPrismaOltp },
        { provide: EventService, useValue: mockEventService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    })
      .setLogger(nullLogger)
      .compile();

    service = module.get<UserProfileService>(UserProfileService);
    prismaOltp = module.get(PRISMA_CLIENT_COMMON_OLTP);
    eventService = module.get(EventService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('mapSsoLoginToDto', () => {
    it('should correctly map a UserSsoLoginModel to UserProfileDto', () => {
      const mockSsoLogin = createMockUserSsoLoginModel({
        sso_user_id: 'sso123',
        sso_user_name: 'Sso Test User',
        email: 'sso.test@example.com',
        sso_login_provider: createMockSsoLoginProviderModel({
          name: 'TestSsoProvider',
        }),
      });
      const dto = (service as any).mapSsoLoginToDto(mockSsoLogin);
      expect(dto).toEqual({
        provider: 'TestSsoProvider',
        userId: 'sso123',
        name: 'Sso Test User',
        email: 'sso.test@example.com',
        providerType: 'sso',
      });
    });

    it('should throw InternalServerErrorException if sso_login_provider is missing', () => {
      const invalidSsoLogin = {
        user_id: new Decimal(1),
        sso_user_id: 'sso123',
      } as any; // Missing provider
      expect(() => (service as any).mapSsoLoginToDto(invalidSsoLogin)).toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('mapSocialLoginToDto', () => {
    it('should correctly map a UserSocialLoginModel to UserProfileDto', () => {
      const mockSocialLogin = createMockUserSocialLoginModel({
        social_user_id: 'social456',
        social_user_name: 'Social Test User',
        social_login_provider: createMockSocialLoginProviderModel({
          name: 'TestSocialProvider',
        }),
      });
      const dto = (service as any).mapSocialLoginToDto(mockSocialLogin);
      expect(dto).toEqual({
        provider: 'TestSocialProvider',
        userId: 'social456',
        name: 'Social Test User',
        providerType: 'social',
      });
    });
    it('should handle null social_user_name', () => {
      const mockSocialLogin = createMockUserSocialLoginModel({
        social_user_id: 'social789',
        social_user_name: null,
        social_login_provider: createMockSocialLoginProviderModel({
          name: 'AnotherSocialProvider',
        }),
      });
      const dto = (service as any).mapSocialLoginToDto(mockSocialLogin);
      expect(dto.name).toBeUndefined();
    });

    it('should throw InternalServerErrorException if social_login_provider is missing', () => {
      const invalidSocialLogin = {
        user_id: new Decimal(1),
        social_user_id: 'social123',
      } as any; // Missing provider
      expect(() =>
        (service as any).mapSocialLoginToDto(invalidSocialLogin),
      ).toThrow(InternalServerErrorException);
    });
  });

  describe('findSSOUserLoginsByUserId', () => {
    it('should return an array of UserProfileDto for SSO logins', async () => {
      const userId = 1;
      const mockSsoLogins = [
        createMockUserSsoLoginModel({
          user_id: new Decimal(userId),
          sso_login_provider: createMockSsoLoginProviderModel({ name: 'Okta' }),
        }),
        createMockUserSsoLoginModel({
          user_id: new Decimal(userId),
          sso_login_provider: createMockSsoLoginProviderModel({
            name: 'Auth0-SAML',
          }),
        }),
      ];
      prismaOltp.user_sso_login.findMany.mockResolvedValue(mockSsoLogins);

      const result = await service.findSSOUserLoginsByUserId(userId);
      expect(result).toHaveLength(2);
      expect(result[0].provider).toBe('Okta');
      expect(result[1].provider).toBe('Auth0-SAML');
      expect(prismaOltp.user_sso_login.findMany).toHaveBeenCalledWith({
        where: { user_id: userId },
        include: { sso_login_provider: true },
      });
    });

    it('should return an empty array if no SSO logins found', async () => {
      prismaOltp.user_sso_login.findMany.mockResolvedValue([]);
      const result = await service.findSSOUserLoginsByUserId(1);
      expect(result).toEqual([]);
    });
  });

  describe('createSSOUserLogin', () => {
    const userId = 1;
    const profileDto: UserProfileDto = {
      provider: 'TestSsoProvider',
      userId: 'sso-user-id-new',
      name: 'New SSO User',
      email: 'new.sso@example.com',
      providerType: 'sso',
    };
    const mockProviderRecord = createMockSsoLoginProviderModel({
      name: 'TestSsoProvider',
      sso_login_provider_id: new Decimal(5),
    });
    const mockCreatedSsoLogin = createMockUserSsoLoginModel({
      user_id: new Decimal(userId),
      provider_id: mockProviderRecord.sso_login_provider_id,
      sso_user_id: profileDto.userId,
      sso_user_name: profileDto.name,
      email: profileDto.email,
      sso_login_provider: mockProviderRecord,
    });

    it('should create and return a new SSO user login profile', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(
        mockProviderRecord,
      );
      prismaOltp.user_sso_login.create.mockResolvedValue(mockCreatedSsoLogin);

      const result = await service.createSSOUserLogin(
        userId,
        profileDto,
        operatorId,
      );

      expect(prismaOltp.sso_login_provider.findFirst).toHaveBeenCalledWith({
        where: { name: profileDto.provider },
      });
      expect(prismaOltp.user_sso_login.create).toHaveBeenCalledWith({
        data: {
          user_id: userId,
          provider_id: mockProviderRecord.sso_login_provider_id,
          sso_user_id: profileDto.userId,
          email: profileDto.email,
          sso_user_name: profileDto.name,
        },
        include: { sso_login_provider: true },
      });
      expect(result.provider).toBe(profileDto.provider);
      expect(result.userId).toBe(profileDto.userId);
    });

    it('should throw BadRequestException if provider name or sso user ID is missing', async () => {
      await expect(
        service.createSSOUserLogin(
          userId,
          { ...profileDto, provider: undefined } as any,
          operatorId,
        ),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.createSSOUserLogin(
          userId,
          { ...profileDto, userId: undefined } as any,
          operatorId,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException if SSO provider not found', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(null);
      await expect(
        service.createSSOUserLogin(userId, profileDto, operatorId),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw ConflictException if SSO login already exists (P2002)', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(
        mockProviderRecord,
      );
      prismaOltp.user_sso_login.create.mockRejectedValue(
        new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
          code: 'P2002',
          clientVersion: 'test',
          meta: { target: ['user_id_provider_id'] },
        }),
      );
      await expect(
        service.createSSOUserLogin(userId, profileDto, operatorId),
      ).rejects.toThrow(ConflictException);
    });
    it('should throw InternalServerErrorException for other Prisma errors', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(
        mockProviderRecord,
      );
      prismaOltp.user_sso_login.create.mockRejectedValue(
        new Error('Some other DB error'),
      );
      await expect(
        service.createSSOUserLogin(userId, profileDto, operatorId),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('updateSSOUserLogin', () => {
    const userId = 1;
    const profileDto: UserProfileDto = {
      provider: 'TestSsoProvider',
      userId: 'sso-user-id-existing', // This field is not used for where clause, but for context
      name: 'Updated SSO User',
      email: 'updated.sso@example.com',
      providerType: 'sso',
    };
    const mockProviderRecord = createMockSsoLoginProviderModel({
      name: 'TestSsoProvider',
      sso_login_provider_id: new Decimal(5),
    });
    const mockUpdatedSsoLogin = createMockUserSsoLoginModel({
      user_id: new Decimal(userId),
      provider_id: mockProviderRecord.sso_login_provider_id,
      sso_user_id: profileDto.userId, // Assuming sso_user_id is not changed by update
      sso_user_name: profileDto.name,
      email: profileDto.email,
      sso_login_provider: mockProviderRecord,
    });

    it('should update and return the SSO user login profile', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(
        mockProviderRecord,
      );
      prismaOltp.user_sso_login.update.mockResolvedValue(mockUpdatedSsoLogin);

      const result = await service.updateSSOUserLogin(
        userId,
        profileDto,
        operatorId,
      );
      expect(prismaOltp.sso_login_provider.findFirst).toHaveBeenCalledWith({
        where: { name: profileDto.provider },
      });
      expect(prismaOltp.user_sso_login.update).toHaveBeenCalledWith({
        where: {
          user_id_provider_id: {
            user_id: userId,
            provider_id: mockProviderRecord.sso_login_provider_id,
          },
        },
        data: {
          email: profileDto.email,
          sso_user_name: profileDto.name,
        },
        include: { sso_login_provider: true },
      });
      expect(result.name).toBe(profileDto.name);
      expect(result.email).toBe(profileDto.email);
    });

    it('should throw BadRequestException if provider name or sso user ID is missing for update context', async () => {
      await expect(
        service.updateSSOUserLogin(
          userId,
          { ...profileDto, provider: undefined } as any,
          operatorId,
        ),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updateSSOUserLogin(
          userId,
          { ...profileDto, userId: undefined } as any,
          operatorId,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw NotFoundException if SSO provider not found for update', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(null);
      await expect(
        service.updateSSOUserLogin(userId, profileDto, operatorId),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException if SSO login to update not found (P2025)', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(
        mockProviderRecord,
      );
      prismaOltp.user_sso_login.update.mockRejectedValue(
        new Prisma.PrismaClientKnownRequestError('Record to update not found', {
          code: 'P2025',
          clientVersion: 'test',
          meta: {},
        }),
      );
      await expect(
        service.updateSSOUserLogin(userId, profileDto, operatorId),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteSSOUserLogin', () => {
    const userId = 1;
    const providerName = 'TestSsoProvider';
    const ssoUserIdForEvent = 'sso-user-to-delete';
    const mockProviderRecord = createMockSsoLoginProviderModel({
      name: providerName,
      sso_login_provider_id: new Decimal(5),
    });

    it('should delete an SSO user login and post event', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(
        mockProviderRecord,
      );
      prismaOltp.user_sso_login.delete.mockResolvedValue(
        {} as UserSsoLoginModel,
      ); // delete returns the deleted record
      eventService.postEnvelopedNotification.mockResolvedValue(undefined);

      await service.deleteSSOUserLogin(
        userId,
        providerName,
        ssoUserIdForEvent,
        operatorId,
      );

      expect(prismaOltp.sso_login_provider.findFirst).toHaveBeenCalledWith({
        where: { name: providerName },
      });
      expect(prismaOltp.user_sso_login.delete).toHaveBeenCalledWith({
        where: {
          user_id_provider_id: {
            // Corrected: PK for user_sso_login is user_id + provider_id
            user_id: userId,
            provider_id: mockProviderRecord.sso_login_provider_id,
          },
        },
      });
      expect(eventService.postEnvelopedNotification).toHaveBeenCalledWith(
        'user.sso.unlinked',
        {
          userId: userId.toString(),
          profileProvider: providerName,
          profileId: ssoUserIdForEvent,
        },
      );
    });

    it('should throw NotFoundException if SSO provider not found for delete', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(null);
      await expect(
        service.deleteSSOUserLogin(
          userId,
          providerName,
          ssoUserIdForEvent,
          operatorId,
        ),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException if SSO login to delete not found (P2025)', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(
        mockProviderRecord,
      );
      prismaOltp.user_sso_login.delete.mockRejectedValue(
        new Prisma.PrismaClientKnownRequestError('Record to delete not found', {
          code: 'P2025',
          clientVersion: 'test',
          meta: {},
        }),
      );
      await expect(
        service.deleteSSOUserLogin(
          userId,
          providerName,
          ssoUserIdForEvent,
          operatorId,
        ),
      ).rejects.toThrow(NotFoundException);
    });

    it('should log error but not re-throw if event publishing fails', async () => {
      prismaOltp.sso_login_provider.findFirst.mockResolvedValue(
        mockProviderRecord,
      );
      prismaOltp.user_sso_login.delete.mockResolvedValue(
        {} as UserSsoLoginModel,
      );
      eventService.postEnvelopedNotification.mockRejectedValue(
        new Error('Bus unavailable'),
      );

      await expect(
        service.deleteSSOUserLogin(
          userId,
          providerName,
          ssoUserIdForEvent,
          operatorId,
        ),
      ).resolves.toBeUndefined();
    });
  });

  describe('addExternalProfile', () => {
    const userId = 1;
    const profileDto: UserProfileDto = {
      provider: 'TestSocialProvider',
      userId: 'social-user-new',
      name: 'New Social User',
      providerType: 'social', // Explicitly social
    };
    const mockSocialProviderRecord = createMockSocialLoginProviderModel({
      name: 'TestSocialProvider',
      social_login_provider_id: new Decimal(15),
    });
    const mockCreatedSocialLogin = createMockUserSocialLoginModel({
      user_id: new Decimal(userId),
      social_login_provider_id:
        mockSocialProviderRecord.social_login_provider_id,
      social_user_id: profileDto.userId,
      social_user_name: profileDto.name,
      social_login_provider: mockSocialProviderRecord,
    });

    it('should add a new external social profile', async () => {
      prismaOltp.social_login_provider.findFirst.mockResolvedValue(
        mockSocialProviderRecord,
      );
      prismaOltp.user_social_login.create.mockResolvedValue(
        mockCreatedSocialLogin,
      );

      const result = await service.addExternalProfile(
        userId,
        profileDto,
        operatorId,
      );

      expect(prismaOltp.social_login_provider.findFirst).toHaveBeenCalledWith({
        where: { name: { equals: profileDto.provider, mode: 'insensitive' } },
      });
      expect(prismaOltp.user_social_login.create).toHaveBeenCalledWith({
        data: {
          user_id: userId,
          social_login_provider_id:
            mockSocialProviderRecord.social_login_provider_id,
          social_user_id: profileDto.userId,
          social_user_name: profileDto.name,
        },
        include: { social_login_provider: true },
      });
      expect(result.provider).toBe(profileDto.provider);
      expect(result.userId).toBe(profileDto.userId);
      // expect(eventService.postEnvelopedNotification).not.toHaveBeenCalled(); // As per current logic
    });

    it('should throw BadRequestException if attempting to add SSO profile via this method', async () => {
      await expect(
        service.addExternalProfile(
          userId,
          { ...profileDto, providerType: 'sso' },
          operatorId,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException if provider name or social user ID is missing', async () => {
      await expect(
        service.addExternalProfile(
          userId,
          { ...profileDto, provider: undefined } as any,
          operatorId,
        ),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.addExternalProfile(
          userId,
          { ...profileDto, userId: undefined } as any,
          operatorId,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException if social provider not found', async () => {
      prismaOltp.social_login_provider.findFirst.mockResolvedValue(null);
      await expect(
        service.addExternalProfile(userId, profileDto, operatorId),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw ConflictException if social profile already linked to another account (P2002 on provider_id, social_user_id)', async () => {
      prismaOltp.social_login_provider.findFirst.mockResolvedValue(
        mockSocialProviderRecord,
      );
      prismaOltp.user_social_login.create.mockRejectedValue(
        new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
          code: 'P2002',
          clientVersion: 'test',
          meta: { target: ['social_login_provider_id', 'social_user_id'] },
        }),
      );
      await expect(
        service.addExternalProfile(userId, profileDto, operatorId),
      ).rejects.toThrow(
        new ConflictException(
          'This social identity is already linked to another Topcoder account.',
        ),
      );
    });
    it('should throw ConflictException if user already linked with this provider type (P2002 on user_id, provider_id)', async () => {
      prismaOltp.social_login_provider.findFirst.mockResolvedValue(
        mockSocialProviderRecord,
      );
      prismaOltp.user_social_login.create.mockRejectedValue(
        new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
          code: 'P2002',
          clientVersion: 'test',
          meta: { target: ['user_id', 'social_login_provider_id'] },
        }),
      );
      await expect(
        service.addExternalProfile(userId, profileDto, operatorId),
      ).rejects.toThrow(
        new ConflictException(
          `This account is already linked with the social provider '${profileDto.provider}'.`,
        ),
      );
    });
  });

  describe('findAllUserProfiles', () => {
    it('should return a combined list of SSO and Social profiles', async () => {
      const userId = 1;
      const mockSsoLogin = createMockUserSsoLoginModel({
        user_id: new Decimal(userId),
        sso_login_provider: createMockSsoLoginProviderModel({
          name: 'Okta-SSO',
        }),
      });
      const mockSocialLogin = createMockUserSocialLoginModel({
        user_id: new Decimal(userId),
        social_login_provider: createMockSocialLoginProviderModel({
          name: 'GitHub-Social',
        }),
      });

      prismaOltp.user_sso_login.findMany.mockResolvedValue([mockSsoLogin]);
      prismaOltp.user_social_login.findMany.mockResolvedValue([
        mockSocialLogin,
      ]);

      const result = await service.findAllUserProfiles(userId);
      expect(result).toHaveLength(2);
      expect(result.find((p) => p.provider === 'Okta-SSO')).toBeDefined();
      expect(result.find((p) => p.provider === 'GitHub-Social')).toBeDefined();
    });
  });

  describe('deleteExternalProfile', () => {
    const userId = 1;
    const providerName = 'TestSocialProvider';
    const mockSocialProviderRecord = createMockSocialLoginProviderModel({
      name: providerName,
      social_login_provider_id: new Decimal(15),
    });

    it('should delete an external social profile', async () => {
      prismaOltp.social_login_provider.findFirst.mockResolvedValue(
        mockSocialProviderRecord,
      );
      prismaOltp.user_social_login.deleteMany.mockResolvedValue({ count: 1 });

      await service.deleteExternalProfile(userId, providerName);
      expect(prismaOltp.social_login_provider.findFirst).toHaveBeenCalledWith({
        where: { name: { equals: providerName, mode: 'insensitive' } },
      });
      expect(prismaOltp.user_social_login.deleteMany).toHaveBeenCalledWith({
        where: {
          user_id: userId,
          social_login_provider_id:
            mockSocialProviderRecord.social_login_provider_id,
        },
      });
    });

    it('should throw NotFoundException if social provider not found', async () => {
      prismaOltp.social_login_provider.findFirst.mockResolvedValue(null);
      await expect(
        service.deleteExternalProfile(userId, providerName),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException if no profile found to delete (deleteMany.count is 0)', async () => {
      prismaOltp.social_login_provider.findFirst.mockResolvedValue(
        mockSocialProviderRecord,
      );
      prismaOltp.user_social_login.deleteMany.mockResolvedValue({ count: 0 });
      await expect(
        service.deleteExternalProfile(userId, providerName),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw InternalServerErrorException for other Prisma errors', async () => {
      prismaOltp.social_login_provider.findFirst.mockResolvedValue(
        mockSocialProviderRecord,
      );
      prismaOltp.user_social_login.deleteMany.mockRejectedValue(
        new Error('DB Error'),
      );
      await expect(
        service.deleteExternalProfile(userId, providerName),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });
});
