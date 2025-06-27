import { Test, TestingModule } from '@nestjs/testing';
import { UserProfileHelper } from './user-profile.helper';
import { UserProfileDto } from '../../dto/user/user.dto';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import { Logger } from '@nestjs/common';
import {
  Prisma,
} from '@prisma/client-common-oltp';
import { ProviderId } from '../../core/constant/provider-type.enum';

const userIdValue = new Prisma.Decimal(123);

describe('UserProfileHelper', () => {
  let service: UserProfileHelper;
  let mockPrismaClient;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockPrismaClient = {
      user_social_login: {
        findFirst: jest.fn(),
        updateMany: jest.fn(),
      },
      user_sso_login: {
        findFirst: jest.fn(),
      },
      sso_login_provider: {
        findFirst: jest.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserProfileHelper,
        {
          provide: PRISMA_CLIENT_COMMON_OLTP,
          useValue: mockPrismaClient,
        },
      ],
    }).compile();

    service = module.get<UserProfileHelper>(UserProfileHelper);
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
  });

  describe('createProfile', () => {
    it('should create profile from identity with provider', () => {
      const decoded = {
        identities: [
          {
            provider: 'auth0',
            connection: 'TC-User-Database',
            user_id: 'auth0|12345',
          },
        ],
        email: 'test@example.com',
        email_verified: true,
      };

      const result = service.createProfile(decoded);

      expect(result).toBeInstanceOf(UserProfileDto);
      expect(result.providerType).toBe('auth0');
      expect(result.provider).toBe('TC-User-Database');
      expect(result.userId).toBe('12345');
      expect(result.email).toBe('test@example.com');
      expect(result.isEmailVerified).toBe(true);
    });

    it('should create profile from decoded with user_id when no identities', () => {
      const decoded = {
        user_id: 'auth0|12345',
        email: 'test@example.com',
        email_verified: false,
      };

      const result = service.createProfile(decoded);

      expect(result.userId).toBe('12345');
      expect(result.isEmailVerified).toBe(false);
    });

    it('should create profile from decoded with sub when no user_id', () => {
      const decoded = {
        sub: 'auth0|12345',
        email: 'test@example.com',
      };

      const result = service.createProfile(decoded);

      expect(result.userId).toBe('12345');
    });

    it('should handle custom OAuth connection provider type', () => {
      const decoded = {
        identities: [
          {
            provider: 'oauth2',
            connection: 'custom-oauth',
            user_id: 'custom|123',
          },
        ],
        email: 'test@example.com',
      };

      const result = service.createProfile(decoded);

      expect(result.providerType).toBe('custom-oauth');
    });

    it('should set name from provider type nameKey', () => {
      const decoded = {
        identities: [
          {
            provider: 'twitter',
            connection: 'twitter',
            user_id: '123',
          },
        ],
        email: 'test@example.com',
        screen_name: 'Test User',
      };

      const result = service.createProfile(decoded);

      expect(result.name).toBe('Test User');
    });

    it('should handle empty identities array', () => {
      const decoded = {
        identities: [],
        sub: 'auth0|123',
        email: 'test@example.com',
      };

      const result = service.createProfile(decoded);

      expect(result.userId).toBe('123');
    });
  });

  describe('getUserIdByProfile', () => {
    it('should throw error when profile is null', async () => {
      await expect(service.getUserIdByProfile(null)).rejects.toThrow('profile must be specified.');
    });

    it('should throw error for unsupported provider type', async () => {
      const profile = new UserProfileDto();
      profile.providerType = 'unknown';

      await expect(service.getUserIdByProfile(profile)).rejects.toThrow('Unsupported provider type: unknown');
    });

    it('should handle LDAP provider type', async () => {
      const profile = new UserProfileDto();
      profile.providerType = 'ad';
      profile.userId = '123';
      
      // Mock the internal call that would happen for LDAP
      mockPrismaClient.user_social_login.findFirst.mockResolvedValue({ user_id: userIdValue });

      const result = await service.getUserIdByProfile(profile);
      expect(result).toBe(123);
    });

    it('should handle social provider type', async () => {
      const profile = new UserProfileDto();
      profile.providerType = 'google-oauth2';
      profile.userId = '123';
      profile.email = 'test@example.com';

      mockPrismaClient.user_social_login.findFirst.mockResolvedValue({ user_id: userIdValue });

      const result = await service.getUserIdByProfile(profile);
      expect(result).toBe(123);
    });

    it('should handle enterprise provider type', async () => {
      const profile = new UserProfileDto();
      profile.providerType = 'samlp';
      profile.provider = 'okta';
      profile.userId = '123';
      profile.email = 'test@example.com';

      mockPrismaClient.sso_login_provider.findFirst.mockResolvedValue({ sso_login_provider_id: 1 });
      mockPrismaClient.user_sso_login.findFirst.mockResolvedValue({ user_id: userIdValue });

      const result = await service.getUserIdByProfile(profile);
      expect(result).toEqual(123);
    });

    it('should return null when no user found for social provider', async () => {
      const profile = new UserProfileDto();
      profile.providerType = 'google-oauth2';
      profile.userId = '123';
      profile.email = 'test@example.com';

      mockPrismaClient.user_social_login.findFirst.mockResolvedValue(null);

      const result = await service.getUserIdByProfile(profile);
      expect(result).toBeUndefined();
    });

    it('should throw error if social user id is not provided', async () => {
      const profile = new UserProfileDto();
      profile.providerType = 'google-oauth2';
      profile.userId = null;
      profile.email = 'test@example.com';

      await expect(service.getUserIdByProfile(profile)).rejects.toThrow('profile must have userId');
    });

    it('should ignore error if user not found by social user id', async () => {
      const profile = new UserProfileDto();
      profile.providerType = 'google-oauth2';
      profile.userId = '123';
      profile.email = 'test@example.com';

      mockPrismaClient.user_social_login.findFirst.mockRejectedValueOnce(new Error('query-fail-with-userId'));
      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce({ user_id: userIdValue });

      const result = await service.getUserIdByProfile(profile);
      expect(result).toBe(123);
      expect(mockPrismaClient.user_social_login.findFirst).toHaveBeenCalledWith({
        where: {
          social_user_id: '123',
          social_login_provider_id: ProviderId.GOOGLE
        }
      });
      expect(mockPrismaClient.user_social_login.findFirst).toHaveBeenCalledWith({
        where: {
          social_email: profile.email,
          social_email_verified: false,
          social_login_provider_id: ProviderId.GOOGLE
        }
      });
    });

    it('should get user by profile name if email is not provided', async () => {
      const profile = new UserProfileDto();
      profile.providerType = 'google-oauth2';
      profile.userId = '123';
      profile.email = null;
      profile.name = 'test-name';

      // first call
      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce({});
      // second call
      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce({ user_id: userIdValue });

      const result = await service.getUserIdByProfile(profile);
      expect(result).toBe(123);
      expect(mockPrismaClient.user_social_login.findFirst).toHaveBeenCalledWith({
        where: {
          social_user_id: '123',
          social_login_provider_id: ProviderId.GOOGLE
        }
      });
      expect(mockPrismaClient.user_social_login.findFirst).toHaveBeenCalledWith({
        where: {
          social_user_name: profile.name,
          social_login_provider_id: ProviderId.GOOGLE
        }
      });
    });

    it('should throw error if no email or name provided', async () => {
      const profile = new UserProfileDto();
      profile.providerType = 'google-oauth2';
      profile.userId = '123';
      profile.email = null;

      // first call
      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce({});

      await expect(service.getUserIdByProfile(profile)).rejects.toThrow('he social account should have at least one valid email or one valid username.');
    });
  });
});
