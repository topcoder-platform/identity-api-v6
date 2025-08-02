import { Test, TestingModule } from '@nestjs/testing';
import { ValidationService } from './validation.service';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { BadRequestException, ConflictException, Logger } from '@nestjs/common';
import {
  user as UserModel,
  email as EmailModel,
  country as CountryModel,
  user_social_login as UserSocialLoginModel,
} from '@prisma/client';
import * as DTOs from '../../dto/user/user.dto';
import {
  ProviderId,
  ProviderTypes,
} from '../../core/constant/provider-type.enum';
import { Decimal } from '@prisma/client/runtime/library';

// Corrected Constants
const MSG_PROFILE_MANDATORY = 'Profile data must be specified.';
const MSG_SOCIAL_USER_ID_MANDATORY =
  'Social User ID is mandatory for social profiles.';
const MSG_SSO_ID_OR_EMAIL_MANDATORY =
  'At least one of SSO User ID or Email is mandatory for SSO profiles.';
const MSG_UNSUPPORTED_PROVIDER = (providerName: string) =>
  `Unsupported provider: ${providerName}.`; // Service adds a period
const MSG_USER_ALREADY_BOUND_WITH_PROVIDER =
  'User is already linked with this provider.';
const MSG_SOCIAL_PROFILE_IN_USE =
  'This social profile is already in use by another account.';
const MSG_SSO_PROFILE_IN_USE =
  'This SSO profile is already in use by another account.';
const MSG_TEMPLATE_MISSING_UTMSOURCE =
  'Referral source (UTM source/handle) must be provided.';
const MSG_TEMPLATE_USER_NOT_FOUND =
  'Referring user not found with the provided handle.';

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

// Mock Prisma Client
const mockPrismaOltp = {
  user: {
    findFirst: jest.fn(),
    count: jest.fn(),
  },
  email: {
    findFirst: jest.fn(),
  },
  country: {
    findUnique: jest.fn(),
  },
  user_social_login: {
    count: jest.fn(),
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
  },
  user_sso_login: {
    findFirst: jest.fn(),
  },
};

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
};

const createMockEmailModel = (input: Partial<EmailModel>): EmailModel => {
  return {
    email_id: input.email_id || new Decimal(1),
    user_id: input.user_id ? new Decimal(input.user_id) : null,
    email_type_id: input.email_type_id || new Decimal(1),
    address: input.address || 'test@example.com',
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
};

const createMockCountryModel = (input: Partial<CountryModel>): CountryModel => {
  return {
    country_code: input.country_code || 'US',
    country_name: input.country_name || 'United States',
    modify_date: input.modify_date || new Date(),
    participating:
      input.participating === undefined
        ? new Decimal(1)
        : new Decimal(input.participating),
    default_taxform_id: input.default_taxform_id || null,
    longitude: input.longitude || null,
    latitude: input.latitude || null,
    region: input.region || null,
    iso_name: input.iso_name || null,
    iso_alpha2_code: input.iso_alpha2_code || null,
    iso_alpha3_code: input.iso_alpha3_code || null,
    ...input,
  };
};

const createMockUserSocialLoginModel = (
  input: Partial<UserSocialLoginModel>,
): UserSocialLoginModel => {
  return {
    user_id: input.user_id || new Decimal(1),
    social_login_provider_id:
      input.social_login_provider_id || new Decimal(ProviderId.GOOGLE),
    social_user_id: input.social_user_id || 'google-user-123',
    social_user_name: input.social_user_name || 'Google User',
    social_email: input.social_email || null,
    social_email_verified: input.social_email_verified || null,
    create_date: input.create_date || new Date(),
    modify_date: input.modify_date || null,
    ...input,
  };
};

describe('ValidationService', () => {
  let service: ValidationService;
  let prismaOltp: typeof mockPrismaOltp;
  let loggerWarnSpy: jest.SpyInstance;
  let loggerErrorSpy: jest.SpyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    loggerWarnSpy = jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => {});
    loggerErrorSpy = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => {});

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ValidationService,
        { provide: PRISMA_CLIENT, useValue: mockPrismaOltp },
      ],
    })
      .setLogger(nullLogger)
      .compile();

    service = module.get<ValidationService>(ValidationService);
    prismaOltp = module.get(PRISMA_CLIENT);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateHandle', () => {
    it('should return valid if handle is good and available', async () => {
      prismaOltp.user.findFirst.mockResolvedValue(null);
      const result = await service.validateHandle('new_handle123');
      expect(result).toEqual({ valid: true });
      expect(prismaOltp.user.findFirst).toHaveBeenCalledWith({
        where: { handle_lower: 'new_handle123' },
      });
    });

    it('should throw BadRequestException if handle is empty', async () => {
      await expect(service.validateHandle('')).rejects.toThrow(
        new BadRequestException('Handle cannot be empty.'),
      );
    });

    it('should throw BadRequestException if handle format is invalid (too short)', async () => {
      await expect(service.validateHandle('h!')).rejects.toThrow(
        new BadRequestException(
          'Handle must be 3-64 characters long and can only contain alphanumeric characters and _.-`[]{} symbols.',
        ),
      );
    });
    it('should throw BadRequestException if handle format is invalid (invalid char)', async () => {
      await expect(service.validateHandle('handle*')).rejects.toThrow(
        new BadRequestException(
          'Handle must be 3-64 characters long and can only contain alphanumeric characters and _.-`[]{} symbols.',
        ),
      );
    });

    it('should throw BadRequestException if handle is reserved', async () => {
      await expect(service.validateHandle('admin')).rejects.toThrow(
        new BadRequestException("Handle 'admin' is reserved."),
      );
      await expect(service.validateHandle('Support')).rejects.toThrow(
        new BadRequestException("Handle 'Support' is reserved."),
      );
    });

    it('should throw ConflictException if handle already exists', async () => {
      prismaOltp.user.findFirst.mockResolvedValue(
        createMockUserModel({ handle: 'existing_handle' }),
      );
      await expect(service.validateHandle('existing_handle')).rejects.toThrow(
        new ConflictException("Handle 'existing_handle' is already taken."),
      );
    });
  });

  describe('validateEmail', () => {
    it('should return valid if email is good and available', async () => {
      prismaOltp.email.findFirst.mockResolvedValue(null);
      const result = await service.validateEmail('new@example.com');
      expect(result).toEqual({ valid: true });
      expect(prismaOltp.email.findFirst).toHaveBeenCalledWith({
        where: { address: 'new@example.com' },
        select: { user_id: true },
      });
    });

    it('should return valid if email record exists but is not linked to a user (user_id is null)', async () => {
      prismaOltp.email.findFirst.mockResolvedValue(
        createMockEmailModel({ address: 'orphan@example.com', user_id: null }),
      );
      const result = await service.validateEmail('orphan@example.com');
      expect(result).toEqual({ valid: true });
    });

    it('should throw BadRequestException if email is empty', async () => {
      await expect(service.validateEmail('')).rejects.toThrow(
        new BadRequestException('Email cannot be empty.'),
      );
    });

    it('should throw BadRequestException if email format is invalid', async () => {
      await expect(service.validateEmail('invalid-email')).rejects.toThrow(
        new BadRequestException('Invalid email format.'),
      );
    });

    it('should throw ConflictException if email already exists and is linked to a user', async () => {
      prismaOltp.email.findFirst.mockResolvedValue(
        createMockEmailModel({
          address: 'taken@example.com',
          user_id: new Decimal(123),
        }),
      );
      await expect(service.validateEmail('taken@example.com')).rejects.toThrow(
        new ConflictException("Email 'taken@example.com' is already in use."),
      );
    });
  });

  describe('validateSocial', () => {
    let isSocialIdentityInUseSpy: jest.SpyInstance;
    let loggerLogSpy: jest.SpyInstance;

    beforeEach(() => {
      // Add logger.log spy to existing spies
      loggerLogSpy = jest
        .spyOn(Logger.prototype, 'log')
        .mockImplementation(() => {});

      // Mock the isSocialIdentityInUse private method
      isSocialIdentityInUseSpy = jest
        .spyOn(service as any, 'isSocialIdentityInUse')
        .mockResolvedValue(false);
    });

    afterEach(() => {
      isSocialIdentityInUseSpy.mockRestore();
      loggerLogSpy.mockRestore();
    });

    it('should return valid result for valid social provider and user ID', async () => {
      const result = await service.validateSocial('github', 'github-user-123');

      expect(result).toEqual({
        valid: true,
        reasonCode: null,
        reason: null,
      });
      expect(loggerLogSpy).toHaveBeenCalledWith(
        'Validating social: providerKey=github, socialProviderUserId=github-user-123',
      );
      expect(isSocialIdentityInUseSpy).toHaveBeenCalledWith(
        ProviderTypes['github'].id,
        'github-user-123',
      );
    });

    it('should throw BadRequestException if socialProviderKey is empty', async () => {
      await expect(service.validateSocial('', 'user-123')).rejects.toThrow(
        new BadRequestException('Social provider key cannot be empty.'),
      );
    });

    it('should throw BadRequestException if socialProviderKey is null', async () => {
      await expect(
        service.validateSocial(null as any, 'user-123'),
      ).rejects.toThrow(
        new BadRequestException('Social provider key cannot be empty.'),
      );
    });

    it('should throw BadRequestException if socialProviderKey is only whitespace', async () => {
      await expect(service.validateSocial('   ', 'user-123')).rejects.toThrow(
        new BadRequestException('Social provider key cannot be empty.'),
      );
    });

    it('should throw BadRequestException if socialProviderUserId is empty', async () => {
      await expect(service.validateSocial('github', '')).rejects.toThrow(
        new BadRequestException('Social user ID cannot be empty.'),
      );
    });

    it('should throw BadRequestException if socialProviderUserId is null', async () => {
      await expect(
        service.validateSocial('github', null as any),
      ).rejects.toThrow(
        new BadRequestException('Social user ID cannot be empty.'),
      );
    });

    it('should throw BadRequestException if socialProviderUserId is only whitespace', async () => {
      await expect(service.validateSocial('github', '   ')).rejects.toThrow(
        new BadRequestException('Social user ID cannot be empty.'),
      );
    });

    it('should throw BadRequestException for unsupported provider key', async () => {
      await expect(
        service.validateSocial('unknown-provider', 'user-123'),
      ).rejects.toThrow(
        new BadRequestException('Unsupported provider key: unknown-provider'),
      );
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        'Unsupported provider key received: unknown-provider',
      );
    });

    it('should throw BadRequestException for non-social provider', async () => {
      await expect(service.validateSocial('samlp', 'user-123')).rejects.toThrow(
        new BadRequestException(
          'Unsupported provider key: samlp (Not a social provider)',
        ),
      );
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        'Provider samlp is not a social provider.',
      );
    });

    it('should return invalid result when social profile is already in use', async () => {
      isSocialIdentityInUseSpy.mockResolvedValue(true);

      const result = await service.validateSocial('github', 'github-user-123');

      expect(result).toEqual({
        valid: false,
        reasonCode: 'THIS_SOCIAL_PROFILE_IS_ALREADY_IN_USE',
        reason: 'This social profile is already in use',
      });
    });

    it('should handle validation error with reason code format (code__message)', async () => {
      isSocialIdentityInUseSpy.mockResolvedValue(false);
      jest
        .spyOn(service as any, 'validateSocialProfiles')
        .mockResolvedValue(
          'PROFILE_CONFLICT__Social profile conflicts with existing user',
        );

      const result = await service.validateSocial('github', 'github-user-123');

      expect(result).toEqual({
        valid: false,
        reasonCode: 'PROFILE_CONFLICT',
        reason: 'Social profile conflicts with existing user',
      });
    });

    it('should handle validation error without reason code format', async () => {
      isSocialIdentityInUseSpy.mockResolvedValue(false);
      jest
        .spyOn(service as any, 'validateSocialProfiles')
        .mockResolvedValue('Custom error message');

      const result = await service.validateSocial('github', 'github-user-123');

      expect(result).toEqual({
        valid: false,
        reasonCode: 'CUSTOM_ERROR_MESSAGE',
        reason: 'Custom error message',
      });
    });
  });

  describe('validateSocialProfiles (private method)', () => {
    let isSocialIdentityInUseSpy: jest.SpyInstance;

    beforeEach(() => {
      isSocialIdentityInUseSpy = jest
        .spyOn(service as any, 'isSocialIdentityInUse')
        .mockResolvedValue(false);
    });

    afterEach(() => {
      isSocialIdentityInUseSpy.mockRestore();
    });

    it('should return null for valid social profile not in use', async () => {
      const result = await (service as any).validateSocialProfiles(
        'user-123',
        1,
      );

      expect(result).toBeNull();
      expect(isSocialIdentityInUseSpy).toHaveBeenCalledWith(1, 'user-123');
    });

    it('should throw Error if socialUserId is empty', async () => {
      await expect(
        (service as any).validateSocialProfiles('', 1),
      ).rejects.toThrow(
        new Error('Both socialUserId and socialProvider must be specified.'),
      );
    });

    it('should throw Error if socialUserId is null', async () => {
      await expect(
        (service as any).validateSocialProfiles(null, 1),
      ).rejects.toThrow(
        new Error('Both socialUserId and socialProvider must be specified.'),
      );
    });

    it('should return error message when social identity is in use', async () => {
      isSocialIdentityInUseSpy.mockResolvedValue(true);

      const result = await (service as any).validateSocialProfiles(
        'user-123',
        1,
      );

      expect(result).toBe('This social profile is already in use');
    });
  });

  describe('createValidationResult (private method)', () => {
    it('should create valid result with null reason', () => {
      const result = (service as any).createValidationResult(true, null);

      expect(result).toEqual({
        valid: true,
        reasonCode: null,
        reason: null,
      });
    });

    it('should create invalid result with simple reason', () => {
      const result = (service as any).createValidationResult(
        false,
        'Profile not found',
      );

      expect(result).toEqual({
        valid: false,
        reasonCode: 'PROFILE_NOT_FOUND',
        reason: 'Profile not found',
      });
    });

    it('should create invalid result with reason code format (code__message)', () => {
      const result = (service as any).createValidationResult(
        false,
        'USER_EXISTS__User already exists',
      );

      expect(result).toEqual({
        valid: false,
        reasonCode: 'USER_EXISTS',
        reason: 'User already exists',
      });
    });

    it('should handle empty reason', () => {
      const result = (service as any).createValidationResult(false, '');

      expect(result).toEqual({
        valid: false,
        reasonCode: null,
        reason: null,
      });
    });

    it('should handle null reason', () => {
      const result = (service as any).createValidationResult(false, null);

      expect(result).toEqual({
        valid: false,
        reasonCode: null,
        reason: null,
      });
    });

    it('should convert non-string reason to string', () => {
      const result = (service as any).createValidationResult(false, 123);

      expect(result).toEqual({
        valid: false,
        reasonCode: '123',
        reason: '123',
      });
    });
  });

  describe('code (private method)', () => {
    it('should convert reason to uppercase code with underscores', () => {
      const result = (service as any).code('User not found');

      expect(result).toBe('USER_NOT_FOUND');
    });

    it('should handle multiple spaces', () => {
      const result = (service as any).code('This   is    a test');

      expect(result).toBe('THIS_IS_A_TEST');
    });

    it('should return null for null input', () => {
      const result = (service as any).code(null);

      expect(result).toBeNull();
    });

    it('should return null for empty string', () => {
      const result = (service as any).code('');

      expect(result).toBeNull();
    });

    it('should handle single word', () => {
      const result = (service as any).code('error');

      expect(result).toBe('ERROR');
    });
  });

  describe('validateCountry', () => {
    it('should resolve if country code is valid', async () => {
      prismaOltp.country.findUnique.mockResolvedValue(
        createMockCountryModel({ country_code: 'US' }),
      );
      await expect(service.validateCountry('US')).resolves.toBeUndefined();
      expect(prismaOltp.country.findUnique).toHaveBeenCalledWith({
        where: { country_code: 'US' },
      });
    });

    it('should throw BadRequestException if country code is empty', async () => {
      await expect(service.validateCountry('')).rejects.toThrow(
        new BadRequestException('Country code cannot be empty.'),
      );
    });

    it('should throw BadRequestException if country code is not found', async () => {
      prismaOltp.country.findUnique.mockResolvedValue(null);
      await expect(service.validateCountry('XX')).rejects.toThrow(
        new BadRequestException("Country code 'XX' is not valid."),
      );
    });
  });

  describe('validateCountryAndMutate', () => {
    it('should return null and mutate input DTO on success', async () => {
      const countryInput: DTOs.CountryDto = { code: 'CA' };
      const dbCountry = createMockCountryModel({
        country_code: 'CA',
        country_name: 'Canada DB',
      });
      prismaOltp.country.findUnique.mockResolvedValue(dbCountry);

      const result = await service.validateCountryAndMutate(countryInput);
      expect(result).toBeNull();
      expect(countryInput.name).toBe('Canada DB');
      expect(prismaOltp.country.findUnique).toHaveBeenCalledWith({
        where: { country_code: 'CA' },
      });
    });

    it('should return error message if countryInput is null', async () => {
      const result = await service.validateCountryAndMutate(null);
      expect(result).toBe('Country data must be specified.');
    });

    it('should return error message if countryInput.code is empty', async () => {
      const result = await service.validateCountryAndMutate({ code: '' });
      expect(result).toBe('Country code must be provided and valid.');
    });
    it('should return error message if countryInput.code is only whitespace', async () => {
      const result = await service.validateCountryAndMutate({ code: '  ' });
      expect(result).toBe('Country code must be provided and valid.');
    });

    it('should return error message if country not found in DB', async () => {
      prismaOltp.country.findUnique.mockResolvedValue(null);
      const result = await service.validateCountryAndMutate({ code: 'XX' });
      expect(result).toMatch("Country with code  for code 'XX'.");
    });

    it('should return error message on DB error', async () => {
      prismaOltp.country.findUnique.mockRejectedValue(
        new Error('DB connection lost'),
      );
      const result = await service.validateCountryAndMutate({ code: 'US' });
      expect(result).toBe(
        'An internal error occurred while validating country data.',
      );
      expect(loggerErrorSpy).toHaveBeenCalled();
    });
  });

  describe('validateProfile', () => {
    const internalUserId = 123;
    const socialProfile: DTOs.UserProfileDto = {
      provider: 'github',
      userId: 'github-123',
      name: 'GitHub User',
    };
    const ssoProfile: DTOs.UserProfileDto = {
      provider: 'samlp',
      userId: 'saml-123',
      name: 'SAML User',
      email: 'saml@example.com',
    };
    const ldapProfile: DTOs.UserProfileDto = {
      provider: 'ad',
      userId: 'ldap-user',
      name: 'LDAP User',
    };
    const auth0Profile: DTOs.UserProfileDto = {
      provider: 'auth0',
      userId: 'auth0-db-user',
      name: 'Auth0 DB User',
    };

    beforeEach(() => {
      prismaOltp.user_social_login.findUnique.mockReset();
      prismaOltp.user_social_login.findFirst.mockReset();
      prismaOltp.user_sso_login.findFirst.mockReset();
    });

    // --- Social Profile Validation ---
    it('should validate a new social profile successfully', async () => {
      prismaOltp.user_social_login.findUnique.mockResolvedValue(null);
      prismaOltp.user_social_login.findFirst.mockResolvedValue(null);
      await expect(
        service.validateProfile(socialProfile, internalUserId),
      ).resolves.toBeUndefined();
      expect(socialProfile.providerType).toBe('social');
    });

    it('should throw ConflictException if social profile already linked to this user', async () => {
      prismaOltp.user_social_login.findUnique.mockResolvedValue(
        createMockUserSocialLoginModel({
          user_id: new Decimal(internalUserId),
          social_login_provider_id: new Decimal(ProviderTypes['github'].id),
        }),
      );
      await expect(
        service.validateProfile(socialProfile, internalUserId),
      ).rejects.toThrow(
        new ConflictException(MSG_USER_ALREADY_BOUND_WITH_PROVIDER),
      );
    });

    it('should throw ConflictException if social profile in use by another user', async () => {
      prismaOltp.user_social_login.findUnique.mockResolvedValue(null);
      prismaOltp.user_social_login.findFirst.mockResolvedValue(
        createMockUserSocialLoginModel({
          user_id: new Decimal(456),
          social_login_provider_id: new Decimal(ProviderTypes['github'].id),
          social_user_id: socialProfile.userId,
        }),
      );
      await expect(
        service.validateProfile(socialProfile, internalUserId),
      ).rejects.toThrow(new ConflictException(MSG_SOCIAL_PROFILE_IN_USE));
    });
    it('should throw BadRequestException if social profile userId is missing', async () => {
      const profileWithoutUserId = {
        ...socialProfile,
        userId: undefined as any,
      };
      await expect(
        service.validateProfile(profileWithoutUserId, internalUserId),
      ).rejects.toThrow(new BadRequestException(MSG_SOCIAL_USER_ID_MANDATORY));
    });

    // --- SSO Profile Validation (Non-LDAP Enterprise) ---
    it('should validate a new SSO (non-LDAP enterprise) profile successfully', async () => {
      const mockFind = jest
        .spyOn(service, 'findInternalUserIdBySsoProfile')
        .mockResolvedValue(null);
      await expect(
        service.validateProfile(ssoProfile, internalUserId),
      ).resolves.toBeUndefined();
      expect(ssoProfile.providerType).toBe('enterprise');
      expect(mockFind).toHaveBeenCalledWith(ssoProfile, ProviderTypes['samlp']);
    });

    it('should throw ConflictException if SSO (non-LDAP enterprise) profile in use', async () => {
      jest
        .spyOn(service, 'findInternalUserIdBySsoProfile')
        .mockResolvedValue(456);
      await expect(
        service.validateProfile(ssoProfile, internalUserId),
      ).rejects.toThrow(new ConflictException(MSG_SSO_PROFILE_IN_USE));
    });
    it('should throw BadRequestException if SSO profile userId and email are missing', async () => {
      const profileWithoutIds = {
        ...ssoProfile,
        userId: undefined,
        email: undefined,
      } as any;
      await expect(
        service.validateProfile(profileWithoutIds, internalUserId),
      ).rejects.toThrow(new BadRequestException(MSG_SSO_ID_OR_EMAIL_MANDATORY));
    });

    // --- LDAP and Auth0 (Database) Profile Validation ---
    it('should skip specific DB validation for LDAP provider type', async () => {
      await expect(
        service.validateProfile(ldapProfile, internalUserId),
      ).resolves.toBeUndefined();
      expect(ldapProfile.providerType).toBe('enterprise');
      expect(prismaOltp.user_sso_login.findFirst).not.toHaveBeenCalled();
      expect(prismaOltp.user_social_login.findFirst).not.toHaveBeenCalled();
    });

    it('should skip specific DB validation for Auth0 (database type) provider', async () => {
      await expect(
        service.validateProfile(auth0Profile, internalUserId),
      ).resolves.toBeUndefined();
      expect(auth0Profile.providerType).toBe('database');
      expect(prismaOltp.user_sso_login.findFirst).not.toHaveBeenCalled();
      expect(prismaOltp.user_social_login.findFirst).not.toHaveBeenCalled();
    });

    // --- General Profile Validation ---
    it('should throw BadRequestException if profile is null', async () => {
      // The service code now checks for !profile first.
      await expect(
        service.validateProfile(null as any, internalUserId),
      ).rejects.toThrow(new BadRequestException(MSG_PROFILE_MANDATORY));
    });

    it('should throw BadRequestException for unsupported provider in profile', async () => {
      await expect(
        service.validateProfile(
          { provider: 'unknown-provider', userId: '123', name: 'Test' },
          internalUserId,
        ),
      ).rejects.toThrow(
        new BadRequestException(MSG_UNSUPPORTED_PROVIDER('unknown-provider')),
      );
    });

    it('should correctly parse string internalUserId to number for social profile', async () => {
      prismaOltp.user_social_login.findUnique.mockResolvedValue(null);
      prismaOltp.user_social_login.findFirst.mockResolvedValue(null);
      await service.validateProfile(socialProfile, '123');
      expect(prismaOltp.user_social_login.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            user_id_social_login_provider_id: {
              user_id: 123,
              social_login_provider_id: ProviderTypes['github'].id,
            },
          },
        }),
      );
    });
    it('should throw BadRequestException for invalid string internalUserId format', async () => {
      await expect(
        service.validateProfile(socialProfile, 'abc'),
      ).rejects.toThrow(
        new BadRequestException('Invalid internal user ID format.'),
      );
    });
  });

  describe('getSocialLoginsForUser', () => {
    const internalUserId = 1;
    const providerKey = 'github';

    it('should return social logins for a user and provider', async () => {
      const mockLogins = [createMockUserSocialLoginModel({})];
      prismaOltp.user_social_login.findMany.mockResolvedValue(
        mockLogins as any,
      );

      const result = await service.getSocialLoginsForUser(
        internalUserId,
        providerKey,
      );
      expect(result).toEqual(mockLogins);
      expect(prismaOltp.user_social_login.findMany).toHaveBeenCalledWith({
        where: {
          user_id: internalUserId,
          social_login_provider_id: ProviderTypes[providerKey].id,
        },
        include: { social_login_provider: true },
      });
    });

    it('should throw BadRequestException for invalid internalUserId (NaN)', async () => {
      await expect(
        service.getSocialLoginsForUser(NaN, providerKey),
      ).rejects.toThrow(
        new BadRequestException('Internal User ID must be a valid number.'),
      );
    });

    it('should throw BadRequestException for non-social or unknown provider', async () => {
      await expect(
        service.getSocialLoginsForUser(internalUserId, 'unknown-provider'),
      ).rejects.toThrow(
        new BadRequestException(
          'Provider unknown-provider is not a valid social provider.',
        ),
      );
      await expect(
        service.getSocialLoginsForUser(internalUserId, 'samlp'),
      ).rejects.toThrow(
        new BadRequestException(
          'Provider samlp is not a valid social provider.',
        ),
      );
    });
  });

  describe('findInternalUserIdBySsoProfile', () => {
    const ssoProfileWithEmail: DTOs.UserProfileDto = {
      provider: 'samlp',
      userId: 'saml-123',
      name: 'SAML User',
      email: 'saml.user@example.com',
    };
    const ssoProfileWithUserIdOnly: DTOs.UserProfileDto = {
      provider: 'samlp',
      userId: 'saml-456',
      name: 'SAML User 2',
    };
    const samlpProviderDetails = ProviderTypes['samlp'];

    it('should find user by email if provided and exists', async () => {
      prismaOltp.user_sso_login.findFirst.mockResolvedValueOnce({
        user_id: new Decimal(10),
      });
      const result = await service.findInternalUserIdBySsoProfile(
        ssoProfileWithEmail,
        'samlp',
      );
      expect(result).toBe(10);
      expect(prismaOltp.user_sso_login.findFirst).toHaveBeenCalledWith({
        where: {
          provider_id: samlpProviderDetails.id,
          email: ssoProfileWithEmail.email,
        },
        select: { user_id: true },
      });
    });

    it('should find user by sso_user_id if email lookup fails or email not provided', async () => {
      prismaOltp.user_sso_login.findFirst
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({ user_id: new Decimal(20) });

      const result = await service.findInternalUserIdBySsoProfile(
        ssoProfileWithEmail,
        samlpProviderDetails,
      );
      expect(result).toBe(20);
      expect(prismaOltp.user_sso_login.findFirst).toHaveBeenCalledTimes(2);
      expect(prismaOltp.user_sso_login.findFirst).toHaveBeenNthCalledWith(2, {
        where: {
          provider_id: samlpProviderDetails.id,
          sso_user_id: ssoProfileWithEmail.userId,
        },
        select: { user_id: true },
      });
    });

    it('should find user by sso_user_id if only userId is in profile', async () => {
      prismaOltp.user_sso_login.findFirst.mockResolvedValueOnce({
        user_id: new Decimal(30),
      });
      const result = await service.findInternalUserIdBySsoProfile(
        ssoProfileWithUserIdOnly,
        'samlp',
      );
      expect(result).toBe(30);
      expect(prismaOltp.user_sso_login.findFirst).toHaveBeenCalledWith({
        where: {
          provider_id: samlpProviderDetails.id,
          sso_user_id: ssoProfileWithUserIdOnly.userId,
        },
        select: { user_id: true },
      });
    });

    it('should return null if user not found by email or sso_user_id', async () => {
      prismaOltp.user_sso_login.findFirst.mockResolvedValue(null);
      const result = await service.findInternalUserIdBySsoProfile(
        ssoProfileWithEmail,
        'samlp',
      );
      expect(result).toBeNull();
      expect(prismaOltp.user_sso_login.findFirst).toHaveBeenCalledTimes(2);
    });

    it('should throw BadRequestException for unsupported provider string', async () => {
      await expect(
        service.findInternalUserIdBySsoProfile(
          ssoProfileWithEmail,
          'unknown-provider',
        ),
      ).rejects.toThrow(
        new BadRequestException(MSG_UNSUPPORTED_PROVIDER('"unknown-provider"')),
      );
    });

    it('should throw BadRequestException for unsupported provider object if it leads to getProviderDetails returning undefined', async () => {
      const unknownProviderDetailsAsString = '[object Object]'; // How a generic object might stringify
      // This test relies on the actual getProviderDetails returning undefined for such a string
      const errorMsg = JSON.stringify(unknownProviderDetailsAsString);
      await expect(
        service.findInternalUserIdBySsoProfile(
          ssoProfileWithEmail,
          unknownProviderDetailsAsString as any,
        ),
      ).rejects.toThrow(
        new BadRequestException(MSG_UNSUPPORTED_PROVIDER(errorMsg)),
      );
    });

    it('should return null if provider is not enterprise', async () => {
      const result = await service.findInternalUserIdBySsoProfile(
        ssoProfileWithEmail,
        'github',
      );
      expect(result).toBeNull();
      expect(prismaOltp.user_sso_login.findFirst).not.toHaveBeenCalled();
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        'Attempted to find SSO user with non-enterprise provider: github',
      );
    });
  });

  describe('validateReferral', () => {
    it('should return null if referral source (handle) exists', async () => {
      prismaOltp.user.count.mockResolvedValue(1);
      const result = await service.validateReferral('existingReferrer');
      expect(result).toBeNull();
      expect(prismaOltp.user.count).toHaveBeenCalledWith({
        where: { handle_lower: 'existingreferrer' },
      });
    });

    it('should return error message if referral source is empty', async () => {
      const result = await service.validateReferral('');
      expect(result).toBe(MSG_TEMPLATE_MISSING_UTMSOURCE);
    });
    it('should return error message if referral source is null', async () => {
      const result = await service.validateReferral(null);
      expect(result).toBe(MSG_TEMPLATE_MISSING_UTMSOURCE);
    });
    it('should return error message if referral source is only whitespace', async () => {
      const result = await service.validateReferral('   ');
      expect(result).toBe(MSG_TEMPLATE_MISSING_UTMSOURCE);
    });

    it('should return error message if referring user not found', async () => {
      prismaOltp.user.count.mockResolvedValue(0);
      const result = await service.validateReferral('nonExistentReferrer');
      expect(result).toBe(MSG_TEMPLATE_USER_NOT_FOUND);
    });

    it('should return internal error message if handleExists (via prisma call) signals an error', async () => {
      prismaOltp.user.count.mockRejectedValue(new Error('DB Error in count'));
      const result = await service.validateReferral('someReferrer');
      expect(result).toBe(
        'An internal error occurred while validating referral.',
      );
      expect(loggerErrorSpy).toHaveBeenCalled();
    });
  });

  describe('handleExists (private method - tested via validateReferral or directly for clarity)', () => {
    it('should return true if handle exists (case-insensitive)', async () => {
      prismaOltp.user.count.mockResolvedValue(1);
      const result = await (service as any).handleExists('TestHandle');
      expect(result).toBe(true);
      expect(prismaOltp.user.count).toHaveBeenCalledWith({
        where: { handle_lower: 'testhandle' },
      });
    });

    it('should return false if handle does not exist', async () => {
      prismaOltp.user.count.mockResolvedValue(0);
      const result = await (service as any).handleExists('NonExistent');
      expect(result).toBe(false);
    });

    it('should return false if handle is empty or null or whitespace', async () => {
      expect(await (service as any).handleExists('')).toBe(false);
      expect(await (service as any).handleExists(null)).toBe(false);
      expect(await (service as any).handleExists('   ')).toBe(false);
      expect(prismaOltp.user.count).not.toHaveBeenCalled();
    });

    it('should return "ERROR" on database error', async () => {
      prismaOltp.user.count.mockRejectedValue(new Error('DB Error'));
      const result = await (service as any).handleExists('AnyHandle');
      expect(result).toBe('ERROR');
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "Database error in handleExists for 'AnyHandle'",
        ),
        expect.any(String),
      );
    });
  });
});
