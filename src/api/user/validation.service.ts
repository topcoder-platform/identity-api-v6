import {
  Injectable,
  Inject,
  Logger,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';

import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { country, sso_login_provider, PrismaClient } from '@prisma/client';
import * as DTOs from '../../dto/user/user.dto';
import {
  getProviderDetails,
  ProviderDetails,
  ProviderId,
} from '../../core/constant/provider-type.enum';
import { Constants } from '../../core/constant/constants';
import { Decimal } from '@prisma/client/runtime/library';
import { CommonUtils } from '../../shared/util/common.utils';

// Basic email regex, can be refined
const EMAIL_REGEX =
  /^[+_A-Za-z0-9-]+(\.[+_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\.[A-Za-z0-9]+)*(\.[A-Za-z]{2,}$)/;
// Basic handle regex: 3-64 chars, alphanumeric, and specific special characters _ . - ` [ ] { }
const HANDLE_REGEX = /^[-A-Za-z0-9_.`{}[\]]{3,64}$/;
// TODO: Add list of reserved handles if necessary
const RESERVED_HANDLES = ['admin', 'support', 'root', 'administrator']; // Example

const MSG_PROFILE_MANDATORY = 'Profile data must be specified.';
const MSG_SOCIAL_USER_ID_MANDATORY =
  'Social User ID is mandatory for social profiles.';
const MSG_SSO_ID_OR_EMAIL_MANDATORY =
  'At least one of SSO User ID or Email is mandatory for SSO profiles.';
const MSG_UNSUPPORTED_PROVIDER = (providerName: string) =>
  `Unsupported provider: ${providerName}.`;
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

const INVALID_HANDLE_PATTERNS = [/^(.*?)es$/, /^(.*?)s$/, /^_*(.*?)_*$/];

@Injectable()
export class ValidationService {
  private readonly logger = new Logger(ValidationService.name);

  constructor(
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient,
  ) {}

  /**
   * Performs quick validations for first name.
   * @param firstName To be checked
   * @throws BadRequestException if invalid
   */
  validateFirstName(firstName: string) {
    if (firstName && firstName.length > Constants.MAX_LENGTH_FIRST_NAME) {
      throw new BadRequestException(
        `Maximum length of first name is ${Constants.MAX_LENGTH_FIRST_NAME}`,
      );
    }
  }

  /**
   * Performs quick validations for last name.
   * @param lastName To be checked
   * @throws BadRequestException if invalid
   */
  validateLastName(lastName: string) {
    if (lastName && lastName.length > Constants.MAX_LENGTH_LAST_NAME) {
      throw new BadRequestException(
        `Maximum length of last name is ${Constants.MAX_LENGTH_LAST_NAME}`,
      );
    }
  }

  /**
   * Performs quick validations for email.
   * @param email To be checked
   * @throws BadRequestException if invalid
   */
  staticValidateEmail(email: string) {
    if (!CommonUtils.validateString(email)) {
      throw new BadRequestException('Email address is required');
    }
    if (!EMAIL_REGEX.test(email)) {
      throw new BadRequestException('Invalid email format.');
    }
    if (email.length > Constants.MAX_LENGTH_EMAIL) {
      throw new BadRequestException(
        `Maximum length of email address is ${Constants.MAX_LENGTH_EMAIL}`,
      );
    }
  }

  /**
   * Quick validation for user object.
   * @param user User to be checked
   * @throws BadRequestException if invalid
   */
  validateUser(user: DTOs.UserParamBaseDto) {
    // validate first name
    this.validateFirstName(user.firstName);
    // validate last name
    this.validateLastName(user.lastName);
    // validate password
    // at this point, if password is not provided, we don't check
    if (user.credential?.password) {
      this.validatePassword(user.credential?.password);
    }
    // validate email
    this.staticValidateEmail(user.email);
    // validate handle - called from user service (includes static checks)
  }

  async validateHandle(
    handle: string,
    userId: number = null,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(`Validating handle: ${handle}`);
    if (!handle) {
      return { valid: false, reason: 'Handle is required' };
    }
    if (
      handle.length < Constants.MIN_LENGTH_HANDLE ||
      handle.length > Constants.MAX_LENGTH_HANDLE
    ) {
      return {
        valid: false,
        reason: `Length of Handle in character should be between ${Constants.MIN_LENGTH_HANDLE} and ${Constants.MAX_LENGTH_HANDLE}.`,
        reasonCode: 'INVALID_LENGTH',
      };
    }

    if (handle.indexOf(' ') != -1) {
      return {
        valid: false,
        reason: 'Handle may not contain a space',
        reasonCode: 'INVALID_FORMAT',
      };
    }

    if (!HANDLE_REGEX.test(handle)) {
      return {
        valid: false,
        reason:
          'Handle must be 3-64 characters long and can only contain alphanumeric characters and _.-`[]{} symbols.',
        reasonCode: 'INVALID_FORMAT',
      };
    }
    if (handle.match(/^[-_.{}[\]]+$/)) {
      return {
        valid: false,
        reason: 'Handle may not contain only punctuation.',
        reasonCode: 'INVALID_FORMAT',
      };
    }
    if (handle.toLocaleLowerCase().trim().startsWith('admin')) {
      return {
        valid: false,
        reason: 'Please choose another handle, not starting with admin.',
        reasonCode: 'INVALID_HANDLE',
      };
    }
    if (RESERVED_HANDLES.includes(handle.toLowerCase())) {
      return {
        valid: false,
        reason: `Handle '${handle}' is reserved`,
        reasonCode: 'INVALID_HANDLE',
      };
    }

    if (await this.isInvalidHandle(handle)) {
      return {
        valid: false,
        reason: `Handle is invalid`,
        reasonCode: 'INVALID_HANDLE',
      };
    }

    // now check if handle is already used by someone else
    const existingUser = await this.prismaClient.user.findFirst({
      where: { handle_lower: handle.toLowerCase() },
    });

    if (
      existingUser &&
      (!userId || (existingUser?.user_id as unknown as number) != userId)
    ) {
      return {
        valid: false,
        reason: `Handle '${handle}' has already been taken`,
        reasonCode: 'ALREADY_TAKEN',
      };
    }
    this.logger.log(`Handle '${handle}' is valid and available.`);
    return { valid: true };
  }

  /**
   * Validate email via database.
   * @param email Email to be checked
   * @throws BadRequestException if invalid
   */
  async validateEmailViaDB(email: string) {
    if (!CommonUtils.validateString(email)) {
      throw new BadRequestException('Email address is required');
    }
    const emailCount = await this.prismaClient.email.count({
      where: { address: { equals: email, mode: 'insensitive' } },
    });
    if (emailCount > 0) {
      throw new BadRequestException(
        `Email address '${email}' has already been registered, please use another one.`,
      );
    }
  }

  async isInvalidHandle(handle: string): Promise<boolean> {
    if (!handle) {
      return false;
    }
    const checkedHandles = new Set<string>();
    // check invalid handles
    if (await this.isExactInvalidHandle(handle)) {
      return true;
    }
    checkedHandles.add(handle);

    const extractedHandles = this.numberTrimTokenExtract(
      checkedHandles,
      handle,
    );
    if (extractedHandles.size > 0) {
      for (const token of extractedHandles) {
        if (await this.isExactInvalidHandle(token)) {
          return true;
        }
      }
    }

    // last check using regex
    const regexHandles = this.regexTokenExtract(
      INVALID_HANDLE_PATTERNS,
      checkedHandles,
      handle,
    );
    if (regexHandles.size > 0) {
      for (const token of regexHandles) {
        if (await this.isExactInvalidHandle(token)) {
          return true;
        }
      }
    }
    // when everything passed, return false
    return false;
  }

  async isExactInvalidHandle(handle: string): Promise<boolean> {
    if (!handle) {
      return false;
    }
    const count = await this.prismaClient.invalid_handles.count({
      where: {
        invalid_handle: {
          equals: handle,
          mode: 'insensitive',
        },
      },
    });
    return count > 0;
  }

  async validateEmail(
    email: string,
    userId: number = null,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(`Validating email: ${email}`);
    if (!email) {
      throw new BadRequestException('Email cannot be empty.');
    }
    if (!EMAIL_REGEX.test(email)) {
      throw new BadRequestException('Invalid email format.');
    }

    // Check if email exists in the email table and is associated with a user
    const existingEmailRecord = await this.prismaClient.email.findFirst({
      where: { address: email },
      select: { user_id: true },
    });

    // If a record for this email address exists AND it has a user_id, it means the email is in use.
    if (existingEmailRecord && existingEmailRecord.user_id != null) {
      const existingId = Number(existingEmailRecord.user_id);
      if (!userId || existingId !== userId) {
        this.logger.warn(
          `Validation failed: Email '${email}' already exists and is associated with user ID: ${existingId}.`,
        );
        throw new ConflictException(`Email '${email}' is already in use.`);
      }
    }

    // If existingEmailRecord is null, or if it exists but user_id is null (orphaned, less likely/problematic for new registration),
    // the email is considered available.
    this.logger.log(`Email '${email}' is valid and available.`);
    return { valid: true };
  }

  validatePassword(password: string): DTOs.ValidationResponseDto {
    // Mandatory
    if (!password) throw new BadRequestException('Password is required.');

    // Range check
    if (
      password.length < Constants.MIN_LENGTH_PASSWORD ||
      password.length > Constants.MAX_LENGTH_PASSWORD
    ) {
      throw new BadRequestException(
        `Length of password in character should be between ${Constants.MIN_LENGTH_PASSWORD} and ${Constants.MAX_LENGTH_PASSWORD}`,
      );
    }

    // Check if it has a letter.
    if (!Constants.PASSWORD_HAS_LETTER_REGEX.test(password)) {
      throw new BadRequestException('Password must have at least a letter');
    }

    // Check if it has punctuation symbol
    if (
      !Constants.PASSWORD_HAS_SYMBOL_REGEX.test(password) &&
      !Constants.PASSWORD_HAS_DIGIT_REGEX.test(password)
    ) {
      throw new BadRequestException(
        'Password must have at least a symbol or number',
      );
    }

    return { valid: true };
  }

  /**
   * Checks if a specific social identity (provider + social_user_id) is already linked
   * to any internal user.
   * Corresponds to Java: userDao.socialUserExists(profile)
   * @param providerNumericId The numeric ID of the social provider (from social_login_provider table).
   * @param socialProviderUserId The user's ID within that social provider.
   */
  private async isSocialIdentityInUse(
    providerNumericId: ProviderId,
    socialProviderUserId: string,
  ): Promise<boolean> {
    const count = await this.prismaClient.user_social_login.count({
      // Model name from schema
      where: {
        social_login_provider_id: providerNumericId, // Field name from schema
        social_user_id: socialProviderUserId, // Field name from schema
      },
    });
    return count > 0;
  }

  /**
   * The primary validation method called by the controller.
   * @param socialProviderName The string key of the social provider (e.g., 'google-oauth2').
   * @param socialProviderUserId The user's ID within that social provider.
   */
  async validateSocial(
    socialProviderName: string,
    socialProviderUserId: string,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(
      `Validating social: providerKey=${socialProviderName}, socialProviderUserId=${socialProviderUserId}`,
    );

    // Parameter validation (already done in controller but good for service robustness)
    if (!socialProviderName?.trim()) {
      throw new BadRequestException('Social provider key cannot be empty.');
    }
    if (!socialProviderUserId?.trim()) {
      throw new BadRequestException('Social user ID cannot be empty.');
    }

    const providerDetails = getProviderDetails(socialProviderName);

    if (!providerDetails) {
      this.logger.warn(
        `Unsupported provider name received: ${socialProviderName}`,
      );
      throw new BadRequestException(
        `Unsupported provider key: ${socialProviderName}`,
      );
    }
    if (!providerDetails.isSocial) {
      this.logger.warn(
        `Provider ${socialProviderName} is not a social provider.`,
      );
      throw new BadRequestException(
        `Unsupported provider key: ${socialProviderName} (Not a social provider)`,
      );
    }

    // The numeric ID (e.g., 1 for FACEBOOK, 2 for GOOGLE) is used in user_social_login.social_login_provider_id
    const providerNumericId: number = providerDetails.id;

    const err = await this.validateSocialProfiles(
      socialProviderUserId,
      providerNumericId,
    );
    if (err) {
      return this.createValidationResult(false, err);
    } else {
      return this.createValidationResult(true, null);
    }
  }

  private async validateSocialProfiles(
    socialUserId: string,
    providerNumericId: any,
  ) {
    if (!socialUserId || !providerNumericId) {
      throw new Error(
        'Both socialUserId and socialProvider must be specified.',
      );
    }

    const isInUse = await this.isSocialIdentityInUse(
      providerNumericId,
      socialUserId,
    );
    if (isInUse) {
      return 'This social profile is already in use';
    }

    return null;
  }

  private createValidationResult(valid: boolean, reason: string | null) {
    const result = {
      valid: valid,
      reasonCode: null,
      reason: null,
    };

    const safeReason = reason?.toString() || null;

    if (safeReason && safeReason.includes('__')) {
      const [code, msg] = safeReason.split('__', 2);
      result.reason = msg;
      result.reasonCode = code;
    } else {
      result.reason = safeReason;
      result.reasonCode = this.code(safeReason);
    }

    return result;
  }

  private code(reason: string | null): string | null {
    return reason ? reason.toUpperCase().replace(/\s+/g, '_') : null;
  }

  async validateCountry(countryCode: string): Promise<void> {
    this.logger.log(`Validating country: ${countryCode}`);
    if (!countryCode) {
      throw new BadRequestException('Country code cannot be empty.');
    }
    const countryRecord = await this.prismaClient.country.findUnique({
      where: { country_code: countryCode },
    });
    if (!countryRecord) {
      throw new BadRequestException(
        `Country code '${countryCode}' is not valid.`,
      );
    }
    // Add more specific validation if needed (e.g. participating status)
    this.logger.debug(`Country code '${countryCode}' validated.`);
  }

  // General TODO for porting other validation methods removed, focus is on existing methods.
  // // TODO: Add other specific validation methods as needed from UserResource/DAO
  // // - validateTerm
  // // - validateReferral
  // // - validateUserProfile

  /**
   * Validates the provided country data.
   * If valid, it populates the input 'countryInput' object with details from the database
   * and returns null.
   * If invalid, it returns an error message string.
   *
   * Note: This pattern directly mimics the Java example but is less common in NestJS
   * where throwing exceptions for errors and returning data directly is preferred.
   *
   * @param countryInput The country data to validate. THIS OBJECT WILL BE MUTATED ON SUCCESS.
   * @returns A Promise resolving to null if validation is successful (and input is mutated),
   *          or an error message string if validation fails.
   */
  public async validateCountryAndMutate(
    countryInput?: DTOs.CountryDto | null, // Allow null input to match Java's initial check
  ): Promise<string | null> {
    this.logger.debug(
      `Validating country (with mutation): ${JSON.stringify(countryInput)}`,
    );

    if (!countryInput) {
      // The Java code threw IllegalArgumentException. Here, we return an error message
      // to match the contract of "string for error, null for success".
      this.logger.warn('Validation failed: countryInput is null.');
      return 'Country data must be specified.';
    }

    if (
      !countryInput.code &&
      !countryInput.name &&
      !countryInput.isoAlpha2Code &&
      !countryInput.isoAlpha3Code
    ) {
      this.logger.warn('Validation failed: Country code is invalid.');
      return 'Country data is invalid.';
    }

    const dbCountryRecord: country | null | string =
      await this.findCountryBy(countryInput);
    if (!dbCountryRecord || typeof dbCountryRecord === 'string') {
      // if an error string
      this.logger.warn(
        `Country with details: '${JSON.stringify(countryInput)}' not found in database.`,
      );
      return `Country data is invalid.`;
    }

    // --- MUTATION PART ---
    // Populate the input 'countryInput' object with data from the database.
    // This is the side effect.
    this.logger.debug(
      `Country found. Mutating input DTO with DB data: ${JSON.stringify(dbCountryRecord)}`,
    );
    countryInput.code = dbCountryRecord.country_code; // Usually already the same
    countryInput.name = dbCountryRecord.country_name;
    countryInput.isoAlpha2Code = dbCountryRecord.iso_alpha2_code;
    countryInput.isoAlpha3Code = dbCountryRecord.iso_alpha3_code;
    return null; // Signifies success, and countryInput has been mutated.
  }

  /**
   * Find country by multiple ways.
   * @param country Country to look for from DB
   * @returns the country from DB
   */
  private async findCountryBy(
    country: DTOs.CountryDto,
  ): Promise<string | country | null> {
    // it is assumed that at this point, country is a valid object
    try {
      let dbCountryRecord: country | null;
      // find country by code
      dbCountryRecord = await this.prismaClient.country.findUnique({
        where: { country_code: country.code },
      });
      // find by alpha 2 code
      if (
        !dbCountryRecord &&
        CommonUtils.validateString(country.isoAlpha2Code)
      ) {
        dbCountryRecord = await this.prismaClient.country.findFirst({
          where: { iso_alpha2_code: country.isoAlpha2Code },
        });
      }
      // find by alpha 3 code
      if (
        !dbCountryRecord &&
        CommonUtils.validateString(country.isoAlpha3Code)
      ) {
        dbCountryRecord = await this.prismaClient.country.findFirst({
          where: { iso_alpha3_code: country.isoAlpha3Code },
        });
      }
      // find by name
      if (!dbCountryRecord && CommonUtils.validateString(country.name)) {
        dbCountryRecord = await this.prismaClient.country.findFirst({
          where: {
            OR: [
              {
                iso_name: country.name,
              },
              {
                country_name: country.name,
              },
            ],
          },
        });
      }
      return dbCountryRecord;
    } catch (error) {
      this.logger.error(
        `Database error while finding country by code '${country.code}': ${error.message}`,
        error.stack,
      );
      // To strictly follow the "return string for error" and avoid throwing,
      // we'd return a generic error message here.
      return 'An internal error occurred while retrieving country data.';
    }
  }

  public async validateProfile(
    profile: DTOs.UserProfileDto,
    internalUserId?: number | string,
  ): Promise<void> {
    if (!profile) {
      throw new BadRequestException(MSG_PROFILE_MANDATORY);
    }
    this.logger.debug(
      `Validating profile for provider '${profile.provider}', externalId '${profile.userId}' ${internalUserId ? ', internalUserId ' + internalUserId : ''}`,
    );

    // Use your existing getProviderDetails function
    const providerDetails = getProviderDetails(profile.provider);
    if (!providerDetails) {
      this.logger.warn(`Unsupported provider received: ${profile.provider}`);
      throw new BadRequestException(MSG_UNSUPPORTED_PROVIDER(profile.provider));
    }

    // Update DTO with derived provider type (optional, but good for consistency using your structure)
    if (providerDetails.isSocial) {
      profile.providerType = 'social';
    } else if (providerDetails.isEnterprise) {
      profile.providerType = 'enterprise';
    } else {
      // Handle cases where it's neither social nor enterprise (e.g., Auth0 which is isSocial:false, isEnterprise:false)
      profile.providerType = 'database'; // Or based on your specific logic for such providers
    }

    let appUserId: number | undefined = undefined;
    if (internalUserId) {
      appUserId =
        typeof internalUserId === 'string'
          ? parseInt(internalUserId, 10)
          : internalUserId;
      if (isNaN(appUserId)) {
        this.logger.warn(`Invalid internalUserId format: ${internalUserId}`);
        throw new BadRequestException('Invalid internal user ID format.');
      }
    }

    // Logic based on your ProviderDetails structure
    if (providerDetails.isSocial) {
      await this.validateSocialProfile(appUserId, profile, providerDetails);
    }
    // Java: if (profile.isEnterprise() && profile.getProviderTypeEnum() != ProviderType.LDAP)
    // Your ProviderId.LDAP corresponds to key "ad".
    else if (
      providerDetails.isEnterprise &&
      providerDetails.id !== ProviderId.LDAP
    ) {
      await this.validateSsoProfile(profile, providerDetails);
    }
    // the following checks are left as they only output debug logs
    else if (providerDetails.id === ProviderId.LDAP) {
      // Explicitly LDAP
      this.logger.debug(
        `LDAP profile validation for provider '${providerDetails.key}'. No specific database validation rules applied here based on Java logic.`,
      );
    } else if (providerDetails.id === ProviderId.AUTH0) {
      // Explicitly Auth0
      this.logger.debug(
        `Auth0 database profile validation for provider '${providerDetails.key}'. No specific database validation rules applied here based on Java logic.`,
      );
    }
  }

  private async validateSocialProfile(
    internalUserId: number | undefined,
    profile: DTOs.UserProfileDto,
    providerDetails: ProviderDetails, // Use your ProviderDetails interface
  ): Promise<void> {
    this.logger.debug(
      `Validating SOCIAL profile: ${JSON.stringify(profile)}, providerDetails: ${JSON.stringify(providerDetails)}`,
    );

    if (!profile.userId) {
      throw new BadRequestException(MSG_SOCIAL_USER_ID_MANDATORY);
    }

    if (internalUserId !== undefined) {
      const existingLink = await this.prismaClient.user_social_login.findUnique(
        {
          where: {
            user_id_social_login_provider_id: {
              user_id: internalUserId,
              social_login_provider_id: providerDetails.id, // Use id from your ProviderDetails
            },
          },
        },
      );
      if (existingLink) {
        this.logger.warn(
          `User ${internalUserId} already bound with provider ${providerDetails.key} (ID: ${providerDetails.id})`,
        );
        throw new BadRequestException(MSG_USER_ALREADY_BOUND_WITH_PROVIDER);
      }
    }

    const socialProfileInUse =
      await this.prismaClient.user_social_login.findFirst({
        where: {
          social_login_provider_id: providerDetails.id, // Use id from your ProviderDetails
          social_user_id: profile.userId,
        },
      });

    if (socialProfileInUse) {
      if (
        internalUserId === undefined ||
        Number(socialProfileInUse.user_id) !== internalUserId
      ) {
        this.logger.warn(
          `Social profile for provider ${providerDetails.key} and external ID ${profile.userId} is already in use by user ${socialProfileInUse.user_id.toNumber()}.`,
        );
        throw new BadRequestException(MSG_SOCIAL_PROFILE_IN_USE);
      }
    }
  }

  public async getSocialLoginsForUser(
    internalUserId: number,
    providerKey: string,
  ): Promise<any[]> {
    // Replace 'any'
    if (isNaN(internalUserId))
      throw new BadRequestException('Internal User ID must be a valid number.');

    const providerDetails = getProviderDetails(providerKey); // Use your function
    if (!providerDetails || !providerDetails.isSocial) {
      this.logger.warn(
        `getSocialLoginsForUser called with non-social or unknown provider: ${providerKey}`,
      );
      throw new BadRequestException(
        `Provider ${providerKey} is not a valid social provider.`,
      );
    }

    return this.prismaClient.user_social_login.findMany({
      where: {
        user_id: internalUserId,
        social_login_provider_id: new Decimal(providerDetails.id), // Use id from your ProviderDetails
      },
      include: {
        social_login_provider: true,
      },
    });
  }

  private async validateSsoProfile(
    profile: DTOs.UserProfileDto,
    providerDetails: ProviderDetails, // Use your ProviderDetails interface
  ): Promise<void> {
    this.logger.debug(
      `Validating SSO profile: ${JSON.stringify(profile)}, providerDetails: ${JSON.stringify(providerDetails)}`,
    );

    if (!profile.userId && !profile.email) {
      throw new BadRequestException(MSG_SSO_ID_OR_EMAIL_MANDATORY);
    }

    const existingInternalUserId = await this.findInternalUserIdBySsoProfile(
      profile,
      providerDetails,
    );

    if (existingInternalUserId !== null) {
      this.logger.warn(
        `SSO profile for provider ${providerDetails.key} (details: ${JSON.stringify(profile)}) is already in use by user ${existingInternalUserId}.`,
      );
      throw new ConflictException(MSG_SSO_PROFILE_IN_USE);
    }
  }

  public async findInternalUserIdBySsoProfile(
    profile: DTOs.UserProfileDto,
    providerInput: ProviderDetails | string, // Can accept key string or details object
  ): Promise<number | null> {
    let provider: sso_login_provider | undefined;
    if (typeof providerInput === 'string') {
      provider = await this.prismaClient.sso_login_provider.findFirst({
        where: { name: providerInput },
      });
    } else {
      provider = await this.prismaClient.sso_login_provider.findFirst({
        where: { name: providerInput.key },
      });
    }

    if (!provider) {
      this.logger.warn(
        `findInternalUserIdBySsoProfile called with unknown provider input: ${JSON.stringify(providerInput)}`,
      );
      throw new BadRequestException(
        MSG_UNSUPPORTED_PROVIDER(JSON.stringify(providerInput)),
      );
    }

    this.logger.debug(
      `Finding internal user ID by SSO profile: ${JSON.stringify(profile)}, provider: ${provider.name}`,
    );

    let ssoLink;
    // getUserIdBySSOEmail
    if (profile.email) {
      ssoLink = await this.prismaClient.user_sso_login.findFirst({
        where: {
          provider_id: provider.sso_login_provider_id,
          email: profile.email,
        },
        select: { user_id: true },
      });
    }
    console.log("Looking for user ID: " + profile.userId);
    // getUserIdBySSOUserId
    if (!ssoLink && profile.userId) {
      ssoLink = await this.prismaClient.user_sso_login.findFirst({
        where: {
          provider_id: provider.sso_login_provider_id,
          sso_user_id: profile.userId,
        },
        select: { user_id: true },
      });
    }

    if (ssoLink && ssoLink.user_id) {
      return Number(ssoLink.user_id);
    }
    return null;
  }

  /**
   * Validates if a user exists with the given handle (referral source).
   * Mimics the Java method's contract: returns an error string or null for success.
   *
   * @param source The handle of the referring user.
   * @returns A Promise resolving to null if validation is successful,
   *          or an error message string if validation fails.
   */
  public async validateReferral(
    source?: string | null,
  ): Promise<string | null> {
    this.logger.debug(`Validating referral source (direct): '${source}'`);

    if (!source || source.trim().length === 0) {
      this.logger.warn(
        MSG_TEMPLATE_MISSING_UTMSOURCE + ` Input was: '${source}'`,
      );
      return MSG_TEMPLATE_MISSING_UTMSOURCE;
    }

    const handleExistsResult = await this.handleExists(source);

    // If handleExists itself throws an error (e.g., DB connection issue),
    // we might want to catch it here and return a generic error string,
    // or let it propagate as an InternalServerErrorException.
    // For strict adherence to String|null, we'd catch and return string.
    if (handleExistsResult === 'ERROR') {
      // Custom signal for internal error from handleExists
      return 'An internal error occurred while validating referral.';
    }

    if (!handleExistsResult) {
      // This implies boolean false from handleExists
      this.logger.warn(MSG_TEMPLATE_USER_NOT_FOUND + ` Handle: '${source}'`);
      return MSG_TEMPLATE_USER_NOT_FOUND;
    }

    this.logger.debug(`Referral source '${source}' is valid.`);
    return null; // Success
  }

  /**
   * Checks if a user exists with the given handle.
   * Mimics Java's boolean return, but adapted for async and potential error string.
   * @param handle The handle to check.
   * @returns A Promise resolving to true if exists, false if not, or 'ERROR' string on failure.
   */
  private async handleExists(
    handle?: string | null,
  ): Promise<boolean | 'ERROR'> {
    if (!handle || handle.trim().length === 0) {
      return false;
    }
    // this.logger.debug(`Checking if handle exists (internal): '${handle}'`); // Less verbose for internal

    const normalizedHandle = handle.toLowerCase();

    try {
      const count = await this.prismaClient.user.count({
        where: {
          // handle: handle, // Case-sensitive
          handle_lower: normalizedHandle, // Case-insensitive
        },
      });
      return count > 0;
    } catch (error) {
      this.logger.error(
        `Database error in handleExists for '${handle}': ${error.message}`,
        error.stack,
      );
      // To strictly follow the String|null pattern of the parent,
      // this internal helper could signal an error differently than throwing.
      // Or, the caller (validateReferral) catches exceptions from this.
      // Let's signal error with a specific string for the caller to interpret.
      return 'ERROR';
    }
  }

  private isDigit(char) {
    return /^\d$/.test(char);
  }

  numberTrimTokenExtract(
    ignoreTokens: Set<string>,
    handle: string,
  ): Set<string> {
    const extractedTokens = new Set<string>();
    if (handle == null || handle.length == 0) {
      return extractedTokens;
    }

    // find heading and trailing digits count
    let head = 0;
    while (head < handle.length && this.isDigit(handle.charAt(head))) {
      head++;
    }
    if (head >= handle.length) {
      head = handle.length - 1;
    }
    let tail = handle.length - 1;
    while (tail >= 0 && this.isDigit(handle.charAt(tail))) {
      tail--;
    }
    if (tail < 0) {
      tail = 0;
    }
    // remove all possible heading and trailing digits
    for (let i = 0; i <= head; i++) {
      for (let j = handle.length; j > tail && j > i; j--) {
        const token = handle.substring(i, j);
        if (token.length > 0 && !ignoreTokens.has(token)) {
          extractedTokens.add(token);
          ignoreTokens.add(token);
        }
      }
    }
    return extractedTokens;
  }

  private isIterable(obj): boolean {
    if (obj === null || obj === undefined) {
      return false;
    }
    return typeof obj[Symbol.iterator] === 'function';
  }

  regexTokenExtract(
    patterns: Array<RegExp>,
    ignoreTokens: Set<string>,
    handle: string,
  ): Set<string> {
    const extractedTokens = new Set<string>();
    if (handle == null || handle.length == 0) {
      return extractedTokens;
    }
    for (const pattern of patterns) {
      const matchesIterator = handle.match(pattern);
      if (this.isIterable(matchesIterator)) {
        const token = matchesIterator[1];
        if (!ignoreTokens.has(token) && token.length > 0) {
          extractedTokens.add(token);
          ignoreTokens.add(token);
        }
      }
    }
    return extractedTokens;
  }
}
