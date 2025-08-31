import {
  Injectable,
  Inject,
  Logger,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';

import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { country, PrismaClient } from '@prisma/client';
import * as DTOs from '../../dto/user/user.dto';
import {
  getProviderDetails,
  ProviderDetails,
  ProviderId,
} from '../../core/constant/provider-type.enum';
import { Constants } from '../../core/constant/constants';

// Basic email regex, can be refined
const EMAIL_REGEX =
  /^[+_A-Za-z0-9-]+(\.[+_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\.[A-Za-z0-9]+)*(\.[A-Za-z]{2,}$)/;
// Basic handle regex: 3-64 chars, alphanumeric, and specific special characters _ . - ` [ ] { }
const HANDLE_REGEX = /^[a-zA-Z0-9\-[\]_.`{}]{3,64}$/;
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

@Injectable()
export class ValidationService {
  private readonly logger = new Logger(ValidationService.name);

  constructor(
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient,
  ) {}

  async validateHandle(
    handle: string,
    userId: number = null,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(`Validating handle: ${handle}`);
    if (!handle) {
      throw new BadRequestException('Handle cannot be empty.');
    }
    if (!HANDLE_REGEX.test(handle)) {
      throw new BadRequestException(
        'Handle must be 3-64 characters long and can only contain alphanumeric characters and _.-`[]{} symbols.',
      );
    }
    if (RESERVED_HANDLES.includes(handle.toLowerCase())) {
      throw new BadRequestException(`Handle '${handle}' is reserved.`);
    }

    const existingUser = await this.prismaClient.user.findFirst({
      where: { handle_lower: handle.toLowerCase() },
    });

    if (
      existingUser &&
      (!userId || (existingUser?.user_id as unknown as number) != userId)
    ) {
      this.logger.warn(`Validation failed: Handle '${handle}' already exists.`);
      throw new ConflictException(`Handle '${handle}' is already taken.`);
    }
    this.logger.log(`Handle '${handle}' is valid and available.`);
    return { valid: true };
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
      where: {
        address: email.toLowerCase(),
        // user_id: { not: null } // Ensures it's linked to a user. If an email can exist unlinked, this check is important.
        // For registration, any email record might be considered a conflict.
        // Let's assume for now that if an email address exists in the table, it's considered taken.
      },
      select: { user_id: true }, // We only need to know if it exists and if it has a user_id
    });

    // If a record for this email address exists AND it has a user_id, it means the email is in use.
    if (
      existingEmailRecord &&
      (!userId || (existingEmailRecord.user_id as unknown as number) != userId)
    ) {
      this.logger.warn(
        `Validation failed: Email '${email}' already exists and is associated with user ID: ${existingEmailRecord.user_id.toNumber()}.`,
      );
      throw new ConflictException(`Email '${email}' is already in use.`);
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
    if (!/[A-Za-z]/.test(password)) {
      throw new BadRequestException('Password must have at least a letter');
    }

    // Check if it has punctuation symbol
    if (!/\\p{P}/.test(password) && !/\d/.test(password)) {
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
   * @param socialProviderKey The string key of the social provider (e.g., 'google-oauth2').
   * @param socialProviderUserId The user's ID within that social provider.
   */
  async validateSocial(
    socialProviderKey: string,
    socialProviderUserId: string,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(
      `Validating social: providerKey=${socialProviderKey}, socialProviderUserId=${socialProviderUserId}`,
    );

    // Parameter validation (already done in controller but good for service robustness)
    if (!socialProviderKey?.trim()) {
      throw new BadRequestException('Social provider key cannot be empty.');
    }
    if (!socialProviderUserId?.trim()) {
      throw new BadRequestException('Social user ID cannot be empty.');
    }

    const providerDetails = getProviderDetails(socialProviderKey);

    if (!providerDetails) {
      this.logger.warn(
        `Unsupported provider key received: ${socialProviderKey}`,
      );
      throw new BadRequestException(
        `Unsupported provider key: ${socialProviderKey}`,
      );
    }
    if (!providerDetails.isSocial) {
      this.logger.warn(
        `Provider ${socialProviderKey} is not a social provider.`,
      );
      throw new BadRequestException(
        `Unsupported provider key: ${socialProviderKey} (Not a social provider)`,
      );
    }

    // The numeric ID (e.g., 1 for FACEBOOK, 2 for GOOGLE) is used in user_social_login.social_login_provider_id
    const providerNumericId = providerDetails.id;

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

    if (!providerNumericId) {
      return 'Mandatory parameter: Provider ID';
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
      return 'Country data must be specified.'; // Or throw new BadRequestException
    }

    // Assuming 'code' is the primary identifier in CountryDto for lookup
    if (
      !countryInput.code ||
      typeof countryInput.code !== 'string' ||
      countryInput.code.trim() === ''
    ) {
      this.logger.warn(
        'Validation failed: Country code is missing or invalid.',
      );
      return 'Country code must be provided and valid.'; // Or throw new BadRequestException
    }

    let dbCountryRecord: country | null;
    try {
      dbCountryRecord = await this.prismaClient.country.findUnique({
        // Ensure 'country' is your Prisma model name
        where: { country_code: countryInput.code },
      });
    } catch (error) {
      this.logger.error(
        `Database error while finding country by code '${countryInput.code}': ${error.message}`,
        error.stack,
      );
      // To strictly follow the "return string for error" and avoid throwing,
      // we'd return a generic error message here.
      return 'An internal error occurred while validating country data.';
    }

    if (!dbCountryRecord) {
      this.logger.warn(
        `Country with code '${countryInput.code}' not found in database.`,
      );
      return `Country with code ` + ` for code '${countryInput.code}'.`;
    }

    // --- MUTATION PART ---
    // Populate the input 'countryInput' object with data from the database.
    // This is the side effect.
    this.logger.debug(
      `Country found. Mutating input DTO with DB data: ${JSON.stringify(dbCountryRecord)}`,
    );
    countryInput.code = dbCountryRecord.country_code; // Usually already the same
    countryInput.name = dbCountryRecord.country_name;
    // If CountryDto was extended to include these:
    // countryInput.isoAlpha2Code = dbCountryRecord.isoAlpha2Code;
    // countryInput.isoAlpha3Code = dbCountryRecord.isoAlpha3Code;

    return null; // Signifies success, and countryInput has been mutated.
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
    } else if (providerDetails.id === ProviderId.LDAP) {
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
        throw new ConflictException(MSG_USER_ALREADY_BOUND_WITH_PROVIDER);
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
        throw new ConflictException(MSG_SOCIAL_PROFILE_IN_USE);
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
        social_login_provider_id: providerDetails.id, // Use id from your ProviderDetails
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
    let providerDetails: ProviderDetails | undefined;
    if (typeof providerInput === 'string') {
      providerDetails = getProviderDetails(providerInput); // Use your function
    } else {
      providerDetails = providerInput;
    }

    if (!providerDetails) {
      this.logger.warn(
        `findInternalUserIdBySsoProfile called with unknown provider input: ${JSON.stringify(providerInput)}`,
      );
      throw new BadRequestException(
        MSG_UNSUPPORTED_PROVIDER(JSON.stringify(providerInput)),
      );
    }

    this.logger.debug(
      `Finding internal user ID by SSO profile: ${JSON.stringify(profile)}, provider: ${providerDetails.key}`,
    );

    if (!providerDetails.isEnterprise) {
      this.logger.warn(
        `Attempted to find SSO user with non-enterprise provider: ${providerDetails.key}`,
      );
      return null;
    }

    let ssoLink;
    if (profile.email) {
      ssoLink = await this.prismaClient.user_sso_login.findFirst({
        where: {
          provider_id: providerDetails.id, // Use id from your ProviderDetails
          email: profile.email,
        },
        select: { user_id: true },
      });
    }

    if (!ssoLink && profile.userId) {
      ssoLink = await this.prismaClient.user_sso_login.findFirst({
        where: {
          provider_id: providerDetails.id, // Use id from your ProviderDetails
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
}
