import {
  Injectable,
  Inject,
  Logger,
  InternalServerErrorException,
  NotFoundException,
  ConflictException,
  forwardRef,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  PrismaClient,
  user as UserModel,
  Prisma,
  user_sso_login as UserSsoLoginModel,
  sso_login_provider as SsoLoginProviderModel,
} from '@prisma/client';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import {
  CreateUserBodyDto,
  UpdateUserBodyDto,
  UserSearchQueryDto,
  AchievementDto,
  CredentialDto,
  UserParamBaseDto,
  ValidationResponseDto,
  UserOtpDto,
} from '../../dto/user/user.dto';
import { ValidationService } from './validation.service';
import { v4 as uuidv4 } from 'uuid';
import { RoleService } from '../role/role.service';
import { EventService } from '../../shared/event/event.service';
import { Cache } from 'cache-manager';
import { ConfigService } from '@nestjs/config';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import * as crypto from 'crypto';
import { Decimal } from '@prisma/client/runtime/library';
import { Constants, DefaultGroups } from '../../core/constant/constants';
import { MemberPrismaService } from '../../shared/member-prisma/member-prisma.service';
import { MemberStatus } from '../../dto/member';
import { CommonUtils } from '../../shared/util/common.utils';
import { getProviderDetails } from '../../core/constant/provider-type.enum';
import { addMinutes } from 'date-fns';
// Import other needed services like NotificationService, AuthFlowService

// Define a basic structure for the Auth0 profile data we expect
// Export the interface so other modules can import it
export interface Auth0UserProfile {
  sub: string; // Auth0 unique user ID (e.g., 'auth0|12345')
  email?: string;
  email_verified?: boolean;
  given_name?: string;
  family_name?: string;
  name?: string; // Full name
  nickname?: string; // Often the handle/username
  picture?: string;
  // Add any other relevant fields from Auth0 profile
}

export const ACTIVATION_OTP_CACHE_PREFIX_KEY = 'USER_ACTIVATION_OTP';
export const ACTIVATION_OTP_EXPIRY_SECONDS = 24 * 60 * 60; // 24 hours
export const ACTIVATION_OTP_LENGTH = 6;
const OTP_ACTIVATION_MODE = 1;
const ACTIVATION_OTP_EXPIRY_MINUTES = 24 * 60;

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);
  private readonly AUTH0_PROVIDER_NAME = 'auth0'; // Define constant for Auth0 provider name
  private legacyBlowfishKey: string; // Changed: Store the raw Base64 key string directly
  private readonly defaultPassword: string;

  constructor(
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient,
    @Inject(forwardRef(() => ValidationService))
    private readonly validationService: ValidationService,
    @Inject(forwardRef(() => RoleService))
    private readonly roleService: RoleService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    private readonly eventService: EventService,
    private readonly configService: ConfigService,
    private readonly memberPrisma: MemberPrismaService,
    // Inject other services
  ) {
    // Changed: Store the Base64 key directly, validate it's set
    const base64Key = this.configService.get<string>('LEGACY_BLOWFISH_KEY');
    if (!base64Key || base64Key === '!!!_REPLACE_WITH_BASE64_ENCODED_KEY_!!!') {
      this.logger.error(
        'LEGACY_BLOWFISH_KEY environment variable is not set or is using the placeholder value. Legacy password encoding/decoding will fail.',
      );
      // throw new Error('LEGACY_BLOWFISH_KEY must be set.');
      this.legacyBlowfishKey = ''; // Assign empty string to avoid runtime errors if not thrown
    } else {
      // Optional: Basic check if it looks like Base64 (can be improved)
      try {
        Buffer.from(base64Key, 'base64'); // Test decoding
        this.legacyBlowfishKey = base64Key;
        this.logger.log('LEGACY_BLOWFISH_KEY loaded.');
      } catch (e) {
        this.logger.error(
          `LEGACY_BLOWFISH_KEY is not valid Base64: ${e.message}`,
        );
        // throw new Error('Invalid Base64 encoding for LEGACY_BLOWFISH_KEY.');
        this.legacyBlowfishKey = '';
      }
    }
    this.defaultPassword = this.configService.get<string>(
      'DEFAULT_REGISTRATION_PASS',
    );
  }

  // --- Core User Methods ---

  async findUsers(
    query: UserSearchQueryDto,
  ): Promise<{ users: UserModel[]; total: number }> {
    this.logger.debug(`Finding users with query: ${JSON.stringify(query)}`);
    const { handle, email, id, active } = this.extractSearchFilters(query);
    const filters: Prisma.userWhereInput[] = [];

    // If ID is provided, enforce exact match by user_id
    if (typeof id === 'number' && Number.isFinite(id)) {
      filters.push({ user_id: id });
    }

    if (handle) {
      filters.push({ handle_lower: handle.toLowerCase() });
    }

    if (email?.trim()) {
      const normalizedEmail = email.trim();
      filters.push({
        OR: [
          {
            user_email_xref: {
              some: {
                email: {
                  address: {
                    equals: normalizedEmail,
                    mode: 'insensitive',
                  },
                },
              },
            },
          },
          {
            emails: {
              some: {
                address: {
                  equals: normalizedEmail,
                  mode: 'insensitive',
                },
              },
            },
          },
        ],
      });
    }

    // Filter by active flag (derived from status)
    if (typeof active === 'boolean') {
      if (active) {
        filters.push({ status: MemberStatus.ACTIVE });
      } else {
        filters.push({ status: { not: MemberStatus.ACTIVE } });
      }
    }

    const whereClause: Prisma.userWhereInput = filters.length
      ? { AND: filters }
      : {};

    try {
      const total = await this.prismaClient.user.count({ where: whereClause });

      const users = await this.prismaClient.user.findMany({
        where: whereClause,
        skip: query.offset ?? 0,
        take: query.limit ?? Constants.defaultPageSize,
      });

      if (!users.length) {
        return { users, total };
      }

      const userIds = users.map((user) => user.user_id);
      const primaryEmails = await this.prismaClient.email.findMany({
        where: {
          user_id: { in: userIds },
          primary_ind: Constants.primaryEmailFlag,
          email_type_id: Constants.standardEmailType,
        },
        select: {
          user_id: true,
          address: true,
          status_id: true,
        },
      });

      const emailMap = new Map<
        string,
        { address: string | null; statusId: Decimal | null }
      >();

      for (const email of primaryEmails) {
        emailMap.set(email.user_id.toString(), {
          address: email.address ?? null,
          statusId: email.status_id ?? null,
        });
      }

      for (const user of users) {
        const emailRecord = emailMap.get(user.user_id.toString());
        if (emailRecord) {
          (user as any).primaryEmailAddress = emailRecord.address;
          (user as any).primaryEmailStatusId = emailRecord.statusId;
        }
      }

      return { users, total };
    } catch (error) {
      this.logger.error(`Error finding users: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to search users.');
    }
  }

  private extractSearchFilters(query: UserSearchQueryDto): {
    id?: number;
    handle?: string;
    email?: string;
    active?: boolean;
  } {
    const parsedFilters = this.parseFilterString(query.filter);
    // id filter: support `id` and `userId`
    const idRaw = this.getFirstFilterValue(parsedFilters, ['id', 'userId']);
    const id = idRaw != null && idRaw !== '' ? parseInt(idRaw, 10) : undefined;
    const validId = id != null && !Number.isNaN(id) && id > 0 ? id : undefined;
    const handle =
      query.handle ??
      this.getFirstFilterValue(parsedFilters, ['handle', 'handleLower']);
    const email =
      query.email ??
      this.getFirstFilterValue(parsedFilters, [
        'email',
        'emailAddress',
        'primaryEmail',
      ]);

    // active filter: true/false or 1/0
    const activeRaw = this.getFirstFilterValue(parsedFilters, ['active']);
    let active: boolean | undefined = undefined;
    if (typeof activeRaw === 'string') {
      const v = activeRaw.trim().toLowerCase();
      if (v === 'true' || v === '1') active = true;
      else if (v === 'false' || v === '0') active = false;
    }

    return { id: validId, handle, email, active };
  }

  private parseFilterString(filter?: string): Record<string, string> {
    if (!filter) {
      return {};
    }

    const rawFilters = (Array.isArray(filter) ? filter : [filter]) as string[];
    const parsed: Record<string, string> = {};

    for (const rawFilter of rawFilters) {
      if (!rawFilter) {
        continue;
      }

      const expressions = rawFilter
        .split(',')
        .map((expression) => expression.trim())
        .filter(Boolean);

      for (const expression of expressions) {
        const [rawKey, ...rawValueParts] = expression.split('=');
        if (!rawKey || rawValueParts.length === 0) {
          continue;
        }
        const value = rawValueParts.join('=').trim();
        if (!value) {
          continue;
        }

        const key = this.normalizeFilterKey(rawKey);
        if (!key) {
          continue;
        }

        parsed[key] = value;
      }
    }

    return parsed;
  }

  private normalizeFilterKey(key: string): string {
    return key.replace(/[^a-z0-9]/gi, '').toLowerCase();
  }

  private getFirstFilterValue(
    parsedFilters: Record<string, string>,
    candidates: string[],
  ): string | undefined {
    for (const candidate of candidates) {
      const normalizedCandidate = this.normalizeFilterKey(candidate);
      const match = parsedFilters[normalizedCandidate];
      if (match) {
        return match;
      }
    }
    return undefined;
  }

  async findUserById(userId: number): Promise<UserModel | null> {
    this.logger.log(`Finding user by ID: ${userId} for detailed view.`);
    // Step 1: Fetch the core user data
    const user = await this.prismaClient.user.findUnique({
      where: { user_id: userId },
      include: {
        // Include other necessary relations like SSO, but not email directly
        user_sso_login: {
          include: { sso_login_provider: true },
        },
        // user_2fa: true, // Example if 2FA status is needed
      },
    });

    if (!user) {
      // Keep NotFoundException from original logic
      throw new NotFoundException(`User with ID ${userId} not found.`);
    }

    // Step 2: Fetch the primary email separately using the structure from DDL
    const primaryEmail = await this.prismaClient.email.findFirst({
      where: {
        user_id: userId,
        primary_ind: Constants.primaryEmailFlag, // Assuming 1 represents primary based on DDL and Java DAO logic
        email_type_id: Constants.standardEmailType, // Assuming email_type_id 1 is the standard type, as seen in Java DAO
      },
      // Optionally include status/type lookups if needed by consumers
      // include: { email_status_lu: true, email_type_lu: true }
    });

    // Step 3: Attach primary email info to the user object (if found)
    // This is a common pattern but modifies the object; consider a dedicated DTO if strict typing is preferred.
    if (primaryEmail) {
      (user as any).primaryEmailAddress = primaryEmail.address;
      (user as any).primaryEmailStatusId = primaryEmail.status_id;
      // Add other email fields as needed
    }

    // Roles will be fetched separately in the controller or by a mapping function if needed for UserResponseDto
    // This service method returns the core user with directly linked OLTP data.
    return user;
  }

  async findUserByEmailOrHandle(emailOrHandle: string): Promise<
    | (UserModel & {
        user_sso_login: (UserSsoLoginModel & {
          sso_login_provider: SsoLoginProviderModel;
        })[];
      } & { primaryEmail?: { address: string; status_id: Decimal | null } }) // Add primary email info structure
    | null
  > {
    this.logger.debug(`Finding user by email or handle: ${emailOrHandle}`);
    if (!emailOrHandle) {
      throw new BadRequestException('Email or handle cannot be empty.');
    }

    const isEmail = emailOrHandle.includes('@');
    let userId: number | null = null;
    let user:
      | (UserModel & {
          user_sso_login: (UserSsoLoginModel & {
            sso_login_provider: SsoLoginProviderModel;
          })[];
        })
      | null = null;

    if (isEmail) {
      // 1. Find email record first to get user_id (primary email only)
      const emailRecord = await this.prismaClient.email.findFirst({
        where: {
          address: { equals: emailOrHandle, mode: 'insensitive' },
          primary_ind: Constants.primaryEmailFlag,
          // email_type_id: 1, // Assuming type 1 is standard primary
        },
        select: { user_id: true },
      });

      if (emailRecord) {
        userId = emailRecord.user_id.toNumber();
      } else {
        this.logger.debug(
          `No primary email record found for address: ${emailOrHandle}`,
        );
        // Do not throw, allow fallback to handle search or return null later
      }
    }

    // 2. Find user by userId (if found via email) or by handle
    if (userId) {
      user = await this.prismaClient.user.findUnique({
        where: { user_id: userId },
        include: {
          user_sso_login: { include: { sso_login_provider: true } },
        },
      });
    } else if (!isEmail) {
      // Only search by handle if it wasn't an email or email lookup failed
      user = await this.prismaClient.user.findFirst({
        where: { handle_lower: emailOrHandle.toLowerCase() },
        include: {
          user_sso_login: { include: { sso_login_provider: true } },
        },
      });
    }

    if (!user) {
      this.logger.debug(
        `User with email/handle '${emailOrHandle}' not found by findUserByEmailOrHandle.`,
      );
      return null;
    }

    // 3. Fetch primary email details separately and attach
    const primaryEmailRecord = await this.prismaClient.email.findFirst({
      where: {
        user_id: user.user_id,
        primary_ind: Constants.primaryEmailFlag,
      },
      select: { address: true, status_id: true },
    });

    // Attach primary email info to the returned user object
    const userWithEmail = user as typeof user & {
      primaryEmail?: { address: string; status_id: Decimal | null };
    };
    if (primaryEmailRecord) {
      userWithEmail.primaryEmail = {
        address: primaryEmailRecord.address,
        status_id: primaryEmailRecord.status_id,
      };
    }

    return userWithEmail;
  }

  async findUserByEmail(email: string): Promise<
    | (UserModel & {
        user_sso_login: (UserSsoLoginModel & {
          sso_login_provider: SsoLoginProviderModel;
        })[];
      } & { primaryEmail?: { address: string; status_id: Decimal | null } }) // Add primary email info structure
    | null
  > {
    this.logger.debug(`Finding user by email: ${email}`);
    if (!email) {
      throw new BadRequestException('Email cannot be empty.');
    }

    let userId: number | null = null;
    let user:
      | (UserModel & {
          user_sso_login: (UserSsoLoginModel & {
            sso_login_provider: SsoLoginProviderModel;
          })[];
        })
      | null = null;
    let primaryEmailRecord = null;

    const emailRecords = await this.prismaClient.email.findMany({
      where: {
        address: email.toLowerCase(),
        primary_ind: Constants.primaryEmailFlag,
        email_type_id: Constants.standardEmailType,
      },
      select: { user_id: true, address: true, status_id: true },
    });

    if (emailRecords) {
      for (let i = 0; i < emailRecords.length; i++) {
        if (emailRecords[i].address == email) {
          primaryEmailRecord = emailRecords[i];
          userId = emailRecords[i].user_id as unknown as number;
          break;
        }
      }
    } else {
      this.logger.debug(`No primary email record found for address: ${email}`);
      // Do not throw, allow fallback to handle search or return null later
    }

    // 2. Find user by userId (if found via email)
    if (userId) {
      user = await this.prismaClient.user.findUnique({
        where: { user_id: userId },
        include: {
          user_sso_login: { include: { sso_login_provider: true } },
        },
      });
    }

    if (!user) {
      this.logger.debug(
        `User with email '${email}' not found by findUserByEmail.`,
      );
      return null;
    }

    // 3. Fetch primary email details separately and attach
    // Attach primary email info to the returned user object
    const userWithEmail = user as typeof user & {
      primaryEmail?: { address: string; status_id: Decimal | null };
    };
    if (primaryEmailRecord) {
      userWithEmail.primaryEmail = {
        address: primaryEmailRecord.address,
        status_id: primaryEmailRecord.status_id,
      };
    }

    return userWithEmail;
  }

  private generateNumericOtp(length: number): string {
    let otp = '';
    const otpChars = '0123456789';
    for (let i = 0; i < length; i++) {
      otp += otpChars.charAt(Math.floor(Math.random() * otpChars.length));
    }
    return otp;
  }

  /**
   * Encodes password using the legacy Blowfish/ECB/PKCS5Padding method.
   * Matches the logic from the old Java Utils.encodePassword.
   * @param password Plain text password
   * @returns Base64 encoded encrypted password string
   */
  public encodePasswordLegacy(password: string): string {
    if (!this.legacyBlowfishKey) {
      this.logger.error(
        'Attempted to use legacy password encoding without a valid LEGACY_BLOWFISH_KEY.',
      );
      throw new InternalServerErrorException(
        'Legacy password system is misconfigured.',
      );
    }
    try {
      const key = Buffer.from(this.legacyBlowfishKey, 'base64');
      const cipher = crypto.createCipheriv('bf-ecb', key, null);
      let encryptedResult = cipher.update(password, 'utf8', 'base64');
      encryptedResult += cipher.final('base64');

      return encryptedResult;
    } catch (error) {
      this.logger.error(
        `Failed to encode password using legacy Blowfish: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Password encoding failed.');
    }
  }

  /**
   * Verifies a plain text password against a legacy Blowfish encoded stored password.
   * @param password Plain text password from user input
   * @param storedEncoded Base64 encoded password stored in the database
   * @returns boolean True if the password matches, false otherwise.
   */
  public verifyLegacyPassword(
    password: string,
    storedEncoded: string,
  ): boolean {
    if (!this.legacyBlowfishKey) {
      this.logger.error(
        'Attempted to use legacy password verification without a valid LEGACY_BLOWFISH_KEY.',
      );
      // In a real auth flow, this should probably return false or throw specific error
      return false;
    }
    if (!password || !storedEncoded) {
      return false; // Cannot compare empty values
    }
    try {
      const newlyEncoded = this.encodePasswordLegacy(password);
      // Direct string comparison should be safe as Base64 uses a fixed character set.
      return newlyEncoded === storedEncoded.trim();
    } catch (error) {
      // Includes errors from encodePasswordLegacy
      this.logger.error(
        `Error during legacy password verification: ${error.message}`,
      );
      return false; // Fail verification on error
    }
  }

  async registerUser(createUserDto: CreateUserBodyDto): Promise<UserModel> {
    const userParams: UserParamBaseDto = createUserDto.param;

    // set default password in case of missing password
    if (userParams.profile) {
      if (!userParams.credential) {
        userParams.credential = {} as CredentialDto;
      }
      if (!CommonUtils.validateString(userParams.credential.password)) {
        userParams.credential.password = this.defaultPassword;
      }
    }
    // perform initial static validations
    this.validationService.validateUser(userParams);
    // handle validation
    const validationResponse: ValidationResponseDto =
      await this.validationService.validateHandle(userParams.handle);
    if (!validationResponse.valid) {
      throw new BadRequestException(
        `Handle validation failed: ${validationResponse.reason}`,
      );
    }
    // email validation
    await this.validationService.validateEmailViaDB(userParams.email);
    // country validation
    if (userParams.country != null) {
      const result = await this.validationService.validateCountryAndMutate(
        userParams.country,
      );
      if (result) {
        // means there is something wrong
        throw new BadRequestException(result);
      }
    }
    // profile validation
    if (userParams.profile != null) {
      await this.validationService.validateProfile(userParams.profile);
    }
    // referral validation
    if (userParams.utmCampaign === 'ReferralProgram') {
      const result = await this.validationService.validateReferral(
        userParams.utmSource,
      );
      if (result) {
        // means there is something wrong
        throw new BadRequestException(result);
      }
    }

    userParams.isActive = false; // new user is inactive initially
    userParams.status = MemberStatus.UNVERIFIED;

    // -----------------------------------
    // setAccessToken not implemented yet
    // issue running auth0 flow in DEV
    // -----------------------------------

    // Generate OTP first, as it will be stored as the activation_code
    const otpForActivation = this.generateNumericOtp(ACTIVATION_OTP_LENGTH);

    // Step 1: Get the next user ID from the sequence (mimicking Java DAO)
    const nextUserId: number = await this.getNextUserId();
    // Step 2: Perform inserts within a transaction using the fetched ID
    let newUser: UserModel;
    try {
      newUser = await this.prismaClient.$transaction(async (prisma) => {
        const userData = {
          user_id: nextUserId,
          handle: userParams.handle,
          handle_lower: userParams.handle.toLowerCase(),
          status: userParams.status,
          first_name: userParams.firstName,
          last_name: userParams.lastName,
          create_date: new Date(),
          modify_date: new Date(),
          activation_code: otpForActivation,
          reg_source: userParams.regSource,
          utm_source: userParams.utmSource,
          utm_medium: userParams.utmMedium,
          utm_campaign: userParams.utmCampaign,
        };

        this.logger.debug(
          `[registerUser Transaction] Data for prisma.user.create: ${JSON.stringify(userData)}`,
        );

        // ============
        // insert user
        // ============
        const createdUser = await prisma.user.create({
          data: userData,
        });
        this.logger.log(
          `User record created for ${userParams.handle} (ID: ${createdUser.user_id.toNumber()})`,
        );

        // Use the existing service method for consistent password encoding
        const actualEncodedPassword = this.encodePasswordLegacy(
          userParams.credential.password,
        );

        this.logger.debug(
          `[RegisterUser Tx] Encrypted password for handle ${userParams.handle} (using encodePasswordLegacy): ${actualEncodedPassword}`,
        );

        // ====================
        // insert security user
        // ====================
        await prisma.security_user.create({
          data: {
            login_id: createdUser.user_id, // Use the Decimal user_id directly
            user_id: userParams.handle,
            password: actualEncodedPassword, // Use password from service method
          },
        });
        this.logger.log(
          `Security user record created for user ${userParams.handle} (ID: ${nextUserId})`,
        );

        // ====================
        // insert Email record
        // ====================
        await this.createEmailRecord(prisma, userParams, nextUserId);

        // =======================
        // insert user social/sso
        // =======================
        if (userParams.profile) {
          await this.createSsoSocialLoginDuringRegistration(
            prisma,
            userParams,
            nextUserId,
            userParams.email,
          );
        }

        // add user to initial groups
        await this.addUserToDefaultGroups(prisma, nextUserId);

        return createdUser;
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === Constants.prismaUniqueConflictcode) {
          this.logger.warn(
            `Registration failed due to unique constraint: ${error.message}. Fields: ${JSON.stringify(error.meta?.target)}`,
          );
          if ((error.meta?.target as string[])?.includes('handle_lower')) {
            throw new ConflictException(
              `Handle '${userParams.handle}' already exists.`,
            );
          } else if ((error.meta?.target as string[])?.includes('address')) {
            throw new ConflictException(
              `Email '${userParams.email}' already exists.`,
            );
          }
          throw new ConflictException(
            'User with this handle or email already exists.',
          );
        }
      }
      this.logger.error(
        `Error during user registration transaction for ${userParams.handle}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'User registration failed due to a database error.',
      );
    }

    // ==============
    // insert member
    // ==============
    await this.createMemberData(nextUserId, userParams);

    // =============
    // insert otp
    // =============
    // when not active yet
    if (newUser.status != MemberStatus.ACTIVE) {
      const expiresAt = addMinutes(new Date(), ACTIVATION_OTP_EXPIRY_MINUTES);
      // we insert a new one
      await this.prismaClient.user_otp_email.create({
        data: {
          user_id: newUser.user_id,
          mode: OTP_ACTIVATION_MODE,
          otp: otpForActivation,
          resend: false,
          fail_count: 0,
          expire_at: expiresAt,
        },
      });
      await this.resendActivationEmailEvent(
        {
          handle: newUser.handle,
          otp: otpForActivation,
          userId: Number(newUser.user_id),
        },
        userParams.email,
      );
    } else {
      // add Topcoder User role if the user was auto-activated
      await this.assignDefaultUserRole(Number(newUser.user_id));
    }

    // ================================
    // assign additional roles to user
    // ================================
    await this.assignRolesForNewUser(
      userParams.regSource,
      Number(newUser.user_id),
      userParams.primaryRole,
    );

    // ==========================
    // publish user created event
    // ==========================
    await this.publishUserCreatedEvent(newUser, userParams, otpForActivation);

    this.logger.log(
      `Successfully registered user ${newUser.handle} (ID: ${newUser.user_id.toNumber()}). Status: U. Activation OTP sent for eventing.`,
    );
    return newUser;
  }

  private async assignRolesForNewUser(
    regSource: string,
    userId: number,
    userPrimaryRole: string,
  ) {
    // add business user role if needed
    if (
      CommonUtils.validateString(regSource) &&
      regSource.match(/^tcBusiness$/)
    ) {
      await this.roleService.assignRoleByName('Business User', userId, userId);
    }
    // add self-service customer role if needed
    if (
      CommonUtils.validateString(regSource) &&
      regSource.match(/^selfService$/)
    ) {
      await this.roleService.assignRoleByName(
        'Self-Service Customer',
        userId,
        userId,
      );
    }

    let primaryRole = 'Topcoder Talent';
    // if userPrimaryRole is null, primaryRole stays as 'Topcoder Talent'
    // if userPrimaryRole is 'Topcoder Customer', replace primaryRole as 'Topcoder Customer'
    this.logger.log('User Primary Role from request: ' + userPrimaryRole);
    if (
      CommonUtils.validateString(userPrimaryRole) &&
      userPrimaryRole.toLowerCase() === 'topcoder customer'
    ) {
      primaryRole = 'Topcoder Customer';
    }

    this.logger.log('Primary Role to be saved: ' + primaryRole);
    // assign primary role
    await this.roleService.assignRoleByName(primaryRole, userId, userId);
  }

  private async getNextUserId(): Promise<number> {
    try {
      // Prisma doesn't have a built-in nextval function, use raw query
      const result: { nextval: bigint }[] = await this.prismaClient
        .$queryRaw`SELECT nextval('sequence_user_seq'::regclass)`;
      if (!result || result.length === 0 || !result[0].nextval) {
        throw new Error('Failed to retrieve next user ID from sequence.');
      }
      const nextUserId = Number(result[0].nextval);
      this.logger.debug(
        `[registerUser] Fetched next user ID from sequence: ${nextUserId}`,
      );
      return nextUserId;
    } catch (seqError) {
      this.logger.error(
        `[registerUser] Error fetching next user ID: ${seqError.message}`,
        seqError.stack,
      );
      throw new InternalServerErrorException('Failed to generate user ID.');
    }
  }

  private async createMemberData(
    nextUserId: number,
    userParams: UserParamBaseDto,
  ) {
    // Create the member record outside of the interactive transaction
    // to avoid cross-client work while a Prisma transaction is open
    try {
      await this.memberPrisma.member.create({
        data: {
          userId: Number(nextUserId),
          handle: userParams.handle,
          handleLower: userParams.handle.toLowerCase(),
          email: userParams.email,
          tracks: [],
          createdBy: String(nextUserId),
          firstName: userParams.firstName ?? null,
          lastName: userParams.lastName ?? null,
          status: 'UNVERIFIED',
        },
      });
    } catch (err) {
      this.logger.error(
        { err },
        `Failed to create member record for new user ${String(nextUserId)} / ${userParams.handle}`,
      );
      // Intentionally not throwing to keep registration flow consistent
    }
  }

  private async createEmailRecord(
    prisma: any,
    userParams: UserParamBaseDto,
    nextUserId: number,
  ) {
    let emailRecord = await prisma.email.findFirst({
      where: { address: { equals: userParams.email, mode: 'insensitive' } },
    });
    if (!emailRecord) {
      // ADDED: Fetch next email_id explicitly
      let nextEmailId: number;
      try {
        const result: { nextval: bigint }[] =
          await prisma.$queryRaw`SELECT nextval('sequence_email_seq'::regclass)`;
        if (!result || result.length === 0 || !result[0].nextval) {
          throw new Error('Failed to retrieve next email ID from sequence.');
        }
        nextEmailId = Number(result[0].nextval);
        this.logger.debug(
          `[registerUser Transaction] Fetched next email ID: ${nextEmailId}`,
        );
      } catch (seqError) {
        this.logger.error(
          `[registerUser Transaction] Error fetching next email ID: ${seqError.message}`,
          seqError.stack,
        );
        throw new InternalServerErrorException('Failed to generate email ID.');
      }

      emailRecord = await prisma.email.create({
        data: {
          email_id: nextEmailId, // Use fetched ID
          user_id: nextUserId, // ADDED: Link directly to the user ID
          address: userParams.email, // Use provided email
          primary_ind: Constants.primaryEmailFlag, // Defaulted based on Java code logic
          status_id: Constants.unverifiedEmailStatus, // Defaulted based on Java code logic (Inactive/Unverified initially)
          email_type_id: Constants.standardEmailType, // ADDED: Assume type 1 (Primary) as per Java DAO's email queries
          create_date: new Date(),
          modify_date: new Date(),
        },
      });
      this.logger.debug(
        `Email record created for ${userParams.email} (ID: ${emailRecord.email_id.toNumber()})`,
      );
    } else {
      const msg = `Existing email record found for ${userParams.email} (ID: ${emailRecord.email_id.toNumber()})`;
      this.logger.debug(msg);
      throw new Error(msg);
    }
  }

  private async publishUserCreatedEvent(
    newUser: UserModel,
    userParams: UserParamBaseDto,
    otpForActivation: string,
  ) {
    try {
      // For 'event.user.created', attributes should be the full camelCased newUser object
      const createdEventAttributes = this.toCamelCase(newUser);
      // Use postEnvelopedNotification for standard events
      await this.eventService.postEnvelopedNotification(
        'event.user.created',
        createdEventAttributes,
      );
      this.logger.log(
        `Published 'event.user.created' notification for ${newUser.user_id.toNumber()}. Attributes: ${JSON.stringify(createdEventAttributes, null, 2)}`,
      );

      // For activation email, use postDirectBusMessage to match legacy Java structure
      const domain =
        this.configService.get<string>('APP_DOMAIN') || 'topcoder-dev.com'; // Get domain from config
      const fromEmail = `Topcoder <noreply@${domain}>`;
      const sendgridTemplateId = this.configService.get<string>(
        'SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID',
      );

      if (!sendgridTemplateId) {
        this.logger.error(
          `SendGrid template ID not configured (SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID). Cannot send initial registration/activation email.`,
        );
      } else {
        const activationEmailPayload = {
          data: { handle: newUser.handle, code: otpForActivation },
          from: { email: fromEmail },
          version: 'v6',
          sendgrid_template_id: sendgridTemplateId,
          recipients: [userParams.email], // The original email used for registration
        };
        await this.eventService.postDirectBusMessage(
          'external.action.email',
          activationEmailPayload,
        );
        this.logger.log(
          `Published 'external.action.email' (activation) for ${newUser.user_id.toNumber()} to ${userParams.email}. Payload: ${JSON.stringify(activationEmailPayload, null, 2)}`,
        );
      }
    } catch (eventError) {
      this.logger.error(
        `Failed to publish events for user ${newUser.user_id.toNumber()}: ${eventError.message}`,
        eventError.stack,
      );
    }
  }

  private async createSsoSocialLoginDuringRegistration(
    prisma: any,
    userParams: UserParamBaseDto,
    nextUserId: number,
    email: string,
  ) {
    // Capture original providerType value (e.g., 'adfs', 'wipro', 'tc', etc.) before validation normalizes it
    const originalProviderTypeKey = userParams.profile.provider;

    try {
      console.log(`originalProviderTypeKey: ${originalProviderTypeKey}`);
      if (originalProviderTypeKey) {
        const details = getProviderDetails(originalProviderTypeKey);
        if (details?.isSocial) {
          // do we validate profile parameters for social?

          const providerRecord = await prisma.social_login_provider.findFirst({
            where: { name: originalProviderTypeKey },
          });
          if (!providerRecord) {
            this.logger.error(
              `[registerUser Transaction] Enterprise provider '${originalProviderTypeKey}' not found in sso_login_provider; skipping user_sso_login creation.`,
            );
          } else {
            await prisma.user_social_login.create({
              data: {
                user_id: nextUserId,
                social_login_provider_id:
                  providerRecord.social_login_provider_id,
                social_user_name: userParams?.profile?.name,
                social_email: userParams?.profile?.email,
                social_email_verified: userParams?.profile?.isEmailVerified,
                social_user_id: userParams?.profile?.userId,
              },
            });
          }
        } else if (details?.isEnterprise && details?.key !== 'ad') {
          // not ldap
          const providerRecord = await prisma.sso_login_provider.findFirst({
            where: { name: originalProviderTypeKey },
          });
          if (!providerRecord) {
            this.logger.error(
              `[registerUser Transaction] Enterprise provider '${originalProviderTypeKey}' not found in sso_login_provider; skipping user_sso_login creation.`,
            );
          } else {
            const ssoUserId = userParams?.profile?.userId;
            if (!ssoUserId) {
              this.logger.warn(
                `[registerUser Transaction] Enterprise profile missing userId for provider '${originalProviderTypeKey}'; skipping user_sso_login creation.`,
              );
            } else {
              const data = {
                user_id: nextUserId,
                provider_id: providerRecord.sso_login_provider_id,
                sso_user_id: ssoUserId,
                email: userParams?.profile?.email || email,
                sso_user_name: userParams?.profile?.name,
              };
              console.log(`Creating user_sso_login : ${JSON.stringify(data)}`);

              await prisma.user_sso_login.create({
                data,
              });
              this.logger.log(
                `[registerUser Transaction] Created user_sso_login for user ${nextUserId} with provider '${originalProviderTypeKey}'.`,
              );
            }
          }
        }
      }
    } catch (ssoError) {
      this.logger.error(
        `[registerUser Transaction] Error creating user_sso_login for enterprise provider '${originalProviderTypeKey}': ${ssoError.message}`,
        ssoError.stack,
      );
      // Do not fail the whole registration for SSO link issues
      // TODO: Should we fail here?  I don't know that the user will be able to login without that record...
    }
  }

  async updateBasicInfo(
    userIdString: string,
    updateUserDto: UpdateUserBodyDto,
  ): Promise<UserModel> {
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId) || userId <= 0) {
      throw new BadRequestException('Invalid user ID format.');
    }
    this.logger.log(`Updating basic info for user ID: ${userId}`);
    const userParams = updateUserDto.param; // Access nested param object

    const cred: CredentialDto = userParams.credential;
    // validate password if it's specified.
    if (cred != null && cred.password != null)
      this.validationService.validatePassword(cred.password);

    const existingUser = await this.findUserById(userId);
    if (!existingUser) {
      throw new NotFoundException(`User with ID ${userId} not found.`);
    }

    // Can't update handle, email, isActive
    if (userParams.handle != null && userParams.handle != existingUser.handle)
      throw new BadRequestException("Handle can't be updated");
    if (userParams.status != null && userParams.status != existingUser.status)
      throw new BadRequestException("Status can't be updated");

    if (
      userParams.email != null &&
      userParams.email != (existingUser as any).primaryEmailAddress
    )
      throw new BadRequestException("Email address can't be updated");

    let securityUserRecord = null;
    // validate password if it's specified.
    if (cred != null && cred.password != null) {
      // currentPassword is required and must match with registered password
      if (cred.currentPassword == null)
        throw new BadRequestException('Current Password is required');

      securityUserRecord = await this.prismaClient.security_user.findUnique({
        where: { login_id: userId },
        select: {
          password: true,
        },
      });
      if (
        !securityUserRecord ||
        securityUserRecord.password !=
          this.encodePasswordLegacy(cred.currentPassword)
      )
        throw new BadRequestException('Current password is not correct');
    }

    // Only update fields present in the DTO
    const dataToUpdate: Prisma.userUpdateInput = {};
    if (userParams.firstName)
      existingUser.first_name = dataToUpdate.first_name = userParams.firstName;
    if (userParams.lastName)
      existingUser.last_name = dataToUpdate.last_name = userParams.lastName;
    if (userParams.regSource)
      existingUser.reg_source = dataToUpdate.reg_source = userParams.regSource;
    if (userParams.utmSource)
      existingUser.utm_source = dataToUpdate.utm_source = userParams.utmSource;
    if (userParams.utmMedium)
      existingUser.utm_medium = dataToUpdate.utm_medium = userParams.utmMedium;
    if (userParams.utmCampaign)
      existingUser.utm_campaign = dataToUpdate.utm_campaign =
        userParams.utmCampaign;

    if (Object.keys(dataToUpdate).length === 0) {
      return existingUser; // Return current user if no changes
    }

    await this.prismaClient.$transaction(async (prisma) => {
      const userInTx = await this.prismaClient.user.update({
        where: { user_id: userId },
        data: dataToUpdate,
      });
      this.logger.log(`Successfully updated basic info for user ${userId}`);

      // update password
      if (cred != null && cred.password != null) {
        this.logger.debug(`"updating password: ${userInTx.handle}`);
        existingUser.password = cred.password;

        if (securityUserRecord) {
          await prisma.security_user.update({
            where: { login_id: userId },
            data: { password: this.encodePasswordLegacy(cred.password) },
          });
        }
      }

      return userInTx;
    });

    return existingUser;
  }

  // --- Utility to convert snake_case keys to camelCase ---
  public toCamelCase(obj: any): any {
    if (Array.isArray(obj)) {
      return obj.map((v) => this.toCamelCase(v));
    } else if (obj !== null && obj.constructor === Object) {
      return Object.keys(obj).reduce((result, key) => {
        const camelKey = key.replace(/([-_][a-z])/gi, ($1) => {
          return $1.toUpperCase().replace('-', '').replace('_', '');
        });
        result[camelKey] = this.toCamelCase(obj[key]);
        return result;
      }, {} as any);
    }
    return obj;
  }

  // --- Additional User Update Methods ---

  async updateHandle(
    userIdString: string,
    newHandle: string,
    authUser: AuthenticatedUser,
  ): Promise<UserModel> {
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid user ID format.');
    }
    this.logger.log(
      `Attempting to update handle for user ID: ${userId} to ${newHandle}, by admin: ${authUser.userId}`,
    );

    // Validate format and uniqueness (ValidationService throws on failure)
    const validationResponse = await this.validationService.validateHandle(
      newHandle,
      userId,
    );
    if (!validationResponse.valid) {
      throw new BadRequestException(
        `Handle validation failed: ${validationResponse.reason}`,
      );
    }

    // Fetch the user to ensure they exist and get the old handle
    const existingUser = await this.prismaClient.user.findUnique({
      where: { user_id: userId },
    });
    if (!existingUser) {
      throw new NotFoundException(`User with ID ${userId} not found.`);
    }

    const oldHandle = existingUser.handle; // Get the old handle

    // Check if handle is actually changing to avoid unnecessary DB write and event
    if (oldHandle === newHandle) {
      this.logger.log(
        `Handle for user ${userId} is already ${newHandle}. No update performed.`,
      );
      return existingUser;
    }

    try {
      // Start a transaction to update both user and security_user tables
      const updatedUser = await this.prismaClient.$transaction(
        async (prisma) => {
          const userInTx = await prisma.user.update({
            where: { user_id: userId },
            data: {
              handle: newHandle,
              handle_lower: newHandle.toLowerCase(),
              modify_date: new Date(),
              // modified_by: authUser.userId.toString(), // Consider adding if you have this field
            },
          });
          this.logger.log(
            `Successfully updated handle in 'user' table for user ${userId} from ${oldHandle} to ${newHandle}`,
          );

          // Now update the security_user table.
          const securityUserRecord = await prisma.security_user.findUnique({
            where: { login_id: userId },
          });

          if (securityUserRecord) {
            // If it exists, update its user_id (which is the handle) to the new handle
            // This assumes that security_user.user_id (the handle) must be unique.
            // If another user already has newHandle in security_user.user_id, this would fail.
            // This should ideally be caught by the initial validateHandle if security_user.user_id mirrors user.handle.
            await prisma.security_user.update({
              where: { login_id: userId },
              data: { user_id: newHandle },
            });
            this.logger.log(
              `Successfully updated handle in 'security_user' table from ${oldHandle} to ${newHandle} for numeric user ID ${userId}`,
            );
          } else {
            // This case might occur if a user record exists but its security_user counterpart was never created
            // or was created with a different convention. Log a warning.
            this.logger.warn(
              `No security_user record found with handle (user_id) '${oldHandle}' for numeric user ID ${userId}. Cannot update handle in security_user.`,
            );
          }
          return userInTx;
        },
      );

      // Convert to camelCase and publish event.user.updated event
      const eventPayload = this.toCamelCase(updatedUser);
      await this.eventService.postEnvelopedNotification(
        'event.user.updated',
        eventPayload,
      );
      this.logger.log(
        `Published 'event.user.updated' notification for handle change, user ${userId}. Attributes: ${JSON.stringify(eventPayload, null, 2)}`,
      );

      return updatedUser;
    } catch (error) {
      // P2002 for unique constraint violation should be caught by validateHandle now
      // P2025 for record to update not found should be caught by pre-fetch
      this.logger.error(
        `Error updating handle for user ${userId}: ${error.message}`,
        error.stack,
      );
      // Check if it's a unique constraint violation on security_user.user_id (the new handle)
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === Constants.prismaUniqueConflictcode
      ) {
        const target = error.meta?.target as string[];
        if (
          target &&
          target.includes('user_id') &&
          error.message.includes('security_user')
        ) {
          // Heuristic check
          this.logger.warn(
            `Attempted to update handle in security_user to '${newHandle}', but it already exists for another user.`,
          );
          throw new ConflictException(
            `The handle '${newHandle}' is already in use in the security system.`,
          );
        }
      }
      throw new InternalServerErrorException(
        'Failed to update user handle due to a database error.',
      );
    }
  }

  async updatePrimaryEmail(
    userIdString: string,
    newEmail: string,
    authUser: AuthenticatedUser,
  ): Promise<UserModel> {
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid user ID format.');
    }

    this.logger.log(
      `Attempting to update primary email for user ID: ${userId} to ${newEmail} by admin ${authUser.userId}`,
    );

    // Validate new email
    await this.validationService.validateEmail(newEmail, userId);
    const updatedUserInTx = await this.prismaClient.$transaction(async (tx) => {
      // Find the user first
      const userInDB = await tx.user.findUnique({
        where: { user_id: userId },
      });

      if (!userInDB) {
        throw new NotFoundException(`User ${userId} not found.`);
      }

      // Find the current primary email record for this user
      const currentPrimaryEmailRecord = await tx.email.findFirst({
        where: {
          user_id: userId,
          primary_ind: Constants.primaryEmailFlag,
          email_type_id: Constants.standardEmailType,
        },
      });

      if (!currentPrimaryEmailRecord) {
        throw new NotFoundException(
          `No primary email found for user ${userId}.`,
        );
      }

      const oldEmail = currentPrimaryEmailRecord.address;

      // If the new email is the same as current, return user as-is
      if (oldEmail.toLowerCase() === newEmail.toLowerCase()) {
        this.logger.log(
          `Email ${newEmail} is already the primary email for user ${userId}. No changes needed.`,
        );
        return userInDB;
      }

      // Check if new email is already taken by another user as primary
      const existingEmailRecord = await tx.email.findFirst({
        where: {
          address: { equals: newEmail, mode: 'insensitive' },
          user_id: { not: userId },
          primary_ind: Constants.primaryEmailFlag,
        },
      });

      if (existingEmailRecord) {
        throw new BadRequestException(
          'Email address is already in use by another user.',
        );
      }

      // Simply UPDATE the existing primary email record with the new email address
      await tx.email.update({
        where: { email_id: currentPrimaryEmailRecord.email_id },
        data: {
          address: newEmail.toLowerCase(),
          modify_date: new Date(),
        },
      });

      this.logger.log(
        `Updated existing primary email record ${currentPrimaryEmailRecord.email_id.toNumber()} from ${oldEmail} to ${newEmail} for user ${userId}`,
      );

      // Update the user record
      const updatedUser = await tx.user.update({
        where: { user_id: userId },
        data: {
          modify_date: new Date(),
          // modified_by: authUser.userId
        },
      });

      this.logger.log(
        `Successfully updated primary email for user ${userId} from ${oldEmail} to ${newEmail}`,
      );

      return updatedUser;
    });

    // Publish user updated event
    try {
      const eventAttributes = this.toCamelCase(updatedUserInTx);
      await this.eventService.postEnvelopedNotification(
        'event.user.updated',
        eventAttributes,
      );
      this.logger.log(
        `Published 'event.user.updated' notification for primary email change to ${newEmail}, user ${userIdString}`,
      );
    } catch (eventError) {
      this.logger.error(
        `Failed to publish user.updated notification for primary email change, user ${userIdString}: ${eventError.message}`,
        eventError.stack,
      );
    }

    return updatedUserInTx;
  }

  async updateStatus(
    userIdString: string,
    newStatus: string,
    authUser: AuthenticatedUser,
    comment: string,
  ): Promise<UserModel> {
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid User ID format.');
    }
    this.logger.log(
      `Attempting to update status for user ID: ${userId} to ${newStatus} by admin: ${authUser.userId}`,
    );
    const normalizedNewStatus = newStatus.toUpperCase();

    const validStatuses = Object.values(MemberStatus).map((s) =>
      s.toUpperCase(),
    ); // Use MemberStatus enum
    if (!validStatuses.includes(normalizedNewStatus)) {
      throw new BadRequestException(
        `Invalid status code: ${newStatus}. Must be one of: ${validStatuses.join(', ')}`,
      );
    }

    const user = await this.prismaClient.user.findUnique({
      where: { user_id: userId },
    });
    if (!user) {
      throw new NotFoundException(
        `User with ID ${userId} not found for status update.`,
      );
    }

    const oldStatus = user.status;
    if (oldStatus === normalizedNewStatus) {
      this.logger.log(
        `User ${userId} status is already ${normalizedNewStatus}. No update performed.`,
      );
      return user;
    }

    try {
      const updatedUser = await this.prismaClient.user.update({
        where: {
          user_id: userId,
          status: { not: MemberStatus.INACTIVE_IRREGULAR_ACCOUNT },
        },
        data: {
          status: normalizedNewStatus,
          modify_date: new Date(),
        },
      });
      this.logger.log(
        `Successfully updated status for user ${userId} from ${oldStatus} to ${normalizedNewStatus}`,
      );

      // create user achievement
      if (CommonUtils.validateString(comment)) {
        await this.createUserAchievement(userId, comment);
      }
      // activate email
      const primaryEmailRecord = await this.prismaClient.email.findFirst({
        where: {
          user_id: userId,
          primary_ind: Constants.primaryEmailFlag,
        },
      });
      if (
        user.status == MemberStatus.ACTIVE &&
        primaryEmailRecord &&
        Number(primaryEmailRecord.status_id) !== Constants.verifiedEmailStatus
      ) {
        await this.activateEmail(Number(primaryEmailRecord.email_id));
      }

      // Event Publishing Logic based on Java UserResource.updateStatus
      let notificationType = 'event.user.updated'; // Generic update
      if (normalizedNewStatus === 'A' && oldStatus !== 'A') {
        notificationType = 'event.user.activated';
      } else if (normalizedNewStatus !== 'A' && oldStatus === 'A') {
        notificationType = 'event.user.deactivated'; // Or more specific like user.status.inactive, etc.
      }

      const eventAttributes = this.toCamelCase(updatedUser);
      await this.eventService.postEnvelopedNotification(
        notificationType,
        eventAttributes,
      );
      this.logger.log(
        `Published '${notificationType}' notification for user ${userId}. Attributes: ${JSON.stringify(eventAttributes, null, 2)}`,
      );

      // If status changed from Unverified to Active, send welcome email & assign default role
      if (
        oldStatus === MemberStatus.UNVERIFIED &&
        normalizedNewStatus === MemberStatus.ACTIVE
      ) {
        const primaryEmailRecord = await this.prismaClient.email.findFirst({
          where: {
            user_id: userId,
            primary_ind: Constants.primaryEmailFlag,
            status_id: Constants.verifiedEmailStatus,
          }, // Ensure it's verified
        });

        if (primaryEmailRecord?.address) {
          await this.notifyWelcome(userId, primaryEmailRecord?.address);
        }
        // assign default role
        await this.assignDefaultUserRole(userId);
      }

      return updatedUser;
    } catch (error) {
      // P2025 for record to update not found should be caught by pre-fetch
      this.logger.error(
        `Error updating status for user ${userId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'Failed to update user status due to a database error.',
      );
    }
  }

  /**
   * Activate email of user.
   * @param emailId Email ID
   * @throws InternalServerErrorException When an error activating email
   */
  async activateEmail(emailId: number) {
    try {
      await this.prismaClient.email.update({
        data: {
          status_id: Constants.verifiedEmailStatus,
        },
        where: {
          email_id: emailId,
          email_type_id: Constants.standardEmailType,
        },
      });
    } catch (error) {
      this.logger.error(
        `Error activating email of user: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Failed to activate user email');
    }
  }

  // --- User Achievements ---

  async getAchievements(
    userId: number,
    selector?: string,
  ): Promise<AchievementDto[]> {
    this.logger.debug(`Fetching achievements for user ID: ${userId}`);
    try {
      const achievements = await this.prismaClient.user_achievement.findMany({
        where: { user_id: userId },
        include: {
          achievement_type_lu: true, // Include the description lookup table
        },
      });

      // Map to AchievementDto
      const mappedAchievements = achievements.map((ach) => ({
        achievement_type_id: Number(ach.achievement_type_id),
        achievement_desc: ach.achievement_type_lu.achievement_type_desc,
        date: ach.create_date,
        description: ach.description,
      }));
      if (selector && selector.trim().length > 0) {
        const keys = selector.split(',');
        return CommonUtils.pickArray(
          mappedAchievements,
          keys,
        ) as AchievementDto[];
      }
      return mappedAchievements;
    } catch (error) {
      this.logger.error(
        `Error fetching achievements for user ${userId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'Failed to retrieve user achievements.',
      );
    }
  }

  async createUserAchievement(userId: number, comment: string) {
    try {
      const now = new Date();
      await this.prismaClient.user_achievement.create({
        data: {
          user_id: userId,
          achievement_date: now,
          achievement_type_id: 2,
          description: comment,
          create_date: now,
        },
      });
    } catch (error) {
      this.logger.error(
        `Error saving achievement for user ${userId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Failed to save user achivement');
    }
  }

  // --- Auth0 Integration ---

  /**
   * Finds an existing user based on Auth0 profile's 'sub' identifier,
   * or creates a new user if one doesn't exist.
   * This is crucial for the Auth0 callback flow.
   */
  async findOrCreateUserByAuth0Profile(
    auth0Profile: Auth0UserProfile,
  ): Promise<UserModel> {
    this.logger.log(
      `Finding or creating user for Auth0 profile: ${auth0Profile.sub}`,
    );

    if (!auth0Profile.sub) {
      throw new BadRequestException('Auth0 profile sub (user ID) is required.');
    }

    // 1. Find Auth0 Provider ID
    const auth0Provider = getProviderDetails(this.AUTH0_PROVIDER_NAME);
    if (!auth0Provider) {
      // Aligning with Java UserResource behavior: expect provider to be pre-seeded.
      this.logger.error(
        `SSO Provider '${this.AUTH0_PROVIDER_NAME}' not found in the database. This is a configuration issue.`,
      );
      throw new InternalServerErrorException(
        `Critical setup error: SSO Provider '${this.AUTH0_PROVIDER_NAME}' is not configured.`,
      );
    }

    // 2. Try to find user by Auth0 sub
    const existingSsoLogin = await this.prismaClient.user_sso_login.findFirst({
      where: {
        sso_user_id: auth0Profile.sub,
        provider_id: new Decimal(auth0Provider.id),
      },
      include: { user: true },
    });

    if (existingSsoLogin && existingSsoLogin.user) {
      this.logger.log(
        `User found by Auth0 sub ${auth0Profile.sub}: ID ${existingSsoLogin.user.user_id.toNumber()}`,
      );
      // Optionally update user's basic info from Auth0 profile here if needed
      // e.g., first_name, last_name, picture_url (if field exists)
      await this.updateLastLoginDate(Number(existingSsoLogin.user.user_id));
      return existingSsoLogin.user;
    }

    // 3. If not found by sub, try to find by email (if provided and verified)
    let userByEmail: UserModel | null = null;
    if (auth0Profile.email && auth0Profile.email_verified) {
      const emailRecord = await this.prismaClient.email.findFirst({
        where: { address: { equals: auth0Profile.email, mode: 'insensitive' } },
        include: {
          user_email_xref: {
            where: { is_primary: true },
            include: { user: true },
          },
        },
      });
      if (
        emailRecord &&
        emailRecord.user_email_xref &&
        emailRecord.user_email_xref.length > 0 &&
        emailRecord.user_email_xref[0].user
      ) {
        userByEmail = emailRecord.user_email_xref[0].user;
        this.logger.log(
          `User found by email ${auth0Profile.email}: ID ${userByEmail.user_id.toNumber()}. Linking Auth0 sub.`,
        );
        // Link Auth0 sub to this existing user
        await this.prismaClient.user_sso_login.create({
          data: {
            user_id: userByEmail.user_id,
            sso_user_id: auth0Profile.sub,
            provider_id: new Decimal(auth0Provider.id),
          },
        });
        await this.updateLastLoginDate(Number(userByEmail.user_id));
        return userByEmail;
      }
    }

    // 4. If still not found, create a new user
    this.logger.log(
      `No existing user found. Creating new user for Auth0 sub: ${auth0Profile.sub}`,
    );
    const handle =
      auth0Profile.nickname ||
      auth0Profile.given_name ||
      `user${uuidv4().substring(0, 8)}`;
    const handleLower = handle.toLowerCase();

    // Ensure handle is unique
    const existingUserByHandle = await this.prismaClient.user.findFirst({
      where: { handle_lower: handleLower },
    });
    if (existingUserByHandle) {
      // Handle conflict, e.g., by appending a suffix or throwing an error. For now, simple error.
      // This should be rare if nickname/given_name is somewhat unique or uuid is used.
      this.logger.error(
        `Handle conflict during Auth0 user creation: ${handle}`,
      );
      throw new ConflictException(
        `Generated handle ${handle} already exists. Please try again or contact support.`,
      );
    }

    const transactionResult = await this.prismaClient.$transaction(
      async (prisma) => {
        const newUser = await prisma.user.create({
          data: {
            handle: handle,
            handle_lower: handleLower,
            first_name: auth0Profile.given_name,
            last_name: auth0Profile.family_name,
            status: auth0Profile.email_verified ? 'A' : 'U', // Active if email verified, Unverified otherwise
            activation_code: auth0Profile.email_verified ? null : uuidv4(), // Store activation_code directly
            create_date: new Date(),
            modify_date: new Date(),
          },
        });

        // Link Auth0 sub
        await prisma.user_sso_login.create({
          data: {
            user_id: newUser.user_id,
            sso_user_id: auth0Profile.sub,
            provider_id: new Decimal(auth0Provider.id),
          },
        });

        this.logger.log(
          `New user created with ID ${newUser.user_id.toNumber()} and handle ${newUser.handle}`,
        );

        // Publish user.created event
        try {
          // Ensure event payload matches what consumers expect
          await this.eventService.postEnvelopedNotification('user.created', {
            userId: newUser.user_id,
            handle: newUser.handle,
            email: auth0Profile.email,
          });
        } catch (eventError) {
          this.logger.error(
            `Failed to publish user.created event for ${newUser.user_id.toNumber()}: ${eventError.message}`,
            eventError.stack,
          );
        }

        return newUser;
      },
    );

    await this.updateLastLoginDate(Number(transactionResult.user_id));
    return transactionResult;
  }

  async updateLastLoginDate(userId: number): Promise<void> {
    this.logger.debug(`Updating last login date for user ID: ${userId}`);
    try {
      await this.prismaClient.user.update({
        where: { user_id: userId },
        data: { last_login: new Date() },
      });
    } catch (error) {
      // Log error but don't necessarily throw, as this is often a non-critical update
      this.logger.error(
        `Failed to update last login date for user ${userId}: ${error.message}`,
        error.stack,
      );
    }
  }

  async generateSSOToken(userId: number): Promise<string> {
    this.logger.debug(
      `Attempting to generate SSO token for user ID: ${userId}`,
    );

    if (userId === null || userId === undefined) {
      this.logger.error(
        'generateSSOToken called with null or undefined userId.',
      );
      throw new BadRequestException('userId must be specified.'); // Matches Java message
    }

    const user = await this.findUserById(userId);
    if (!user) {
      // Match Java's approach - same exception type for both cases
      throw new BadRequestException("userId doesn't exist."); // Exact Java message
    }
    const securityUserRecord = await this.prismaClient.security_user.findUnique(
      {
        where: { user_id: user.handle },
        select: { password: true },
      },
    );

    const encodedPassword = securityUserRecord.password;
    const status = user.status;

    // Delegate to another method like Java does
    return this.generateSSOTokenWithCredentials(
      userId,
      encodedPassword,
      status,
    );
  }

  /**
   * Generate an SSO token compatible with the v3 Java implementation.
   */
  private generateSSOTokenWithCredentials(
    userId: number,
    password: string,
    status: string,
  ): string {
    const salt = this.getSSOTokenSalt();
    console.log('SALT:', salt);
    if (!salt) {
      throw new Error('Failed to generate SSO token. Invalid configuration.');
    }

    console.log(
      `SALT: ${salt} userId: ${userId} encrypted password: ${password} status: ${status}`,
    );
    // Java concatenates strings then gets UTF-8 bytes
    const plain = Buffer.from(
      String(salt) + String(userId) + password + status,
      'utf8',
    );

    // SHA-256 digest as raw bytes
    const raw = crypto.createHash('sha256').update(plain).digest(); // Buffer

    // Replicate Java's hex conversion: no zero-padding per byte
    let hash = '';
    for (const byte of raw.values()) {
      hash += (byte & 0xff).toString(16); // no padStart(2, "0")
    }

    return `${userId}|${hash}`;
  }

  private getSSOTokenSalt(): string | null {
    // In NestJS, configuration is typically handled via ConfigService
    // and environment variables.
    const salt = this.configService.get<string>('SSO_TOKEN_SALT');
    if (!salt) {
      this.logger.error(
        'SSO_TOKEN_SALT is not defined in environment configuration.',
      );
      return null;
    }
    return salt;
  }

  async placeholderFindUserByAuth0Sub(
    auth0Sub: string,
  ): Promise<UserModel | null> {
    this.logger.warn(
      `Using placeholderFindUserByAuth0Sub for sub: ${auth0Sub}. Replace with findOrCreateUserFromAuth0Profile.`,
    );
    // Basic lookup for now, replace with full logic
    const auth0ProviderId = 1; // Assuming '1'
    const ssoLogin = await this.prismaClient.user_sso_login.findFirst({
      where: {
        provider_id: auth0ProviderId,
        sso_user_id: auth0Sub,
      },
      include: { user: true },
    });
    return ssoLogin?.user ?? null;
  }

  /**
   * Checks if an email address is available or if it's already in use by ANOTHER user.
   * Throws ConflictException if the email is used by a different user.
   * Allows the email if it's already associated with the CURRENT user (e.g., non-primary email being made primary).
   */
  async checkEmailAvailabilityForUser(
    emailAddress: string,
    currentUserId: number,
  ): Promise<void> {
    this.logger.debug(
      `Checking email availability for ${emailAddress}, excluding user ID ${currentUserId}`,
    );
    if (!emailAddress) {
      throw new BadRequestException('Email address cannot be empty.');
    }

    const conflictingEmail = await this.prismaClient.email.findFirst({
      where: {
        address: { equals: emailAddress, mode: 'insensitive' },
        primary_ind: Constants.primaryEmailFlag, // It's a primary email
        user_id: {
          not: currentUserId, // And it does not belong to the current user
          // Also ensure user_id is not null, though primary_ind=1 implies a user_id, Prisma requires explicit not: null if not part of composite
        },
      },
      select: {
        // We only need to know if it exists and who it belongs to for logging
        user_id: true,
      },
    });

    if (conflictingEmail) {
      this.logger.warn(
        `Email ${emailAddress} is already in use as primary by another user (user_id: ${conflictingEmail.user_id.toNumber()}).`,
      );
      throw new ConflictException(
        `Email address ${emailAddress} is already in use by another account.`,
      );
    }

    this.logger.log(
      `Email ${emailAddress} is available for user ID ${currentUserId} or is not a primary email for another user.`,
    );
  }

  async updatePrimaryRole(
    userId: number,
    newPrimaryRole: string,
    operatorId: number,
  ): Promise<UserModel> {
    this.logger.log(
      `Attempting to update primary role for user ID: ${userId} to ${newPrimaryRole}`,
    );

    const user = await this.prismaClient.user.findUnique({
      where: { user_id: userId },
    });
    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found.`);
    }

    const validPrimaryRoles = ['Topcoder Talent', 'Topcoder Customer'];
    if (!validPrimaryRoles.includes(newPrimaryRole)) {
      throw new BadRequestException(
        `Invalid primary role specified: ${newPrimaryRole}. Must be one of: ${validPrimaryRoles.join(', ')}`,
      );
    }

    this.logger.debug(`Deassigning old primary roles for user ${userId}`);
    for (const roleNameToDeassign of validPrimaryRoles) {
      if (roleNameToDeassign !== newPrimaryRole) {
        // Avoid deassigning then reassigning the same role if it was already primary
        try {
          await this.roleService.deassignRoleByName(roleNameToDeassign, userId);
        } catch (error) {
          // Log if a role to deassign wasn't found or assigned, but don't fail the operation
          this.logger.warn(
            `Could not de-assign role '${roleNameToDeassign}' for user ${userId} (may not have been assigned): ${error.message}`,
          );
        }
      }
    }

    this.logger.debug(
      `Assigning new primary role '${newPrimaryRole}' to user ${userId}`,
    );
    await this.roleService.assignRoleByName(newPrimaryRole, userId, operatorId);

    this.logger.log(
      `Successfully updated primary role for user ${userId} to ${newPrimaryRole}`,
    );
    return user; // Return the original user model, as roles are managed in a separate domain
  }

  // User Preferences and self-service profile updates are future considerations.
  // async getPreferences(userId: number) { ... }
  // async updatePreferences(userId: number, preferencesDto, authUser: AuthenticatedUser) { ... }

  // async getDetailedProfile(userId: number) { ... } // for address, etc.
  // async updateDetailedProfile(userId: number, profileDetailsDto, authUser: AuthenticatedUser) { ... }

  /**
   * Assign default user role to user.
   * @param userId User ID
   */
  async assignDefaultUserRole(userId: number) {
    // Changed role name to "Topcoder User" to match Java UserResource.assignDefaultUserRole logic
    await this.roleService.assignRoleByName('Topcoder User', userId, userId);
  }

  /**
   * Notify welcome.
   * @param userId User ID
   * @param emailAddress Email address to send welcome email
   */
  async notifyWelcome(userId: number, emailAddress: string) {
    try {
      const user = await this.findUserById(userId);
      // Use postEnvelopedNotification for standard events
      // whole user details sent not just userId
      await this.eventService.postEnvelopedNotification('welcome', {
        id: userId,
      });
      this.logger.log(`Published 'event.user.activated' event for ${userId}`);

      // Send Welcome Email directly, matching legacy Java behavior
      if (emailAddress && user?.handle) {
        const domain =
          this.configService.get<string>('APP_DOMAIN') || 'topcoder-dev.com';
        const fromEmail = `Topcoder <noreply@${domain}>`;
        let welcomeTemplateId = this.configService.get<string>(
          'SENDGRID_WELCOME_EMAIL_TEMPLATE_ID',
        );
        if (
          CommonUtils.validateString(user.reg_source) &&
          user.reg_source.match(/^selfService$/)
        ) {
          welcomeTemplateId = this.configService.get<string>(
            'SENDGRID_SELFSERVICE_WELCOME_EMAIL_TEMPLATE_ID',
          );
        }
        if (!welcomeTemplateId) {
          this.logger.error(
            `SendGrid template ID not configured (SENDGRID_WELCOME_EMAIL_TEMPLATE_ID). Cannot send welcome email for user ${userId}.`,
          );
        } else {
          const welcomeEmailPayload = {
            data: {
              handle: user.handle,
              // Add other data fields specific to the welcome template if needed
            },
            from: { email: fromEmail },
            version: 'v6',
            sendgrid_template_id: welcomeTemplateId,
            recipients: [emailAddress],
          };
          await this.eventService.postDirectBusMessage(
            'external.action.email',
            welcomeEmailPayload,
          );
          this.logger.log(
            `Published 'external.action.email' (welcome) for user ${userId} to ${emailAddress}. Payload: ${JSON.stringify(welcomeEmailPayload, null, 2)}`,
          );
        }
      } else {
        this.logger.warn(
          `Could not send welcome email for user ${userId} due to missing primary email address or handle.`,
        );
      }
    } catch (eventError) {
      this.logger.error(
        `Failed to publish events for user activation ${userId}: ${eventError.message}`,
        eventError.stack,
      );
    }
  }

  /**
   * Resend email to user.
   * @param email Email address to identify user
   * @param handle Handle of user
   * @returns user details if successful
   * @throws UnauthorizedException if user not found
   * @throws BadRequestException if user already activated or no primary email
   */
  async resendEmail(email?: string, handle?: string): Promise<UserModel> {
    // find user
    let user: UserModel | null = null;
    // first by handle
    if (CommonUtils.validateString(handle)) {
      user = await this.findUserByEmailOrHandle(handle);
    } else if (CommonUtils.validateString(email)) {
      // search by email, !!case sensitive!!
      user = await this.prismaClient.user.findFirst({
        where: {
          emails: {
            some: { address: { equals: email } },
          },
        },
      });
    }
    if (!user) {
      throw new UnauthorizedException('Credentials are incorrect'); // match java code
    }
    if (user.status != MemberStatus.UNVERIFIED) {
      throw new BadRequestException('User has been activated');
    }

    // make sure we get primary email
    const emailRecord = await this.prismaClient.email.findFirst({
      where: {
        user_id: user.user_id,
        primary_ind: Constants.primaryEmailFlag,
        email_type_id: Constants.standardEmailType,
      },
    });
    // check if there is primary email
    if (!emailRecord) {
      throw new BadRequestException('No primary email for user');
    }
    // send email event
    await this.sendActivationEmailEvent(
      user.handle,
      user.activation_code,
      emailRecord.address, // send to primary email
      user.reg_source,
    );
    // return user as per java code
    return user;
  }

  /**
   * Send activation email event.
   * @param handle User handle
   * @param activationCode The activation code
   * @param email Email address to send to
   * @param regSource Registration source if available
   */
  private async sendActivationEmailEvent(
    handle: string,
    activationCode: string,
    email: string,
    regSource?: string,
  ) {
    const domain =
      this.configService.get<string>('APP_DOMAIN') || 'topcoder-dev.com';
    const fromEmail = `Topcoder <noreply@${domain}>`;
    const sendGridTemplateId = this.configService.get<string>(
      'SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID',
    );
    const sendGridSelfServiceTemplateId = this.configService.get<string>(
      'SENDGRID_SELFSERVICE_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID',
    );

    const data: any = {
      handle: handle,
      code: activationCode,
      domain: domain,
      subDomain: 'www',
      path: '/home',
      redirectUrl: `https%3A%2F%2Fwww.${domain}%2Fhome`,
      version: 'v6',
      sendgrid_template_id: sendGridTemplateId,
    };

    if (CommonUtils.validateString(regSource)) {
      if (regSource.match(/^tcBusiness$/)) {
        data.subDomain = 'connect';
        data.path = '/';
        data.redirectUrl = `https%3A%2F%2Fconnect.${domain}%2F`;
      }
      if (regSource.match(/^selfService$/)) {
        data.subDomain = 'platform';
        data.path = '/self-service';
        data.redirectUrl = `https%3A%2F%2Fplatform.${domain}%2Fself-service`;
        data.sendgrid_template_id = sendGridSelfServiceTemplateId;
      }
    }

    try {
      await this.eventService.postDirectBusMessage('external.action.email', {
        data: data,
        from: { email: fromEmail },
        recipients: [email], // The original email used for registration
      });
      this.logger.log(
        `Published 'external.action.email' event for user ${handle}`,
      );
    } catch (eventError) {
      this.logger.error(
        `Failed to publish resend email event for user ${handle}: ${eventError.message}`,
        eventError.stack,
      );
    }
  }

  /**
   * Resend activation email event.
   * @param userOtp User OTP details
   * @param primaryEmail Primary email address
   */
  async resendActivationEmailEvent(userOtp: UserOtpDto, primaryEmail: string) {
    try {
      // For activation email (resend), use postDirectBusMessage to match legacy Java structure
      const domain =
        this.configService.get<string>('APP_DOMAIN') || 'topcoder-dev.com';
      const fromEmail = `Topcoder <noreply@${domain}>`;
      // Use the specific template ID for resending activation emails
      const sendgridTemplateId = this.configService.get<string>(
        'SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID',
      );

      if (!sendgridTemplateId) {
        this.logger.error(
          `SendGrid template ID not configured (SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID). Cannot send activation email resend.`,
        );
      } else {
        const activationEmailPayload = {
          data: { handle: userOtp.handle, code: userOtp.otp },
          from: { email: fromEmail },
          version: 'v6',
          sendgrid_template_id: sendgridTemplateId,
          recipients: [primaryEmail], // The user's primary email
        };
        await this.eventService.postDirectBusMessage(
          'external.action.email',
          activationEmailPayload,
        );
        this.logger.log(
          `Published 'external.action.email' (activation resend) for ${userOtp.userId} with new OTP. Payload: ${JSON.stringify(activationEmailPayload, null, 2)}`,
        );
      }
    } catch (eventError) {
      this.logger.error(
        `Failed to publish resend activation event for user ${userOtp.userId}: ${eventError.message}`,
        eventError.stack,
      );
    }
  }

  /**
   * Add user to default groups.
   * @param prisma Prisma client
   * @param userId The user ID to add.
   */
  private async addUserToDefaultGroups(prisma: any, userId: number) {
    this.logger.log(`Adding user: ${userId} to default groups`);
    const defaultGroups: number[] = [
      DefaultGroups.MANAGER,
      DefaultGroups.CODERS,
      DefaultGroups.LEVEL_TWO_ADMINS,
      DefaultGroups.ANONYMOUS,
    ];
    for (const groupId of defaultGroups) {
      await this.addUserToGroup(prisma, userId, groupId);
    }
  }

  /**
   * Add user to group.
   * @param prisma Prisma client
   * @param userId The user ID
   * @param groupId The group ID
   */
  private async addUserToGroup(prisma: any, userId: number, groupId: number) {
    try {
      const result: { nextval: bigint }[] =
        await prisma.$queryRaw`SELECT nextval('sequence_user_group_seq'::regclass)`;
      if (!result || result.length === 0 || !result[0].nextval) {
        throw new Error('Failed to retrieve next user group ID from sequence.');
      }
      const nextUserGroupId = Number(result[0].nextval);
      this.logger.log(`Next userGroupXref ID: ${nextUserGroupId}`);
      await prisma.user_group_xref.create({
        data: {
          user_group_id: nextUserGroupId,
          group_id: groupId,
          login_id: userId,
          create_user_id: Constants.DEFAULT_CREATE_USER_ID,
          security_status_id: Constants.DEFAULT_SECURITY_STATUS_ID,
        },
      });
      this.logger.log(`User: ${userId} assigned to groupId: ${groupId}`);
    } catch (error) {
      this.logger.error(
        `Unable to assign userId: ${userId} to groupId: ${groupId}`,
        error,
      );
      // should we fail when an error occurs?
    }
  }
}
