import {
  Injectable,
  Inject,
  Logger,
  InternalServerErrorException,
  NotFoundException,
  ConflictException,
  forwardRef,
  BadRequestException,
} from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  PrismaClient as PrismaClientCommonOltp,
  user as UserModel,
  Prisma,
  user_sso_login as UserSsoLoginModel,
  sso_login_provider as SsoLoginProviderModel,
} from '@prisma/client-common-oltp';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import {
  CreateUserBodyDto,
  UpdateUserBodyDto,
  UserSearchQueryDto,
  AchievementDto,
} from '../../dto/user/user.dto';
import { ValidationService } from './validation.service';
import { v4 as uuidv4 } from 'uuid';
import { RoleService } from '../role/role.service';
import { EventService } from '../../shared/event/event.service';
import { Cache } from 'cache-manager';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import * as crypto from 'crypto';
import * as CryptoJS from 'crypto-js';
import { Decimal } from '@prisma/client/runtime/library';
import { Constants } from 'src/core/constant/constants';
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

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);
  private readonly AUTH0_PROVIDER_NAME = 'auth0'; // Define constant for Auth0 provider name
  private legacyBlowfishKey: string; // Changed: Store the raw Base64 key string directly

  constructor(
    @Inject(PRISMA_CLIENT_COMMON_OLTP)
    private readonly prismaOltp: PrismaClientCommonOltp,
    @Inject(forwardRef(() => ValidationService))
    private readonly validationService: ValidationService,
    @Inject(forwardRef(() => RoleService))
    private readonly roleService: RoleService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    private readonly eventService: EventService,
    private readonly configService: ConfigService,
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
  }

  // --- Core User Methods ---

  async findUsers(query: UserSearchQueryDto): Promise<UserModel[]> {
    this.logger.debug(`Finding users with query: ${JSON.stringify(query)}`);
    const whereClause: Prisma.userWhereInput = {};
    if (query.handle) {
      whereClause.handle_lower = query.handle.toLowerCase();
    }
    if (query.email) {
      whereClause.user_email_xref = {
        some: {
          email: {
            address: query.email,
          },
        },
      };
    }

    try {
      return this.prismaOltp.user.findMany({
        where: whereClause,
        skip: query.offset ?? 0,
        take: query.limit ?? Constants.defaultPageSize,
      });
    } catch (error) {
      this.logger.error(`Error finding users: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to search users.');
    }
  }

  async findUserById(userId: number): Promise<UserModel | null> {
    this.logger.log(`Finding user by ID: ${userId} for detailed view.`);
    // Step 1: Fetch the core user data
    const user = await this.prismaOltp.user.findUnique({
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
    const primaryEmail = await this.prismaOltp.email.findFirst({
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
      const emailRecord = await this.prismaOltp.email.findFirst({
        where: {
          address: emailOrHandle.toLowerCase(),
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
      user = await this.prismaOltp.user.findUnique({
        where: { user_id: userId },
        include: {
          user_sso_login: { include: { sso_login_provider: true } },
        },
      });
    } else if (!isEmail) {
      // Only search by handle if it wasn't an email or email lookup failed
      user = await this.prismaOltp.user.findFirst({
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
    const primaryEmailRecord = await this.prismaOltp.email.findFirst({
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
      // Changed: Parse the Base64 key directly
      const key = CryptoJS.enc.Base64.parse(this.legacyBlowfishKey);
      const encrypted = CryptoJS.Blowfish.encrypt(password, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
      });
      return encrypted.toString(); // Base64 output
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
    const userParams = createUserDto.param;
    const { handle, email, credential, firstName, lastName } = userParams;

    this.logger.log(
      `Attempting to register user with handle: ${handle} and email: ${email}`,
    );

    if (!handle) {
      throw new BadRequestException('Handle is required.');
    }
    if (!email) {
      throw new BadRequestException('Email is required.');
    }
    if (!credential?.password) {
      throw new BadRequestException('Password is required.');
    }
    if (credential.password.length < 8) {
      throw new BadRequestException(
        'Password must be at least 8 characters long.',
      );
    }

    try {
      await this.validationService.validateHandle(handle);
    } catch (error) {
      this.logger.warn(
        `Handle validation failed for '${handle}': ${error.message}`,
      );
      throw error;
    }
    try {
      await this.validationService.validateEmail(email);
    } catch (error) {
      this.logger.warn(
        `Email validation failed for '${email}': ${error.message}`,
      );
      throw error;
    }

    if (userParams.country != null) {
      try {
        await this.validationService.validateCountryAndMutate(
          userParams.country,
        );
      } catch (error) {
        this.logger.warn(
          `Country validation failed for '${JSON.stringify(userParams.country)}': ${error.message}`,
        );
        throw error;
      }
    }

    if (userParams.profile != null) {
      try {
        await this.validationService.validateProfile(userParams.profile);
      } catch (error) {
        this.logger.warn(
          `Country validation failed for '${JSON.stringify(userParams.country)}': ${error.message}`,
        );
        throw error;
      }
    }

    if (userParams.regSource == 'ReferralProgram') {
      try {
        await this.validationService.validateReferral(userParams.regSource);
      } catch (error) {
        this.logger.warn(
          `Country validation failed for '${JSON.stringify(userParams.country)}': ${error.message}`,
        );
        throw error;
      }
    }

    // Generate OTP first, as it will be stored as the activation_code
    const otpForActivation = this.generateNumericOtp(ACTIVATION_OTP_LENGTH);

    // Step 1: Get the next user ID from the sequence (mimicking Java DAO)
    let nextUserId: number;
    try {
      // Prisma doesn't have a built-in nextval function, use raw query
      const result: { nextval: bigint }[] = await this.prismaOltp
        .$queryRaw`SELECT nextval('common_oltp.sequence_user_seq'::regclass)`;
      if (!result || result.length === 0 || !result[0].nextval) {
        throw new Error('Failed to retrieve next user ID from sequence.');
      }
      nextUserId = Number(result[0].nextval);
      this.logger.debug(
        `[registerUser] Fetched next user ID from sequence: ${nextUserId}`,
      );
    } catch (seqError) {
      this.logger.error(
        `[registerUser] Error fetching next user ID: ${seqError.message}`,
        seqError.stack,
      );
      throw new InternalServerErrorException('Failed to generate user ID.');
    }

    // Step 2: Perform inserts within a transaction using the fetched ID
    let newUser: UserModel;
    try {
      newUser = await this.prismaOltp.$transaction(async (prisma) => {
        const userData = {
          user_id: nextUserId,
          handle: handle,
          handle_lower: handle.toLowerCase(),
          status: 'U',
          first_name: firstName,
          last_name: lastName,
          create_date: new Date(),
          modify_date: new Date(),
          activation_code: otpForActivation,
        };

        this.logger.debug(
          `[registerUser Transaction] Data for prisma.user.create: ${JSON.stringify(userData)}`,
        );

        const createdUser = await prisma.user.create({
          data: userData,
        });
        this.logger.log(
          `User record created for ${handle} (ID: ${createdUser.user_id.toNumber()})`,
        );

        // Use the existing service method for consistent password encoding
        const actualEncodedPassword = this.encodePasswordLegacy(
          credential.password,
        );

        this.logger.debug(
          `[RegisterUser Tx] Encrypted password for handle ${handle} (using encodePasswordLegacy): ${actualEncodedPassword}`,
        );

        await prisma.security_user.create({
          data: {
            login_id: createdUser.user_id, // Use the Decimal user_id directly
            user_id: handle,
            password: actualEncodedPassword, // Use password from service method
          },
        });
        this.logger.log(
          `Security user record created for user ${handle} (ID: ${nextUserId})`,
        );

        let emailRecord = await prisma.email.findFirst({
          where: { address: email.toLowerCase() },
        });
        if (!emailRecord) {
          // ADDED: Fetch next email_id explicitly
          let nextEmailId: number;
          try {
            const result: { nextval: bigint }[] =
              await prisma.$queryRaw`SELECT nextval('common_oltp.sequence_email_seq'::regclass)`;
            if (!result || result.length === 0 || !result[0].nextval) {
              throw new Error(
                'Failed to retrieve next email ID from sequence.',
              );
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
            throw new InternalServerErrorException(
              'Failed to generate email ID.',
            );
          }

          emailRecord = await prisma.email.create({
            data: {
              email_id: nextEmailId, // Use fetched ID
              user_id: nextUserId, // ADDED: Link directly to the user ID
              address: email, // Use provided email
              primary_ind: Constants.primaryEmailFlag, // Defaulted based on Java code logic
              status_id: Constants.unverifiedEmailStatus, // Defaulted based on Java code logic (Inactive/Unverified initially)
              email_type_id: Constants.standardEmailType, // ADDED: Assume type 1 (Primary) as per Java DAO's email queries
              create_date: new Date(),
              modify_date: new Date(),
            },
          });
          this.logger.debug(
            `Email record created for ${email} (ID: ${emailRecord.email_id.toNumber()})`,
          );
        } else {
          this.logger.debug(
            `Existing email record found for ${email} (ID: ${emailRecord.email_id.toNumber()})`,
          );
        }

        return createdUser;
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === Constants.prismaUniqueConflictcode) {
          this.logger.warn(
            `Registration failed due to unique constraint: ${error.message}. Fields: ${JSON.stringify(error.meta?.target)}`,
          );
          if ((error.meta?.target as string[])?.includes('handle_lower')) {
            throw new ConflictException(`Handle '${handle}' already exists.`);
          } else if ((error.meta?.target as string[])?.includes('address')) {
            throw new ConflictException(`Email '${email}' already exists.`);
          }
          throw new ConflictException(
            'User with this handle or email already exists.',
          );
        }
      }
      this.logger.error(
        `Error during user registration transaction for ${handle}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'User registration failed due to a database error.',
      );
    }

    const otpCacheKey = `${ACTIVATION_OTP_CACHE_PREFIX_KEY}:${newUser.user_id.toNumber()}`;
    const otpExpiry =
      this.configService.get<number>(
        'ACTIVATION_OTP_EXPIRY_SECONDS',
        ACTIVATION_OTP_EXPIRY_SECONDS,
      ) * 1000;
    try {
      await this.cacheManager.set(otpCacheKey, otpForActivation, otpExpiry);
      this.logger.log(
        `Activation OTP ${otpForActivation} generated and cached for user ${newUser.user_id.toNumber()} (key: ${otpCacheKey})`,
      );
    } catch (cacheError) {
      this.logger.error(
        `Failed to cache OTP for user ${newUser.user_id.toNumber()}: ${cacheError.message}`,
        cacheError.stack,
      );
    }

    try {
      const operatorIdForRoleAssignment = Number(newUser.user_id);
      // Changed role name to "Topcoder User" to match Java UserResource.assignDefaultUserRole logic
      await this.roleService.assignRoleByName(
        'Topcoder User',
        Number(newUser.user_id),
        operatorIdForRoleAssignment,
      );
      this.logger.log(
        `Default role(s) assigned to user ${newUser.user_id.toNumber()}`,
      );
    } catch (roleError) {
      this.logger.error(
        `Failed to assign default roles to user ${newUser.user_id.toNumber()}: ${roleError.message}`,
        roleError.stack,
      );
    }

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
          version: 'v3',
          sendgrid_template_id: sendgridTemplateId,
          recipients: [email], // The original email used for registration
        };
        await this.eventService.postDirectBusMessage(
          'external.action.email',
          activationEmailPayload,
        );
        this.logger.log(
          `Published 'external.action.email' (activation) for ${newUser.user_id.toNumber()} to ${email}. Payload: ${JSON.stringify(activationEmailPayload, null, 2)}`,
        );
      }
    } catch (eventError) {
      this.logger.error(
        `Failed to publish events for user ${newUser.user_id.toNumber()}: ${eventError.message}`,
        eventError.stack,
      );
    }

    this.logger.log(
      `Successfully registered user ${newUser.handle} (ID: ${newUser.user_id.toNumber()}). Status: U. Activation OTP sent for eventing.`,
    );
    return newUser;
  }

  async updateBasicInfo(
    userIdString: string,
    updateUserDto: UpdateUserBodyDto,
  ): Promise<UserModel> {
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid user ID format.');
    }
    this.logger.log(`Updating basic info for user ID: ${userId}`);
    const userParams = updateUserDto.param; // Access nested param object
    // Only update fields present in the DTO
    const dataToUpdate: Prisma.userUpdateInput = {};
    if (userParams.firstName) dataToUpdate.first_name = userParams.firstName;
    if (userParams.lastName) dataToUpdate.last_name = userParams.lastName;
    // Add other updatable basic fields (country, timezone etc.)

    if (Object.keys(dataToUpdate).length === 0) {
      this.logger.warn(
        `Update basic info called for user ${userId} with no data.`,
      );
      // Or throw BadRequestException
      const currentUser = await this.findUserById(userId);
      if (!currentUser)
        throw new NotFoundException(`User with ID ${userId} not found.`);
      return currentUser; // Return current user if no changes
    }

    try {
      const updatedUser = await this.prismaOltp.user.update({
        where: { user_id: userId },
        data: dataToUpdate,
      });
      this.logger.log(`Successfully updated basic info for user ${userId}`);
      return updatedUser;
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === Constants.prismaNotFoundCode
      ) {
        throw new NotFoundException(
          `User with ID ${userId} not found for update.`,
        );
      }
      this.logger.error(
        `Error updating basic info for user ${userId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'Failed to update user information.',
      );
    }
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
    if (!newHandle) {
      throw new BadRequestException('New handle cannot be empty.');
    }

    // Validate format and uniqueness (ValidationService throws on failure)
    await this.validationService.validateHandle(newHandle);

    // Fetch the user to ensure they exist and get the old handle
    const existingUser = await this.prismaOltp.user.findUnique({
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
      const updatedUser = await this.prismaOltp.$transaction(async (prisma) => {
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
        // The 'user_id' column in 'security_user' stores the handle.
        // We need to find the record by the old handle and update it to the new handle.
        // The 'login_id' in 'security_user' stores the numeric user_id from the 'user' table.

        // First, check if a security_user record exists with the old handle
        const securityUserRecord = await prisma.security_user.findUnique({
          where: { user_id: oldHandle }, // user_id in security_user is the handle
        });

        if (securityUserRecord) {
          // If it exists, update its user_id (which is the handle) to the new handle
          // This assumes that security_user.user_id (the handle) must be unique.
          // If another user already has newHandle in security_user.user_id, this would fail.
          // This should ideally be caught by the initial validateHandle if security_user.user_id mirrors user.handle.
          await prisma.security_user.update({
            where: { user_id: oldHandle },
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
      });

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
    if (!newEmail) {
      throw new BadRequestException('New email cannot be empty.');
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
      throw new BadRequestException('Invalid email format.');
    }

    await this.checkEmailAvailabilityForUser(newEmail, userId);
    const updatedUserInTx = await this.prismaOltp.$transaction(async (tx) => {
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
        },
      });

      if (!currentPrimaryEmailRecord) {
        throw new NotFoundException(
          `No primary email found for user ${userId}.`,
        );
      }

      const oldEmail = currentPrimaryEmailRecord.address;

      // If the new email is the same as current, return user as-is
      if (oldEmail === newEmail.toLowerCase()) {
        this.logger.log(
          `Email ${newEmail} is already the primary email for user ${userId}. No changes needed.`,
        );
        return userInDB;
      }

      // Check if new email is already taken by another user as primary
      const existingEmailRecord = await tx.email.findFirst({
        where: {
          address: newEmail.toLowerCase(),
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
          status_id: new Decimal(2), // Set to unverified status
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

    // Generate OTP and resend token for email verification using the updated email record
    const updatedEmailRecord = await this.prismaOltp.email.findFirst({
      where: {
        user_id: userId,
        primary_ind: Constants.primaryEmailFlag,
      },
    });

    if (updatedEmailRecord) {
      const otpForNewEmail = this.generateNumericOtp(ACTIVATION_OTP_LENGTH);
      const otpCacheKey = `${ACTIVATION_OTP_CACHE_PREFIX_KEY}:UPDATE_EMAIL:${userId}:${updatedEmailRecord.email_id.toNumber()}`;
      const otpExpiry =
        this.configService.get<number>(
          'ACTIVATION_OTP_EXPIRY_SECONDS',
          ACTIVATION_OTP_EXPIRY_SECONDS,
        ) * 1000;

      await this.cacheManager.set(otpCacheKey, otpForNewEmail, otpExpiry);

      const resendPayload = {
        sub: userId.toString(),
        aud: 'emailupdate_activation',
        emailId: updatedEmailRecord.email_id.toString(),
      };
      const resendTokenExpiry = this.configService.get<string>(
        'ACTIVATION_RESEND_JWT_EXPIRY',
        '1h',
      );
      const resendTokenForNewEmail = jwt.sign(
        resendPayload,
        this.configService.get<string>('JWT_SECRET'),
        { expiresIn: resendTokenExpiry },
      );

      // Send verification email
      try {
        await this.eventService.postEnvelopedNotification(
          'email.verification_required',
          {
            userId: userIdString,
            email: newEmail,
            otp: otpForNewEmail,
            resendToken: resendTokenForNewEmail,
            reason: 'PRIMARY_EMAIL_UPDATE',
          },
        );
        this.logger.log(
          `Published 'email.verification_required' event for updated primary email ${newEmail}, user ${userIdString}`,
        );
      } catch (eventError) {
        this.logger.error(
          `Failed to publish email.verification_required event for user ${userIdString}: ${eventError.message}`,
          eventError.stack,
        );
      }
    }

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
  ): Promise<UserModel> {
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid User ID format.');
    }
    this.logger.log(
      `Attempting to update status for user ID: ${userId} to ${newStatus} by admin: ${authUser.userId}`,
    );

    const validStatuses = ['A', 'I', 'U', 'P']; // Active, Inactive, Unverified, Pending (example)
    if (!validStatuses.includes(newStatus.toUpperCase())) {
      throw new BadRequestException(
        `Invalid status code: ${newStatus}. Must be one of: ${validStatuses.join(', ')}`,
      );
    }
    const normalizedNewStatus = newStatus.toUpperCase();

    const user = await this.prismaOltp.user.findUnique({
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
      const updatedUser = await this.prismaOltp.user.update({
        where: { user_id: userId },
        data: {
          status: normalizedNewStatus,
          modify_date: new Date(),
        },
      });
      this.logger.log(
        `Successfully updated status for user ${userId} from ${oldStatus} to ${normalizedNewStatus}`,
      );

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
      if (oldStatus === 'U' && normalizedNewStatus === 'A') {
        this.logger.log(
          `User ${userId} activated (U -> A). Assigning default role and triggering welcome email.`,
        );
        try {
          await this.roleService.assignRoleByName(
            'Topcoder User',
            userId,
            Number(authUser.userId),
          ); // Operator is admin
          this.logger.log(
            `Assigned default role to newly activated user ${userId}.`,
          );
        } catch (roleError) {
          this.logger.error(
            `Failed to assign default role to newly activated user ${userId}: ${roleError.message}`,
            roleError.stack,
          );
        }

        const primaryEmailRecord = await this.prismaOltp.email.findFirst({
          where: {
            user_id: userId,
            primary_ind: Constants.primaryEmailFlag,
            status_id: Constants.verifiedEmailStatus,
          }, // Ensure it's verified
        });

        if (primaryEmailRecord?.address && updatedUser?.handle) {
          const domain =
            this.configService.get<string>('APP_DOMAIN') || 'topcoder-dev.com';
          const fromEmail = `Topcoder <noreply@${domain}>`;
          const welcomeTemplateId = this.configService.get<string>(
            'SENDGRID_WELCOME_EMAIL_TEMPLATE_ID',
          );

          if (!welcomeTemplateId) {
            this.logger.error(
              `SendGrid template ID not configured (SENDGRID_WELCOME_EMAIL_TEMPLATE_ID). Cannot send welcome email for user ${userId} in updateStatus.`,
            );
          } else {
            const welcomeEmailPayload = {
              data: { handle: updatedUser.handle }, // Use handle from updatedUser
              from: { email: fromEmail },
              version: 'v3',
              sendgrid_template_id: welcomeTemplateId,
              recipients: [primaryEmailRecord.address],
            };
            await this.eventService.postDirectBusMessage(
              'external.action.email',
              welcomeEmailPayload,
            );
            this.logger.log(
              `Published 'external.action.email' (welcome via updateStatus) for user ${userId}. Payload: ${JSON.stringify(welcomeEmailPayload, null, 2)}`,
            );
          }
        } else {
          this.logger.warn(
            `Could not send welcome email for newly activated user ${userId} (via updateStatus) due to missing primary email or handle.`,
          );
        }
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

  // --- User Achievements ---

  async getAchievements(userId: number): Promise<AchievementDto[]> {
    this.logger.debug(`Fetching achievements for user ID: ${userId}`);
    try {
      const achievements = await this.prismaOltp.user_achievement.findMany({
        where: { user_id: userId },
        include: {
          achievement_type_lu: true, // Include the description lookup table
        },
      });

      // Map to AchievementDto
      return achievements.map((ach) => ({
        achievement_type_id: Number(ach.achievement_type_id), // Convert Decimal to number
        achievement_desc: ach.achievement_type_lu.achievement_type_desc,
        date: ach.create_date, // Assuming create_date is the achievement date
      }));
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
    const auth0Provider = await this.prismaOltp.sso_login_provider.findFirst({
      where: { name: this.AUTH0_PROVIDER_NAME },
    });

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
    const existingSsoLogin = await this.prismaOltp.user_sso_login.findFirst({
      where: {
        sso_user_id: auth0Profile.sub,
        provider_id: auth0Provider.sso_login_provider_id,
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
      const emailRecord = await this.prismaOltp.email.findFirst({
        where: { address: auth0Profile.email },
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
        await this.prismaOltp.user_sso_login.create({
          data: {
            user_id: userByEmail.user_id,
            sso_user_id: auth0Profile.sub,
            provider_id: auth0Provider.sso_login_provider_id,
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
    const existingUserByHandle = await this.prismaOltp.user.findFirst({
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

    const transactionResult = await this.prismaOltp.$transaction(
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
            provider_id: auth0Provider.sso_login_provider_id,
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
      await this.prismaOltp.user.update({
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

    const encodedPassword = user.password;
    const status = user.status;

    // Delegate to another method like Java does
    return this.generateSSOTokenWithCredentials(
      userId,
      encodedPassword,
      status,
    );
  }

  private generateSSOTokenWithCredentials(
    userId: number,
    password: string,
    status: string,
  ): string {
    // Your existing token generation logic here
    const salt = this.getSSOTokenSalt();
    const plainText = `${salt}${userId}${password}${status}`;
    const hash = crypto
      .createHash('sha256')
      .update(plainText, 'utf-8')
      .digest('hex');
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
    const ssoLogin = await this.prismaOltp.user_sso_login.findFirst({
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

    const conflictingEmail = await this.prismaOltp.email.findFirst({
      where: {
        address: emailAddress.toLowerCase(),
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

    const user = await this.prismaOltp.user.findUnique({
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
}
