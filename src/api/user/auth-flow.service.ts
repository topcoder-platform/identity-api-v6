import { Injectable, Inject, Logger } from '@nestjs/common';
import { PrismaClient as PrismaClientCommonOltp } from '@prisma/client-common-oltp';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import { Cache } from 'cache-manager'; // Import Cache type
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { UserService } from './user.service';
import { EventService } from '../../shared/event/event.service';
import { RoleService } from '../role/role.service';
import { ActivateUserBodyDto, UserOtpDto } from '../../dto/user/user.dto';
import {
  BadRequestException,
  ForbiddenException,
  GoneException,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import {
  ACTIVATION_OTP_CACHE_PREFIX_KEY,
  ACTIVATION_OTP_EXPIRY_SECONDS,
  ACTIVATION_OTP_LENGTH,
} from './user.service';
import { Prisma } from '@prisma/client-common-oltp';
import { v4 as uuidv4 } from 'uuid';
import { Decimal } from '@prisma/client/runtime/library'; // Import Decimal
import * as CryptoJS from 'crypto-js'; // Import crypto-js for Blowfish

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OTP_ACTIVATION_JWT_AUDIENCE = 'emailactivation';
const ONE_TIME_TOKEN_JWT_AUDIENCE = 'onetime_email_update';
const ONE_TIME_TOKEN_CACHE_PREFIX_JTI = 'USED_JTI_OTT';
const PASSWORD_RESET_TOKEN_CACHE_PREFIX = 'PWD_RESET_TOKEN';
const PASSWORD_RESET_TOKEN_LENGTH = 6; // Or longer for more security, Java used 6 alphanumeric

@Injectable()
export class AuthFlowService {
  private readonly logger = new Logger(AuthFlowService.name);
  private readonly jwtSecret: string;
  private readonly resetTokenExpirySeconds: number;
  private readonly activationResendExpirySeconds: number;
  private readonly oneTimeTokenExpirySeconds: number;
  private readonly legacyBlowfishKey: string; // For legacy password decryption

  constructor(
    @Inject(PRISMA_CLIENT_COMMON_OLTP)
    private readonly prismaOltp: PrismaClientCommonOltp,
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly eventService: EventService,
    private readonly roleService: RoleService,
  ) {
    this.jwtSecret = this.configService.get<string>('JWT_SECRET')!;
    this.resetTokenExpirySeconds = 30 * 60; // Example: 30 mins
    this.activationResendExpirySeconds = 1 * 60 * 60; // Example: 1 hour
    this.oneTimeTokenExpirySeconds = 10 * 60; // Example: 10 mins
    this.legacyBlowfishKey = this.configService.get<string>(
      'LEGACY_BLOWFISH_KEY',
    )!;

    if (!this.jwtSecret) {
      // Secret for internal tokens is crucial
      throw new Error('JWT_SECRET environment variable not set');
    }
    if (!this.legacyBlowfishKey) {
      throw new Error('LEGACY_BLOWFISH_KEY environment variable not set');
    }
  }

  private generateNumericOtp(length: number): string {
    let otp = '';
    const otpChars = '0123456789';
    for (let i = 0; i < length; i++) {
      otp += otpChars.charAt(Math.floor(Math.random() * otpChars.length));
    }
    return otp;
  }

  async activateUser(activateDto: ActivateUserBodyDto): Promise<any> {
    const { userId, otp, resendToken } = activateDto.param;
    this.logger.log(`Attempting to activate user ID: ${userId} with OTP`);

    if (!userId || !otp || !resendToken) {
      throw new BadRequestException(
        'User ID, OTP, and resend token are required for activation.',
      );
    }

    let decodedJwtPayload: jwt.JwtPayload | string;
    try {
      decodedJwtPayload = jwt.verify(resendToken, this.jwtSecret, {
        audience: OTP_ACTIVATION_JWT_AUDIENCE,
      }) as jwt.JwtPayload;
      if (decodedJwtPayload.sub !== userId.toString()) {
        this.logger.warn(
          `Resend token subject (${decodedJwtPayload.sub}) does not match user ID (${userId}) for activation.`,
        );
        throw new ForbiddenException('Invalid resend token: User ID mismatch.');
      }
    } catch (error) {
      this.logger.warn(
        `Resend token validation failed for user ID ${userId}: ${error.message}`,
      );
      if (error instanceof jwt.TokenExpiredError) {
        throw new GoneException('Resend token has expired.');
      }
      throw new ForbiddenException('Invalid or expired resend token.');
    }
    this.logger.debug(`Resend token validated for user ID ${userId}`);

    const otpCacheKey = `${ACTIVATION_OTP_CACHE_PREFIX_KEY}:${userId}`;
    const cachedOtp = await this.cacheManager.get<string>(otpCacheKey);

    if (!cachedOtp) {
      this.logger.warn(
        `Activation OTP not found or expired in cache for user ID ${userId}. Key: ${otpCacheKey}`,
      );
      throw new GoneException(
        'Activation OTP has expired or was not found. Please request a new one.',
      );
    }

    if (cachedOtp !== otp) {
      this.logger.warn(
        `Invalid OTP provided for user ID ${userId}. Expected: ${cachedOtp}, Got: ${otp}`,
      );
      throw new BadRequestException('Invalid activation OTP.');
    }
    this.logger.log(`Activation OTP validated for user ID ${userId}`);

    await this.cacheManager.del(otpCacheKey);

    const user = await this.prismaOltp.user.findUnique({
      where: { user_id: userId },
    });
    if (!user) {
      this.logger.error(`User not found for activation: ${userId}`);
      throw new NotFoundException('User not found.');
    }
    if (user.status === 'A') {
      this.logger.log(`User ${userId} is already active.`);
      return { message: 'User is already active.', user: user };
    }
    if (user.status !== 'U') {
      this.logger.warn(
        `User ${userId} has an unexpected status '${user.status}' for activation.`,
      );
      throw new ForbiddenException(
        `User account status (${user.status}) does not allow activation.`,
      );
    }

    let primaryEmailAddress: string | undefined;

    try {
      await this.prismaOltp.$transaction(async (prisma) => {
        await prisma.user.update({
          where: { user_id: userId },
          data: { status: 'A', modify_date: new Date() },
        });
        this.logger.log(`User status updated to 'A' for ID ${userId}`);

        // Find the primary email record for this user directly from the email table
        const primaryEmailRecord = await prisma.email.findFirst({
          where: { user_id: userId, primary_ind: 1 },
        });

        if (primaryEmailRecord) {
          primaryEmailAddress = primaryEmailRecord.address;
          // Update the status of the primary email to Verified (assuming status_id 1)
          await prisma.email.update({
            where: {
              email_id: primaryEmailRecord.email_id,
            },
            data: { status_id: 1, modify_date: new Date() }, // Prisma handles number to Decimal for DTOs
          });
          this.logger.log(
            `Primary email (ID: ${primaryEmailRecord.email_id}, Address: ${primaryEmailRecord.address}) status_id updated to verified for user ${userId}.`,
          );
        } else {
          this.logger.warn(
            `No primary email record (primary_ind = 1) found for user ${userId} during activation to mark as verified.`,
          );
        }
      });
    } catch (dbError) {
      this.logger.error(
        `Database error during activation for user ID ${userId}: ${dbError.message}`,
        dbError.stack,
      );
      throw new InternalServerErrorException(
        'Failed to activate user due to a database error.',
      );
    }

    try {
      // Use postEnvelopedNotification for standard events
      await this.eventService.postEnvelopedNotification('user.activated', {
        userId: userId.toString(),
      });
      this.logger.log(`Published 'user.activated' event for ${userId}`);

      // Send Welcome Email directly, matching legacy Java behavior
      if (primaryEmailAddress && user?.handle) {
        const domain =
          this.configService.get<string>('APP_DOMAIN') || 'topcoder-dev.com';
        const fromEmail = `Topcoder <noreply@${domain}>`;
        const welcomeTemplateId = this.configService.get<string>(
          'SENDGRID_WELCOME_EMAIL_TEMPLATE_ID',
        );

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
            version: 'v3',
            sendgrid_template_id: welcomeTemplateId,
            recipients: [primaryEmailAddress],
          };
          await this.eventService.postDirectBusMessage(
            'external.action.email',
            welcomeEmailPayload,
          );
          this.logger.log(
            `Published 'external.action.email' (welcome) for user ${userId} to ${primaryEmailAddress}. Payload: ${JSON.stringify(welcomeEmailPayload, null, 2)}`,
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

    this.logger.log(`User ${userId} activated successfully.`);
    const activatedUser = await this.prismaOltp.user.findUnique({
      where: { user_id: userId },
    });
    return activatedUser;
  }

  async requestResendActivation(
    resendDto: UserOtpDto,
  ): Promise<{ message: string }> {
    const { userId, resendToken } = resendDto;
    this.logger.log(`Attempting to resend activation for user ID: ${userId}`);

    if (!userId || !resendToken) {
      throw new BadRequestException('User ID and resend token are required.');
    }

    let decodedJwtPayload: jwt.JwtPayload | string;
    try {
      decodedJwtPayload = jwt.verify(resendToken, this.jwtSecret, {
        audience: OTP_ACTIVATION_JWT_AUDIENCE,
      }) as jwt.JwtPayload;
      if (decodedJwtPayload.sub !== userId.toString()) {
        throw new ForbiddenException('Invalid resend token: User ID mismatch.');
      }
    } catch (error) {
      this.logger.warn(
        `Resend activation token validation failed for user ID ${userId}: ${error.message}`,
      );
      if (error instanceof jwt.TokenExpiredError) {
        throw new GoneException('Resend token has expired.');
      }
      throw new ForbiddenException('Invalid or expired resend token.');
    }

    const user = await this.prismaOltp.user.findUnique({
      where: { user_id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found.');
    }

    const primaryEmailRecord = await this.prismaOltp.email.findFirst({
      where: {
        user_id: userId,
        primary_ind: 1,
        status_id: 2, // Look for an UNVERIFIED primary email
      },
    });

    if (!primaryEmailRecord) {
      throw new InternalServerErrorException(
        'Primary unverified email not found for the user.', // Updated error message for clarity
      );
    }
    const primaryEmail = primaryEmailRecord.address;

    if (user.status === 'A') {
      return { message: 'Account is already activated.' };
    }
    if (user.status !== 'U') {
      throw new ForbiddenException(
        `User account status (${user.status}) does not allow resending activation.`,
      );
    }

    const newOtp = this.generateNumericOtp(ACTIVATION_OTP_LENGTH);
    const otpCacheKey = `${ACTIVATION_OTP_CACHE_PREFIX_KEY}:${userId}`;
    const otpExpiry =
      this.configService.get<number>(
        'ACTIVATION_OTP_EXPIRY_SECONDS',
        ACTIVATION_OTP_EXPIRY_SECONDS,
      ) * 1000;

    try {
      await this.cacheManager.set(otpCacheKey, newOtp, otpExpiry);
      this.logger.log(
        `New activation OTP ${newOtp} generated and cached for user ${userId} (key: ${otpCacheKey})`,
      );
    } catch (cacheError) {
      this.logger.error(
        `Failed to cache new OTP for user ${userId}: ${cacheError.message}`,
        cacheError.stack,
      );
      throw new InternalServerErrorException(
        'Failed to process request due to caching error.',
      );
    }

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
          data: { handle: user.handle, code: newOtp },
          from: { email: fromEmail },
          version: 'v3',
          sendgrid_template_id: sendgridTemplateId,
          recipients: [primaryEmail], // The user's primary email
        };
        await this.eventService.postDirectBusMessage(
          'external.action.email',
          activationEmailPayload,
        );
        this.logger.log(
          `Published 'external.action.email' (activation resend) for ${userId} with new OTP. Payload: ${JSON.stringify(activationEmailPayload, null, 2)}`,
        );
      }
    } catch (eventError) {
      this.logger.error(
        `Failed to publish resend activation event for user ${userId}: ${eventError.message}`,
        eventError.stack,
      );
    }

    return { message: 'Activation email has been resent successfully.' };
  }

  async generateOneTimeToken(
    userIdString: string,
    passwordPlain: string,
  ): Promise<string> {
    this.logger.log(
      `Attempting to generate one-time token for user ID: ${userIdString}`,
    );
    if (!userIdString || !passwordPlain) {
      throw new BadRequestException('User ID and password are required.');
    }
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid User ID format.');
    }

    // 1. Fetch user by ID to get handle and status
    const user = await this.prismaOltp.user.findUnique({
      where: { user_id: userId },
      select: { user_id: true, handle: true, status: true },
    });

    if (!user) {
      this.logger.warn(`generateOneTimeToken: User not found for ID ${userId}`);
      throw new NotFoundException('User not found.');
    }

    if (user.status !== 'A') {
      this.logger.warn(
        `generateOneTimeToken: User ${user.handle} (ID: ${userId}) is not active (status: ${user.status}).`,
      );
      throw new ForbiddenException('User account is not active.');
    }

    // 2. Fetch Encrypted Password from security_user using the user's handle
    const securityUserRecord = await this.prismaOltp.security_user.findUnique({
      where: { user_id: user.handle }, // security_user.user_id is the user handle
      select: { password: true },
    });

    if (!securityUserRecord || !securityUserRecord.password) {
      this.logger.error(
        `generateOneTimeToken: Security record or password not found for user handle ${user.handle} (ID: ${userId})`,
      );
      throw new InternalServerErrorException(
        'User security information not found.',
      );
    }

    // 3. Decrypt Password (Blowfish)
    let decryptedPassword = '';
    try {
      const key = CryptoJS.enc.Base64.parse(this.legacyBlowfishKey);
      const encryptedBase64 = securityUserRecord.password;
      const decrypted = CryptoJS.Blowfish.decrypt(encryptedBase64, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
      });
      if (!decrypted || decrypted.sigBytes === 0) {
        throw new Error('Decryption resulted in zero bytes');
      }
      decryptedPassword = decrypted.toString(CryptoJS.enc.Utf8);
      if (!decryptedPassword && decrypted.sigBytes > 0) {
        throw new Error('Decrypted bytes could not be converted to UTF8');
      }
    } catch (error) {
      this.logger.error(
        `generateOneTimeToken: Blowfish decryption failed for user ${user.handle} (ID: ${userId}): ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'Authentication failed due to a security processing error.',
      );
    }

    // 4. Compare Passwords
    if (decryptedPassword !== passwordPlain) {
      this.logger.warn(
        `generateOneTimeToken: Password mismatch for ${user.handle} (ID: ${userId})`,
      );
      throw new UnauthorizedException('Invalid credentials.');
    }
    this.logger.log(
      `User ${userId} authenticated for one-time token generation.`,
    );

    // 5. Generate JWT
    const jti = uuidv4(); // Unique token identifier
    const payload = {
      sub: userId.toString(),
      aud: ONE_TIME_TOKEN_JWT_AUDIENCE,
      jti: jti,
    };
    const token = jwt.sign(payload, this.jwtSecret, {
      expiresIn: `${this.oneTimeTokenExpirySeconds}s`,
    });

    // Note: Unlike Java UserResource, we are not caching the token string itself.
    // Instead, we rely on JWT expiry and will cache the JTI if we need to ensure it's used only once.
    this.logger.log(
      `Generated one-time token (JTI: ${jti}) for user ${userId}`,
    );
    return token;
  }

  async updateEmailWithOneTimeToken(
    userIdString: string,
    newEmail: string,
    token: string,
  ): Promise<void> {
    this.logger.log(
      `Attempting to update email for user ID ${userIdString} to ${newEmail} using one-time token.`,
    );
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid User ID format.');
    }

    // 1. Validate JWT (signature, expiry, audience, subject)
    let decodedPayload: jwt.JwtPayload;
    try {
      decodedPayload = jwt.verify(token, this.jwtSecret, {
        audience: ONE_TIME_TOKEN_JWT_AUDIENCE,
      }) as jwt.JwtPayload;
      if (decodedPayload.sub !== userId.toString()) {
        throw new ForbiddenException('Token subject does not match user ID.');
      }
    } catch (error) {
      this.logger.warn(`One-time token validation failed: ${error.message}`);
      if (error instanceof jwt.TokenExpiredError)
        throw new GoneException('One-time token has expired.');
      throw new ForbiddenException('Invalid or expired one-time token.');
    }

    // 2. Check if JTI has been used (optional, for strict one-time use if not relying purely on short expiry)
    const jti = decodedPayload.jti;
    if (jti) {
      const jtiCacheKey = `${ONE_TIME_TOKEN_CACHE_PREFIX_JTI}:${jti}`;
      const used = await this.cacheManager.get<string>(jtiCacheKey);
      if (used) {
        this.logger.warn(`One-time token JTI ${jti} has already been used.`);
        throw new ForbiddenException(
          'This one-time token has already been used.',
        );
      }
      // Mark JTI as used by caching it for the duration of its potential validity or a bit longer
      await this.cacheManager.set(
        jtiCacheKey,
        'used',
        this.oneTimeTokenExpirySeconds * 1000,
      );
    }
    this.logger.log(`One-time token validated for user ${userId}. JTI: ${jti}`);

    // 3. Validate newEmail format and uniqueness against OTHER users
    if (!newEmail || !EMAIL_REGEX.test(newEmail)) {
      // Assuming EMAIL_REGEX is available or imported
      throw new BadRequestException('Invalid new email format.');
    }
    // This validation should check if `newEmail` is used by *another* user as primary.
    // The ValidationService.validateEmail might need adjustment or a new method for this specific check.
    // For now, assuming validateEmail checks general conflicts.
    try {
      await this.userService.checkEmailAvailabilityForUser(newEmail, userId); // This method needs to be created in UserService
    } catch (error) {
      // Re-throw known exceptions, wrap others
      if (
        error instanceof ConflictException ||
        error instanceof BadRequestException ||
        error instanceof NotFoundException
      ) {
        throw error;
      } else {
        this.logger.error(
          `Unexpected error during email availability check: ${error.message}`,
          error.stack,
        );
        throw new InternalServerErrorException(
          'Error validating new email address.',
        );
      }
    }

    // 4. Prisma Transaction: Update email
    await this.prismaOltp.$transaction(async (prisma) => {
      const newEmailLower = newEmail.toLowerCase();

      // Step 1: Find the current primary email for the user
      const currentPrimaryEmail = await prisma.email.findFirst({
        where: {
          user_id: userId,
          primary_ind: 1,
        },
      });

      // Step 2: If current primary email exists and is different from the new one,
      // mark it as non-primary.
      if (
        currentPrimaryEmail &&
        currentPrimaryEmail.address !== newEmailLower
      ) {
        await prisma.email.update({
          where: { email_id: currentPrimaryEmail.email_id },
          data: {
            primary_ind: 0, // Mark as non-primary
            modify_date: new Date(),
          },
        });
        this.logger.log(
          `Marked old primary email ${currentPrimaryEmail.address} (ID: ${currentPrimaryEmail.email_id}) as non-primary for user ${userId}.`,
        );
      }

      // Step 3: Find or create the record for the new email address
      let newEmailEntity = await prisma.email.findFirst({
        where: { address: newEmailLower },
      });

      if (newEmailEntity) {
        // Email address exists, update it to be the primary for this user
        await prisma.email.update({
          where: { email_id: newEmailEntity.email_id },
          data: {
            user_id: userId, // Associate/Re-associate with this user
            primary_ind: 1, // Mark as primary
            status_id: 1, // Mark as verified
            modify_date: new Date(),
          },
        });
        this.logger.log(
          `Updated existing email ${newEmailLower} (ID: ${newEmailEntity.email_id}) to be primary and verified for user ${userId}.`,
        );
      } else {
        // Email address does not exist, create a new one for this user as primary and verified

        // Get nextval for email_id from sequence
        const emailIdRecord = await prisma.$queryRaw<
          [{ nextval: bigint }]
        >`SELECT nextval('sequence_email_seq'::regclass)`;
        const nextEmailId = emailIdRecord[0].nextval;
        if (!nextEmailId) {
          throw new InternalServerErrorException(
            'Could not retrieve next email_id from sequence.',
          );
        }

        newEmailEntity = await prisma.email.create({
          data: {
            email_id: new Decimal(nextEmailId.toString()), // Ensure correct type
            address: newEmailLower,
            user_id: userId,
            primary_ind: 1,
            status_id: 1, // Verified
            create_date: new Date(),
            modify_date: new Date(),
          },
        });
        this.logger.log(
          `Created new email ${newEmailLower} (ID: ${newEmailEntity.email_id}) as primary and verified for user ${userId}.`,
        );
      }
      this.logger.log(
        `Primary email updated to ${newEmail} for user ${userId}.`,
      );
    });

    // 5. Publish user.updated event
    try {
      const user = await this.prismaOltp.user.findUnique({
        where: { user_id: userId },
      });
      if (user) {
        // Use postEnvelopedNotification for standard events
        await this.eventService.postEnvelopedNotification('user.updated', {
          userId: userId.toString(),
          handle: user.handle,
          email: newEmail, // This is the new email being set
        });
        this.logger.log(
          `Published 'user.updated' event for email change, user ${userId}`,
        );
      }
    } catch (eventError) {
      this.logger.error(
        `Failed to publish user.updated event for email change, user ${userId}: ${eventError.message}`,
      );
    }
  }

  // --- Helper methods ---
  private async generateAndCacheToken(
    purpose: string,
    userId: number,
    expirySeconds: number,
  ): Promise<string> {
    const token = require('crypto').randomBytes(32).toString('hex');
    const key = `identity:${purpose}:${token}`;
    await this.cacheManager.set(key, userId.toString(), expirySeconds * 1000);
    this.logger.log(`Generated ${purpose} token for user ${userId}`);
    return token;
  }

  private async validateAndConsumeToken(
    purpose: string,
    token: string,
  ): Promise<number | null> {
    const key = `identity:${purpose}:${token}`;
    const userIdString = await this.cacheManager.get<string>(key);
    if (!userIdString) {
      this.logger.warn(`${purpose} token not found or expired: ${token}`);
      return null;
    }
    await this.cacheManager.del(key);
    this.logger.log(
      `Validated and consumed ${purpose} token for user ${userIdString}`,
    );
    return parseInt(userIdString, 10);
  }

  private generateAlphanumericToken(length: number): string {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < length; i++) {
      token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
  }

  async initiatePasswordReset(
    emailOrHandle: string,
    resetPasswordUrlPrefix?: string,
  ): Promise<void> {
    this.logger.log(`Initiating password reset for: ${emailOrHandle}`);
    if (!emailOrHandle) {
      throw new BadRequestException('Email or handle is required.');
    }

    let user: Awaited<
      ReturnType<typeof this.userService.findUserByEmailOrHandle>
    >;
    try {
      user = await this.userService.findUserByEmailOrHandle(emailOrHandle);
    } catch (error) {
      // Catch NotFoundException from userService and treat as success to avoid leaking user existence
      if (error instanceof NotFoundException) {
        this.logger.log(
          `User not found for ${emailOrHandle}, but returning success for initiatePasswordReset.`,
        );
        return; // Do not proceed, but don't inform client
      }
      throw error; // Re-throw other errors
    }

    if (!user) {
      // Should be caught by the above, but as a safeguard
      this.logger.log(
        `User not found for ${emailOrHandle}, returning success for initiatePasswordReset.`,
      );
      return;
    }

    // Check if user has SSO profiles (Java logic: userDao.getSSOProfiles)
    // Assuming user model from userService.findUserByEmailOrHandle includes sso_logins
    if (user.user_sso_login && user.user_sso_login.length > 0) {
      this.logger.warn(
        `User ${user.user_id} is an SSO user. Password reset via this flow is not allowed.`,
      );
      throw new ForbiddenException(
        'Password reset is not allowed for SSO-linked accounts.',
      );
    }

    const resetTokenCacheKey = `${PASSWORD_RESET_TOKEN_CACHE_PREFIX}:${user.user_id}`;
    const existingCachedToken =
      await this.cacheManager.get<string>(resetTokenCacheKey);
    if (existingCachedToken) {
      this.logger.warn(
        `Password reset token already issued for user ${user.user_id}.`,
      );
      // Java logic threw an error here. Adhering to that.
      throw new ConflictException(
        'Password reset token has already been issued. Please check your email or wait for it to expire.',
      );
    }

    const resetToken = this.generateAlphanumericToken(
      PASSWORD_RESET_TOKEN_LENGTH,
    );
    const expirySeconds = this.resetTokenExpirySeconds;
    await this.cacheManager.set(
      resetTokenCacheKey,
      resetToken,
      expirySeconds * 1000,
    );
    this.logger.log(
      `Password reset token ${resetToken} generated and cached for user ${user.user_id}`,
    );

    const finalResetUrlPrefix =
      resetPasswordUrlPrefix ||
      this.configService.get<string>('DEFAULT_RESET_PASSWORD_URL_PREFIX') ||
      'https://www.topcoder-dev.com/reset-password?token='; // Fallback if not in config

    // Ensure user has a primary email to send the reset link to
    const primaryEmailAddress = user.primaryEmail?.address;
    if (!primaryEmailAddress) {
      this.logger.error(
        `Password reset initiated for user ${user.user_id} (${user.handle}), but no primary email address is associated. Cannot send email.`,
      );
      // Do not throw an error to prevent user enumeration, but log that email cannot be sent.
      return;
    }

    const finalResetUrl = `${finalResetUrlPrefix}${resetToken}`;
    const resetTokenExpiryMinutes = this.resetTokenExpirySeconds / 60;

    // Construct the attributes for the 'userpasswordreset' notificationType
    // This matches the fields of the legacy Java MailRepresentation, excluding its own notificationType field.
    const eventAttributes = {
      recipients: [
        {
          // Per Java MailRepresentation, recipients can have id and email
          id: user.user_id.toString(),
          email: primaryEmailAddress,
        },
      ],
      data: {
        // Nested data payload as per legacy MailRepresentation
        handle: user.handle,
        resetToken: resetToken,
        tokenExpiry: resetTokenExpiryMinutes,
        resetUrl: finalResetUrl,
        subject: 'Your Topcoder Password Reset Request', // Retaining from previous logic
        from:
          this.configService.get<string>('EVENT_DEFAULT_SENDER_EMAIL') ||
          'noreply@topcoder-dev.com', // Retaining from previous logic
        // Any other fields that were part of MailRepresentation.data
      },
      version: 'v3', // Retaining from previous logic, was part of MailRepresentation
      // Optional fields from MailRepresentation, if applicable
      cc: [],
      bcc: [],
    };

    this.logger.log(
      `[AuthFlowService] Preparing to send 'userpasswordreset' notification. Attributes: ${JSON.stringify(eventAttributes, null, 2)}`,
    );

    try {
      // 'userpasswordreset' is the notificationType for the event envelope's payload
      // eventAttributes are the rest of the fields for that payload
      // Use postEnvelopedNotification for this standard enveloped notification
      await this.eventService.postEnvelopedNotification(
        'userpasswordreset',
        eventAttributes,
      );
      this.logger.log(
        `Password reset notification ('userpasswordreset') published for user ${user.user_id}`,
      );
    } catch (eventError) {
      this.logger.error(
        `Failed to publish password reset event (to event.notification.send) for user ${user.user_id}: ${eventError.message}`,
        eventError.stack,
      );
      // Depending on business requirements, you might want to re-throw or handle this error differently.
      // For example, if email is critical, this could be a hard failure.
    }
  }

  async resetPassword(resetDto: {
    handleOrEmail?: string;
    resetToken: string;
    newPassword?: string;
  }): Promise<void> {
    const { handleOrEmail, resetToken, newPassword } = resetDto;
    this.logger.log(`Attempting to reset password with token.`);

    if (!resetToken || !newPassword) {
      throw new BadRequestException(
        'Reset token and new password are required.',
      );
    }
    if (newPassword.length < 8) {
      throw new BadRequestException(
        'New password must be at least 8 characters long.',
      );
    }

    // Find user by handleOrEmail - needed to construct cache key as per Java logic
    if (!handleOrEmail) {
      // Java logic: if handle/email not provided in DTO, it implies it might have been part of an earlier step
      // or the token itself is globally unique. For now, require handleOrEmail for key construction.
      throw new BadRequestException(
        'Handle or email is required to identify the user for password reset.',
      );
    }

    let user: Awaited<
      ReturnType<typeof this.userService.findUserByEmailOrHandle>
    >;
    try {
      user = await this.userService.findUserByEmailOrHandle(handleOrEmail);
    } catch (error) {
      throw new NotFoundException(`User '${handleOrEmail}' not found.`); // Or BadRequest if user identity is solely from token
    }
    if (!user)
      throw new NotFoundException(`User '${handleOrEmail}' not found.`);

    const resetTokenCacheKey = `${PASSWORD_RESET_TOKEN_CACHE_PREFIX}:${user.user_id}`;
    const cachedToken = await this.cacheManager.get<string>(resetTokenCacheKey);

    if (!cachedToken) {
      this.logger.warn(
        `Password reset token not found in cache for user ${user.user_id}. Key: ${resetTokenCacheKey}`,
      );
      throw new GoneException(
        'Password reset token has expired or is invalid.',
      );
    }

    if (cachedToken !== resetToken) {
      this.logger.warn(
        `Invalid password reset token provided for user ${user.user_id}.`,
      );
      throw new BadRequestException('Invalid password reset token.');
    }

    await this.cacheManager.del(resetTokenCacheKey);
    this.logger.log(
      `Password reset token validated and consumed for user ${user.user_id}`,
    );

    // Encrypt the new password using the legacy Blowfish method from UserService
    const legacyEncodedPassword =
      this.userService.encodePasswordLegacy(newPassword);
    this.logger.debug(
      `Password reset: New password encoded using legacy method for user ${user.handle}.`,
    );

    // Update the password in the security_user table using the user's handle
    await this.prismaOltp.security_user.update({
      where: { user_id: user.handle }, // security_user.user_id is the user handle
      data: { password: legacyEncodedPassword },
    });

    // Also update the modify_date on the main user record
    await this.prismaOltp.user.update({
      where: { user_id: user.user_id.toNumber() },
      data: { modify_date: new Date() }, // Only update modify_date here
    });

    this.logger.log(`Password successfully reset for user ${user.user_id}`);
    // Optionally publish user.password.updated event
  }

  /**
   * Authenticates a user with handle/email and password, mimicking legacy Java logic.
   * Expected to be called by Auth0 Custom Database script.
   * Returns a user profile object suitable for Auth0.
   */
  async authenticateForAuth0(
    handleOrEmail: string,
    passwordPlain: string,
  ): Promise<any> {
    this.logger.log(
      `Auth0 Custom DB: Authenticating user: ${handleOrEmail} (Legacy Flow)`,
    );
    const isEmail = handleOrEmail.includes('@');

    // Simplified User type definition remains the same
    type UserForAuth0 = Prisma.userGetPayload<{
      select: {
        user_id: true;
        handle: true;
        status: true;
        // Password is NOT selected from user table anymore
        first_name: true;
        last_name: true;
        create_date: true;
        modify_date: true;
        last_login: true;
        user_2fa: true; // Keep 2FA info
      };
    }>;

    let userRecord: UserForAuth0 | null = null;
    let userId: number | null = null;
    let userHandle: string | null = null; // Store handle separately

    // 1. Find User Record (without password)
    if (isEmail) {
      const emailRecord = await this.prismaOltp.email.findFirst({
        where: { address: handleOrEmail.toLowerCase(), primary_ind: 1 }, // Ensure it's the primary email
        select: { user_id: true },
      });

      if (emailRecord) {
        userId = emailRecord.user_id.toNumber();
        userRecord = await this.prismaOltp.user.findUnique({
          where: { user_id: userId },
          select: {
            user_id: true,
            handle: true, // Need handle to query security_user
            status: true,
            first_name: true,
            last_name: true,
            create_date: true,
            modify_date: true,
            last_login: true,
            user_2fa: true,
          },
        });
        if (userRecord) {
          userHandle = userRecord.handle;
        }
      }
    } else {
      // Find user by handle
      userRecord = await this.prismaOltp.user.findFirst({
        where: { handle_lower: handleOrEmail.toLowerCase() },
        select: {
          user_id: true,
          handle: true, // Need handle
          status: true,
          first_name: true,
          last_name: true,
          create_date: true,
          modify_date: true,
          last_login: true,
          user_2fa: true,
        },
      });
      if (userRecord) {
        userId = userRecord.user_id.toNumber();
        userHandle = userRecord.handle;
      }
    }

    // Fetch primary email separately (as before)
    let primaryEmail: string | undefined;
    let emailVerified: boolean = false;
    if (userId) {
      const primaryEmailRecord = await this.prismaOltp.email.findFirst({
        where: { user_id: userId, primary_ind: 1 },
        select: { address: true, status_id: true },
      });
      if (primaryEmailRecord) {
        primaryEmail = primaryEmailRecord.address;
        emailVerified = primaryEmailRecord.status_id.toNumber() === 1;
      }
    }

    if (!userRecord || !userId || !userHandle) {
      // Check all necessary identifiers
      this.logger.warn(`Auth0 Custom DB: User not found for ${handleOrEmail}`);
      throw new UnauthorizedException('Invalid credentials.');
    }

    if (userRecord.status !== 'A' && userRecord.status !== 'U') {
      this.logger.warn(
        `Auth0 Custom DB: Account for ${handleOrEmail} (ID: ${userId}) is deactivated (status: ${userRecord.status}).`,
      );
      throw new UnauthorizedException('Account is deactivated.');
    }

    // 2. Fetch Encrypted Password from security_user using the handle
    const securityUserRecord = await this.prismaOltp.security_user.findUnique({
      where: { user_id: userHandle }, // Java logic uses handle as security_user.user_id
      select: { password: true },
    });

    if (!securityUserRecord || !securityUserRecord.password) {
      this.logger.error(
        `Auth0 Custom DB: Security record or password not found for user handle ${userHandle} (ID: ${userId})`,
      );
      // This covers the case where the user exists but the password wasn't stored correctly in security_user
      throw new UnauthorizedException('Invalid credentials.'); // Or InternalServerErrorException if this state shouldn't happen
    }

    // Log the encrypted password before attempting decryption
    this.logger.debug(
      `[AuthFlow Auth0] Encrypted password for handle ${userHandle} from DB: ${securityUserRecord.password}`,
    );

    let decryptedPassword = '';
    try {
      // Changed: Parse the Base64 key directly
      const key = CryptoJS.enc.Base64.parse(this.legacyBlowfishKey);
      const encryptedBase64 = securityUserRecord.password;
      const decrypted = CryptoJS.Blowfish.decrypt(encryptedBase64, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
      });
      // Explicitly check if decryption produced any bytes
      if (!decrypted || decrypted.sigBytes === 0) {
        throw new Error('Decryption resulted in zero bytes');
      }
      decryptedPassword = decrypted.toString(CryptoJS.enc.Utf8);

      // Additional check if conversion to UTF8 failed
      if (!decryptedPassword && decrypted.sigBytes > 0) {
        throw new Error('Decrypted bytes could not be converted to UTF8');
      }
    } catch (error) {
      this.logger.error(
        `Auth0 Custom DB: Blowfish decryption failed for user ${userHandle} (ID: ${userId}): ${error.message}`,
        error.stack, // Log stack trace for decryption errors
      );
      // Rethrow as Internal Server Error to avoid exposing details, but log the specific internal error
      throw new InternalServerErrorException(
        'Password decryption failed internally.',
      );
    }

    // 4. Compare Passwords
    if (decryptedPassword !== passwordPlain) {
      this.logger.warn(
        `Auth0 Custom DB: Password mismatch for ${userHandle} (ID: ${userId})`,
      );
      throw new UnauthorizedException('Invalid credentials.');
    }

    // Password matches, proceed with profile generation
    this.logger.log(
      `Auth0 Custom DB: Password validated for ${userHandle} (ID: ${userId})`,
    );

    // Fetch roles (as before)
    const roleEntities = await this.roleService.findAll(userId);
    const roles = roleEntities.map((r) => r.roleName);

    // Construct the profile object for Auth0 (same structure as before)
    const auth0Profile = {
      user_id: userId.toString(),
      email: primaryEmail?.toLowerCase(),
      email_verified: emailVerified,
      name:
        `${userRecord.first_name || ''} ${userRecord.last_name || ''}`.trim() ||
        primaryEmail,
      given_name: userRecord.first_name || '' || undefined,
      family_name: userRecord.last_name || '' || undefined,
      nickname: userHandle,
      picture: null,
      'https://topcoder.com/claims/userId': userId,
      'https://topcoder.com/claims/handle': userHandle,
      'https://topcoder.com/claims/roles': roles,
      'https://topcoder.com/claims/status': userRecord.status,
      'https://topcoder.com/claims/mfa_enabled':
        userRecord.user_2fa?.mfa_enabled ?? false,
      'https://topcoder.com/claims/dice_enabled':
        userRecord.user_2fa?.dice_enabled ?? false,
      last_login: userRecord.last_login?.toISOString(),
      created_at: userRecord.create_date?.toISOString(),
      updated_at: userRecord.modify_date?.toISOString(),
    };

    this.logger.log(
      `Auth0 Custom DB: Authentication successful for ${userHandle} (ID: ${userId})`,
    );
    return auth0Profile;
  }

  async getUserProfileForAuth0(handleOrEmail: string): Promise<any> {
    this.logger.log(`Auth0 Roles: Getting profile for ${handleOrEmail}`);
    if (!handleOrEmail) {
      throw new BadRequestException('Handle or email is required.');
    }

    const isEmail = handleOrEmail.includes('@');
    let user: Prisma.userGetPayload<{
      select: {
        user_id: true;
        handle: true;
        status: true;
      };
    }> | null = null;
    let userIdNumber: number | null = null;

    if (isEmail) {
      // 1. Find email to get user_id
      const emailRecord = await this.prismaOltp.email.findFirst({
        where: { address: handleOrEmail.toLowerCase() },
        select: { user_id: true },
      });
      if (emailRecord) {
        userIdNumber = emailRecord.user_id.toNumber();
        // 2. Find user by user_id
        user = await this.prismaOltp.user.findUnique({
          where: { user_id: userIdNumber },
          select: {
            user_id: true,
            handle: true,
            status: true,
          },
        });
      }
    } else {
      // Find user by handle
      user = await this.prismaOltp.user.findFirst({
        where: { handle_lower: handleOrEmail.toLowerCase() },
        select: {
          user_id: true,
          handle: true,
          status: true,
        },
      });
      if (user) {
        userIdNumber = user.user_id.toNumber();
      }
    }

    if (!user || userIdNumber === null) {
      // Check both user and userIdNumber
      this.logger.warn(`Auth0 Roles: User ${handleOrEmail} not found.`);
      throw new NotFoundException('User not found.');
    }

    // Fetch roles and primary email separately using userIdNumber
    const roles = await this.roleService.findAll(userIdNumber);
    const primaryEmailRecord = await this.prismaOltp.email.findFirst({
      where: { user_id: userIdNumber, primary_ind: 1 },
      select: { address: true, status_id: true },
    });
    const primaryEmail = primaryEmailRecord?.address;
    const emailVerified = primaryEmailRecord?.status_id.toNumber() === 1;

    // Generate SSO token (ensure userService method exists and works)
    const tcssoToken = await this.userService.generateSSOToken(userIdNumber);

    const response: any = {
      userId: user.user_id.toString(),
      handle: user.handle,
      email: primaryEmail,
      roles: roles.map((r) => r.roleName),
      emailVerified: emailVerified, // Use status from email table
      tcsso: tcssoToken,
      status: user.status,
    };

    if (user.status === 'U') {
      const payload = {
        sub: user.user_id.toString(),
        aud: OTP_ACTIVATION_JWT_AUDIENCE,
      };
      response.resendToken = jwt.sign(payload, this.jwtSecret, {
        expiresIn: `${this.activationResendExpirySeconds}s`,
      });
      response.canResendActivation = true;
      this.logger.log(
        `Auth0 Roles: User ${user.handle} is unverified. Added resendToken.`,
      );
    }

    this.logger.log(`Auth0 Roles: Profile retrieved for ${user.handle}.`);
    return response;
  }

  async changePasswordFromAuth0(
    email: string,
    newPasswordPlain: string,
  ): Promise<{ message: string }> {
    this.logger.log(
      `Auth0 Action: Change password request for email: ${email}`,
    );
    if (!email || !newPasswordPlain) {
      throw new BadRequestException('Email and new password are required.');
    }

    const user = await this.userService.findUserByEmailOrHandle(email); // Ensure this finds by primary email effectively
    if (!user) {
      this.logger.warn(
        `Auth0 Action: User with email ${email} not found for password change.`,
      );
      throw new NotFoundException('User not found.');
    }

    // Check if SSO user (Java UserResource.changePassword did this)
    if (user.user_sso_login && user.user_sso_login.length > 0) {
      this.logger.warn(
        `Auth0 Action: Attempt to change password for SSO user ${user.handle}. Denied.`,
      );
      throw new ForbiddenException(
        'Password change is not allowed for SSO-linked accounts.',
      );
    }

    if (newPasswordPlain.length < 8) {
      throw new BadRequestException(
        'New password must be at least 8 characters long.',
      );
    }

    // Encrypt the new password using the legacy Blowfish method from UserService
    const legacyEncodedPassword =
      this.userService.encodePasswordLegacy(newPasswordPlain);
    this.logger.debug(
      `Auth0 Action: New password encoded using legacy method for user ${user.handle}.`,
    );

    // Update the password in the security_user table using the user's handle
    await this.prismaOltp.security_user.update({
      where: { user_id: user.handle }, // Find security_user record by handle
      data: { password: legacyEncodedPassword },
    });

    // Also update the modify_date on the main user record
    await this.prismaOltp.user.update({
      where: { user_id: user.user_id.toNumber() },
      data: { modify_date: new Date() },
    });

    this.logger.log(
      `Auth0 Action: Password successfully changed for user ${user.handle}.`,
    );
    return { message: 'Password changed successfully.' };
  }
}
