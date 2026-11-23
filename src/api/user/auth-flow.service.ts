import { verifySignedJwt } from 'tc-core-library-js';
import { Injectable, Inject, Logger } from '@nestjs/common';
import { addSeconds } from 'date-fns';
import { format } from 'date-fns-tz';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { Prisma, PrismaClient, user as UserModel } from '@prisma/client';
import { Cache } from 'cache-manager'; // Import Cache type
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import { UserService } from './user.service';
import { EventService } from '../../shared/event/event.service';
import { RoleService } from '../role/role.service';
import {
  ActivateUserBodyDto,
  ResetPasswordBodyDto,
  UserOtpDto,
} from '../../dto/user/user.dto';
import {
  BadRequestException,
  ForbiddenException,
  GoneException,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
  ConflictException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import {
  ACTIVATION_MODE,
  ACTIVATION_LIFETIME_MS,
  MAX_CODE_ATTEMPTS,
  newActivationCode,
  recentActivationEvents,
  nextActivationSend,
  activationAttemptRetry,
} from './activation-code';
import { randomUUID as uuidv4 } from 'node:crypto';
import { Constants } from '../../core/constant/constants';
import { MemberStatus } from '../../dto/member/member.status.enum';
import { MemberPrismaService } from '../../shared/member-prisma/member-prisma.service';
import { MemberStatus as MemberDbStatus } from '../../../prisma/member/generated/member';
import { ValidationService } from './validation.service';
import { CommonUtils } from '../../shared/util/common.utils';

const OTP_ACTIVATION_JWT_AUDIENCE = 'emailactivation';
const ONE_TIME_TOKEN_JWT_AUDIENCE = 'onetime_email_update';
const ONE_TIME_TOKEN_CACHE_PREFIX_JTI = 'USED_JTI_OTT';
const PASSWORD_RESET_TOKEN_CACHE_PREFIX = 'ap:identity:reset-tokens:'; // same as v3 java
const PASSWORD_RESET_TOKEN_LENGTH = 6; // Or longer for more security, Java used 6 alphanumeric

@Injectable()
export class AuthFlowService {
  private readonly logger = new Logger(AuthFlowService.name);
  private readonly jwtSecret: string;
  private readonly resetTokenExpirySeconds: number;
  private readonly activationResendExpirySeconds: number;
  private readonly oneTimeTokenExpirySeconds: number;
  private readonly legacyBlowfishKey: string; // For legacy password decryption
  private readonly authDomain: string;

  constructor(
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient,
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly eventService: EventService,
    private readonly roleService: RoleService,
    private readonly validationService: ValidationService,
    private readonly memberPrisma: MemberPrismaService,
  ) {
    this.authDomain = this.configService.get<string>('AUTH_DOMAIN');
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

  private verifyActivationProof(userId: number, token: string) {
    try {
      verifySignedJwt(token, this.jwtSecret, {
        audience: OTP_ACTIVATION_JWT_AUDIENCE,
        userId,
      });
    } catch (error) {
      if (
        error instanceof jwt.TokenExpiredError ||
        error.name === 'TokenExpiredError'
      ) {
        throw new GoneException(
          'Your activation session expired. Sign in again.',
        );
      }
      throw new ForbiddenException('Invalid or expired resend token.');
    }
  }

  // Lock the account even when its activation row is missing. Resend, wrong
  // attempts and successful activation must all observe the same generation.
  private async lockUnverifiedUser(
    tx: Prisma.TransactionClient,
    userId: number,
  ) {
    const [user] = await tx.$queryRaw<{ status: string }[]>`
      SELECT status FROM identity."user" WHERE user_id = ${userId} FOR UPDATE`;
    if (!user) throw new NotFoundException('User does not exist');
    if (user.status === MemberStatus.ACTIVE)
      throw new BadRequestException('User has been activated');
    if (user.status !== MemberStatus.UNVERIFIED)
      throw new ForbiddenException('Account is deactivated');
  }

  private async activationEmail(tx: Prisma.TransactionClient, userId: number) {
    const email = await tx.email.findFirst({
      where: {
        user_id: userId,
        primary_ind: Constants.primaryEmailFlag,
        email_type_id: Constants.standardEmailType,
      },
      select: { email_id: true, address: true },
    });
    if (!email?.address)
      throw new InternalServerErrorException(
        'Primary email not found for the user.',
      );
    return email;
  }

  private rateLimit(until: Date) {
    return new HttpException(
      {
        message: `Please try again after ${until.toISOString()}.`,
        retryAt: until.toISOString(),
      },
      HttpStatus.TOO_MANY_REQUESTS,
    );
  }

  /** Verifies the audience- and user-bound resend proof through tc-core, then activates the supplied user; throws on invalid proof/OTP. */
  async activateUser(activateDto: ActivateUserBodyDto): Promise<any> {
    const { userId, otp, resendToken } = activateDto.param;
    this.logger.log(`Attempting to activate user ID: ${userId} with OTP`);

    if (!userId || !otp || !resendToken) {
      throw new BadRequestException(
        'User ID, OTP, and resend token are required for activation.',
      );
    }

    this.verifyActivationProof(userId, resendToken);

    let primaryEmailAddress: string;
    try {
      const outcome = await this.prismaClient.$transaction(async (tx) => {
        await this.lockUnverifiedUser(tx, userId);
        const code = await tx.user_otp_email.findUnique({
          where: { user_id_mode: { user_id: userId, mode: ACTIVATION_MODE } },
        });
        if (!code) throw new NotFoundException('No activation code found');
        const now = new Date();
        const retryAt = activationAttemptRetry(code.activation_failures, now);
        if (retryAt) throw this.rateLimit(retryAt);
        if (code.expire_at <= now)
          throw new BadRequestException('Activation code expired');
        if (code.fail_count >= MAX_CODE_ATTEMPTS)
          throw new BadRequestException('Too many attempts');
        if (code.otp !== otp) {
          const failures = [
            ...recentActivationEvents(code.activation_failures, now),
            now,
          ];
          await tx.user_otp_email.update({
            where: { id: code.id },
            data: {
              fail_count: { increment: 1 },
              activation_failures: failures,
            },
          });
          // Return the error so the transaction commits the failed attempt.
          const retry = activationAttemptRetry(failures, now);
          return {
            error: retry
              ? this.rateLimit(retry)
              : new BadRequestException(
                  code.fail_count + 1 >= MAX_CODE_ATTEMPTS
                    ? 'Too many attempts'
                    : 'Wrong activation code',
                ),
          };
        }
        const email = await this.activationEmail(tx, userId);
        if (
          code.delivery_recipient &&
          code.delivery_recipient !== email.address
        ) {
          throw new BadRequestException('Request a new activation code');
        }
        await tx.email.update({
          where: {
            email_id: email.email_id,
            address: email.address,
            primary_ind: Constants.primaryEmailFlag,
          },
          data: { status_id: Constants.verifiedEmailStatus, modify_date: now },
        });
        await tx.user.update({
          where: { user_id: userId },
          data: { status: MemberStatus.ACTIVE, modify_date: now },
        });
        await tx.user_otp_email.delete({ where: { id: code.id } });
        return { address: email.address };
      });
      if (outcome.error) throw outcome.error;
      primaryEmailAddress = outcome.address;

      // Update members.member status to ACTIVE
      try {
        await this.memberPrisma.member.update({
          where: { userId: Number(userId) },
          data: {
            status: MemberDbStatus.ACTIVE,
          },
        });
        this.logger.log(
          `Updated members.member for user ${userId}: status ACTIVE`,
        );
      } catch (err) {
        this.logger.error(
          `Failed to update members.member for user ${userId}: ${err.message}`,
          err.stack,
        );
        // Intentionally not throwing to avoid failing the main identity update
      }
    } catch (dbError) {
      if (dbError instanceof HttpException) throw dbError;
      this.logger.error(
        `Database error during activation for user ID ${userId}: ${dbError.message}`,
        dbError.stack,
      );
      throw new InternalServerErrorException(
        'Failed to activate user due to a database error.',
      );
    }

    try {
      const user = await this.userService.findUserById(userId);
      // Use postEnvelopedNotification for standard events
      // whole user details sent not just userId
      await this.eventService.postEnvelopedNotification(
        'event.user.activated',
        {
          user: user,
        },
      );
      this.logger.log(`Published 'event.user.activated' event for ${userId}`);

      await this.userService.notifyWelcome(userId, primaryEmailAddress);

      // assign a default user role
      await this.userService.assignDefaultUserRole(userId);
    } catch (error) {
      this.logger.error(
        `Error tryting to publish events for user activation ${userId} or assigning default user role: ${error.message}`,
        error.stack,
      );
    }

    this.logger.log(`User ${userId} activated successfully.`);
    const activatedUser = await this.prismaClient.user.findUnique({
      where: { user_id: userId },
    });
    return activatedUser;
  }

  /**
   * Resend activation email.
   * @param resendDto Resend DTO request
   * @returns resulting message
   */
  async requestResendActivation({
    userId,
    resendToken,
  }: UserOtpDto): Promise<{ message: string; nextResendAt: string }> {
    if (!userId || !resendToken)
      throw new BadRequestException('User ID and resend token are required.');
    this.verifyActivationProof(userId, resendToken);
    return this.prismaClient.$transaction(async (tx) => {
      await this.lockUnverifiedUser(tx, userId);
      const where = {
        user_id_mode: { user_id: userId, mode: ACTIVATION_MODE },
      };
      const code = await tx.user_otp_email.findUnique({ where });
      const now = new Date();
      const sends = recentActivationEvents(code?.activation_sends || [], now);
      const failures = recentActivationEvents(
        code?.activation_failures || [],
        now,
      );
      const retryAt = nextActivationSend(sends, failures, now);
      if (retryAt) throw this.rateLimit(retryAt);
      const email = await this.activationEmail(tx, userId);
      sends.push(now);
      const replacement = {
        otp: newActivationCode(code?.otp),
        expire_at: new Date(now.getTime() + ACTIVATION_LIFETIME_MS),
        fail_count: 0,
        resend: true,
        activation_sends: sends,
        activation_failures: failures,
        delivery_due_at: now,
        delivery_recipient: email.address,
      };
      await tx.user_otp_email.upsert({
        where,
        create: { ...where.user_id_mode, ...replacement },
        update: replacement,
      });
      return {
        message: 'SUCCESS',
        nextResendAt: nextActivationSend(sends, failures, now).toISOString(),
      };
    });
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
    const user = await this.prismaClient.user.findUnique({
      where: { user_id: userId },
      select: { user_id: true, handle: true, status: true },
    });

    if (!user) {
      this.logger.warn(`generateOneTimeToken: User not found for ID ${userId}`);
      throw new NotFoundException('User not found.');
    }

    if (user.status != MemberStatus.ACTIVE) {
      this.logger.warn(
        `generateOneTimeToken: User ${user.handle} (ID: ${userId}) is not active (status: ${user.status}).`,
      );
      throw new ForbiddenException('User account is not active.');
    }

    // 2. Fetch Encrypted Password from security_user using the user's handle
    const securityUserRecord = await this.prismaClient.security_user.findUnique(
      {
        where: { user_id: user.handle }, // security_user.user_id is the user handle
        select: { password: true },
      },
    );

    if (!securityUserRecord || !securityUserRecord.password) {
      this.logger.error(
        `generateOneTimeToken: Security record or password not found for user handle ${user.handle} (ID: ${userId})`,
      );
      throw new InternalServerErrorException(
        'User security information not found.',
      );
    }

    // Verify Password
    const passwordsMatching = this.userService.verifyLegacyPassword(
      passwordPlain,
      securityUserRecord.password,
    );

    // Compare Passwords
    if (!passwordsMatching) {
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
    return token as string;
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
      decodedPayload = verifySignedJwt(token, this.jwtSecret, {
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
    await this.validationService.validateEmail(newEmail, userId);

    // 4. Prisma Transaction: Update email - SIMPLIFIED TO JUST UPDATE THE EXISTING PRIMARY EMAIL
    await this.prismaClient.$transaction(async (prisma) => {
      const newEmailLower = newEmail.toLowerCase();

      // Find the user first
      const userInDB = await prisma.user.findUnique({
        where: { user_id: userId },
      });

      if (!userInDB) {
        throw new NotFoundException(`User ${userId} not found.`);
      }

      // Find the current primary email for the user
      const currentPrimaryEmail = await prisma.email.findFirst({
        where: {
          user_id: userId,
          primary_ind: Constants.primaryEmailFlag,
          email_type_id: Constants.standardEmailType,
        },
      });

      if (!currentPrimaryEmail) {
        throw new NotFoundException(
          `No primary email found for user ${userId}.`,
        );
      }

      const oldEmail = currentPrimaryEmail.address;

      // If the new email is the same as current, no need to update
      if (oldEmail === newEmailLower) {
        this.logger.log(
          `Email ${newEmail} is already the primary email for user ${userId}. No changes needed.`,
        );
        return;
      }

      // Check if new email is already taken by another user as primary
      const existingEmailRecord = await prisma.email.findFirst({
        where: {
          address: newEmailLower,
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
      await prisma.email.update({
        where: { email_id: currentPrimaryEmail.email_id },
        data: {
          address: newEmailLower,
          // status_id: new Decimal(1), // Set to verified status since token was validated
          modify_date: new Date(),
        },
      });

      this.logger.log(
        `Updated existing primary email record ${currentPrimaryEmail.email_id.toNumber()} from ${oldEmail} to ${newEmailLower} for user ${userId} (verified via token)`,
      );

      // Update the user record
      await prisma.user.update({
        where: { user_id: userId },
        data: {
          modify_date: new Date(),
        },
      });

      this.logger.log(
        `Primary email updated to ${newEmail} for user ${userId}.`,
      );
    });

    // 4b. Update members.member status to ACTIVE and email to the new value
    try {
      const newEmailLower = newEmail.toLowerCase();
      await this.memberPrisma.member.update({
        where: { userId: Number(userId) },
        data: {
          status: MemberDbStatus.ACTIVE,
          email: newEmailLower,
        },
      });
      this.logger.log(
        `Updated members.member for user ${userId}: status ACTIVE and email ${newEmailLower}.`,
      );
    } catch (err) {
      this.logger.error(
        `Failed to update members.member for user ${userId}: ${err.message}`,
        err.stack,
      );
      // Intentionally not throwing to avoid failing the main identity update
    }

    // 5. Publish user.updated event
    try {
      const user = await this.prismaClient.user.findUnique({
        where: { user_id: userId },
      });
      if (user) {
        // Use postEnvelopedNotification for standard events
        await this.eventService.postEnvelopedNotification(
          'event.user.updated',
          {
            userId: userId.toString(),
            handle: user.handle,
            email: newEmail, // This is the new email being set
          },
        );
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

  async initiatePasswordReset(
    emailOrHandle: string,
    resetPasswordUrlPrefix?: string,
    source?: string,
  ): Promise<any> {
    if (typeof emailOrHandle !== 'string' || emailOrHandle.length === 0) {
      throw new BadRequestException('Email or handle is required.');
    }
    this.logger.log(`Initiating password reset for: ${emailOrHandle}`);

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
        `User ${user.user_id.toNumber()} is an SSO user. Password reset via this flow is not allowed.`,
      );
      throw new ForbiddenException(
        'Password reset is not allowed for SSO-linked accounts.',
      );
    }

    const resetTokenCacheKey = `${PASSWORD_RESET_TOKEN_CACHE_PREFIX}:${user.user_id.toNumber()}`;
    const existingCachedToken =
      await this.cacheManager.get<string>(resetTokenCacheKey);
    if (existingCachedToken) {
      this.logger.warn(
        `Password reset token already issued for user ${user.user_id.toNumber()}.`,
      );
      // Java logic threw an error here. Adhering to that.
      throw new ConflictException(
        'Password reset token has already been issued. Please check your email or wait for it to expire.',
      );
    }

    const resetToken = CommonUtils.generateAlphaNumericString(
      PASSWORD_RESET_TOKEN_LENGTH,
    );
    const expirySeconds = this.resetTokenExpirySeconds;
    await this.cacheManager.set(
      resetTokenCacheKey,
      resetToken,
      expirySeconds * 1000,
    );
    this.logger.log(
      `Password reset token generated and cached for user ${user.user_id.toNumber()}`,
    );

    const finalResetUrlPrefix = this.getResetPasswordUrlPrefix(
      resetPasswordUrlPrefix,
      source,
    );

    // Ensure user has a primary email to send the reset link to
    const primaryEmailAddress = user.primaryEmail?.address;
    if (!primaryEmailAddress) {
      this.logger.error(
        `Password reset initiated for user ${user.user_id.toNumber()} (${user.handle}), but no primary email address is associated. Cannot send email.`,
      );
      // Do not throw an error to prevent user enumeration, but log that email cannot be sent.
      return;
    }

    const expiryDateFormat = "HH:mm:ss z 'on' yyyy-MM-dd";
    const expiryDateStr = format(
      addSeconds(new Date(), this.resetTokenExpirySeconds * 1000),
      expiryDateFormat,
      {
        timeZone: 'America/New_York',
      },
    );

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
        user: user,
        token: resetToken,
        expiry: expiryDateStr,
        resetPassworUrlPrefix: finalResetUrlPrefix,
        subject: 'Your Topcoder Password Reset Request', // Retaining from previous logic
        from:
          this.configService.get<string>('EVENT_DEFAULT_SENDER_EMAIL') ||
          'noreply@topcoder-dev.com', // Retaining from previous logic
        // Any other fields that were part of MailRepresentation.data
      },
      version: 'v6', // Retaining from previous logic, was part of MailRepresentation
      // Optional fields from MailRepresentation, if applicable
      cc: [],
      bcc: [],
    };

    this.logger.log(
      `[AuthFlowService] Preparing to send 'userpasswordreset' notification for user ${user.user_id.toNumber()}`,
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
        `Password reset notification ('userpasswordreset') published for user ${user.user_id.toNumber()}`,
      );
    } catch (eventError) {
      this.logger.error(
        `Failed to publish password reset event (to event.notification.send) for user ${user.user_id.toNumber()}: ${eventError.message}`,
        eventError.stack,
      );
      // Depending on business requirements, you might want to re-throw or handle this error differently.
      // For example, if email is critical, this could be a hard failure.
    }

    return user;
  }

  /**
   * Sanitized reset password URL prefix
   * @param resetPasswordUrlPrefix Provided URL prefix
   * @param source Source of request
   * @returns actual URL that can be used
   */
  private getResetPasswordUrlPrefix(
    resetPasswordUrlPrefix: string,
    source: string,
  ): string {
    if (
      typeof resetPasswordUrlPrefix === 'string' &&
      CommonUtils.validateString(resetPasswordUrlPrefix)
    ) {
      try {
        const parsedUrl = new URL(resetPasswordUrlPrefix);
        const hostname = parsedUrl.hostname.toLowerCase();
        const approvedHost = ['topcoder.com', 'topcoder-dev.com'].some(
          (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
        );
        if (
          parsedUrl.protocol === 'https:' &&
          approvedHost &&
          !parsedUrl.username &&
          !parsedUrl.password
        ) {
          return resetPasswordUrlPrefix;
        }
      } catch {
        // Invalid or unapproved values use the configured safe default below.
      }
    }

    const domain = CommonUtils.validateString(this.authDomain)
      ? this.authDomain
      : 'topcoder.com';
    return typeof source === 'string' &&
      CommonUtils.validateString(source) &&
      source.toLocaleLowerCase() === 'connect'
      ? `https://connect.${domain}/reset-password`
      : `https://www.${domain}/reset-password`;
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
        reg_source: true;
        utm_source: true;
        utm_medium: true;
        utm_campaign: true;
        activation_code: true;
      };
    }>;

    let userRecord: UserForAuth0 | null = null;
    let userId: number | null = null;
    let userHandle: string | null = null; // Store handle separately

    // 1. Find User Record (without password)
    if (isEmail) {
      const emailRecord = await this.prismaClient.email.findFirst({
        where: {
          address: { equals: handleOrEmail, mode: 'insensitive' },
          primary_ind: Constants.primaryEmailFlag,
        }, // Ensure it's the primary email
        select: { user_id: true },
      });

      if (emailRecord) {
        userId = emailRecord.user_id.toNumber();
        userRecord = await this.prismaClient.user.findUnique({
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
            reg_source: true,
            utm_source: true,
            utm_medium: true,
            utm_campaign: true,
            activation_code: true,
          },
        });
        if (userRecord) {
          userHandle = userRecord.handle;
        }
      }
    } else {
      // Find user by handle
      userRecord = await this.prismaClient.user.findFirst({
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
          reg_source: true,
          utm_source: true,
          utm_medium: true,
          utm_campaign: true,
          activation_code: true,
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
      const primaryEmailRecord = await this.prismaClient.email.findFirst({
        where: { user_id: userId, primary_ind: Constants.primaryEmailFlag },
        select: { address: true, status_id: true },
      });
      if (primaryEmailRecord) {
        primaryEmail = primaryEmailRecord.address;
        emailVerified =
          primaryEmailRecord.status_id.toNumber() ===
          Constants.verifiedEmailStatus;
      }
    }

    if (!userRecord || !userId || !userHandle) {
      // Check all necessary identifiers
      this.logger.warn(`Auth0 Custom DB: User not found for ${handleOrEmail}`);
      throw new UnauthorizedException('Invalid credentials.');
    }

    if (
      userRecord.status != MemberStatus.ACTIVE &&
      userRecord.status != MemberStatus.UNVERIFIED
    ) {
      this.logger.warn(
        `Auth0 Custom DB: Account for ${handleOrEmail} (ID: ${userId}) is deactivated (status: ${userRecord.status}).`,
      );
      throw new UnauthorizedException('Account is deactivated.');
    }
    // 2. Fetch Encrypted Password from security_user using the handle
    const securityUserRecord = await this.prismaClient.security_user.findUnique(
      {
        where: { user_id: userHandle }, // Java logic uses handle as security_user.user_id
        select: { password: true },
      },
    );

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

    // Verify Password
    const passwordsMatching = this.userService.verifyLegacyPassword(
      passwordPlain,
      securityUserRecord.password,
    );

    // Compare Passwords
    if (!passwordsMatching) {
      this.logger.warn(
        `Auth0 Custom DB: Password mismatch for ${userHandle} (ID: ${userId})`,
      );
      throw new UnauthorizedException('Invalid credentials.');
    }

    if (userRecord.status !== MemberStatus.ACTIVE || !emailVerified) {
      throw new ForbiddenException({
        code: 'EMAIL_VERIFICATION_REQUIRED',
        message: 'Activate your account before logging in.',
      });
    }

    // Password matches, proceed with profile generation
    this.logger.log(
      `Auth0 Custom DB: Password validated for ${userHandle} (ID: ${userId})`,
    );

    // Fetch roles (as before)
    const roles = await this.roleService.findAll(userId);

    // Construct the profile object for Auth0 (same structure as before)
    const auth0Profile = {
      id: userId.toString(),
      email: primaryEmail?.toLowerCase(),
      emailActive: emailVerified,
      firstName: userRecord.first_name || '' || undefined,
      lastName: userRecord.last_name || '' || undefined,
      handle: userHandle,
      roles: roles,
      status: userRecord.status,
      mfaEnabled: userRecord.user_2fa?.mfa_enabled ?? false,
      diceEnabled: userRecord.user_2fa?.dice_enabled ?? false,
      last_login: userRecord.last_login?.toISOString(),
      createdAt: userRecord.create_date?.toISOString(),
      modifiedAt: userRecord.modify_date?.toISOString(),
      regSource: userRecord.reg_source,
      utmSource: userRecord.utm_source,
      utmMedium: userRecord.utm_medium,
      utmCampaign: userRecord.utm_campaign,
      active: userRecord.status == MemberStatus.ACTIVE,
      country: null, // FIXME where to map
      profile: null,
      profiles: null,
      credential: {
        activationCode: userRecord.activation_code,
        resetToken: null,
        resendToken: null,
        activationBlocked: null,
        canResend: null,
        hasPassword: true, // at this point, we are sure user has password (and been validated)
      },
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
        first_name: true;
        last_name: true;
        reg_source: true;
        last_login: true;
        user_2fa: true; // Keep 2FA info
        utm_source: true;
        utm_medium: true;
        utm_campaign: true;
        create_date: true;
        modify_date: true;
        activation_code: true;
      };
    }> | null = null;
    let userIdNumber: number | null = null;

    if (isEmail) {
      // 1. Find email to get user_id
      const emailRecord = await this.prismaClient.email.findFirst({
        where: { address: { equals: handleOrEmail, mode: 'insensitive' } },
        select: { user_id: true },
      });
      if (emailRecord) {
        userIdNumber = emailRecord.user_id.toNumber();
        // 2. Find user by user_id
        user = await this.prismaClient.user.findUnique({
          where: { user_id: userIdNumber },
          select: {
            user_id: true,
            handle: true,
            status: true,
            first_name: true,
            last_name: true,
            reg_source: true,
            last_login: true,
            user_2fa: true,
            utm_source: true,
            utm_medium: true,
            utm_campaign: true,
            create_date: true,
            modify_date: true,
            activation_code: true,
          },
        });
      }
    } else {
      // Find user by handle
      user = await this.prismaClient.user.findFirst({
        where: { handle_lower: handleOrEmail.toLowerCase() },
        select: {
          user_id: true,
          handle: true,
          status: true,
          first_name: true,
          last_name: true,
          reg_source: true,
          last_login: true,
          user_2fa: true,
          utm_source: true,
          utm_medium: true,
          utm_campaign: true,
          create_date: true,
          modify_date: true,
          activation_code: true,
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
    const primaryEmailRecord = await this.prismaClient.email.findFirst({
      where: { user_id: userIdNumber, primary_ind: Constants.primaryEmailFlag },
      select: { address: true, status_id: true },
    });
    const primaryEmail = primaryEmailRecord?.address;
    const emailVerified =
      primaryEmailRecord?.status_id?.toNumber() ===
      Constants.verifiedEmailStatus;

    // check credentials
    const securityUserRecord = await this.prismaClient.security_user.findUnique(
      {
        where: { user_id: user.handle }, // Java logic uses handle as security_user.user_id
        select: { password: true },
      },
    );

    // reg source, similar to java code, set directly with ssoToken
    const token =
      user.status === MemberStatus.ACTIVE && emailVerified
        ? await this.userService.generateSSOToken(userIdNumber)
        : null;

    const response: any = {
      id: user.user_id.toString(),
      handle: user.handle,
      firstName: user.first_name,
      lastName: user.last_name,
      email: primaryEmail,
      roles: roles, // return as full role objects
      emailActive: emailVerified, // Use status from email table
      status: user.status,
      regSource: token,
      mfaEnabled: user.user_2fa?.mfa_enabled ?? false,
      diceEnabled: user.user_2fa?.dice_enabled ?? false,
      last_login: user.last_login?.toISOString(),
      createdAt: user.create_date?.toISOString(),
      modifiedAt: user.modify_date?.toISOString(),
      utmSource: user.utm_source,
      utmMedium: user.utm_medium,
      utmCampaign: user.utm_campaign,
      active: user.status == MemberStatus.ACTIVE,
      country: '', // FIXME where to map
      profile: null,
      profiles: null,
      credential: {
        activationCode: user.activation_code,
        resetToken: null, // not used here
        resendToken: null, // default, if status 'U', gets updated below
        activationBlocked: null,
        canResend: null, // default, if status 'U', gets updated below
        hasPassword:
          securityUserRecord && securityUserRecord.password ? true : false,
      },
    };

    if (user.status == MemberStatus.UNVERIFIED) {
      const activation = await this.prismaClient.user_otp_email.findUnique({
        where: {
          user_id_mode: { user_id: user.user_id, mode: ACTIVATION_MODE },
        },
        select: {
          fail_count: true,
          expire_at: true,
          delivery_recipient: true,
          activation_sends: true,
          activation_failures: true,
        },
      });
      const now = new Date();
      let state = 'valid';
      if (
        !activation ||
        activation.fail_count >= MAX_CODE_ATTEMPTS ||
        (activation.delivery_recipient &&
          activation.delivery_recipient !== primaryEmail)
      ) {
        state = 'replacement_required';
      } else if (activation.expire_at <= now) {
        state = 'expired';
      }
      response.credential.activationCodeState = state;
      response.credential.canResend = true;
      response.credential.nextResendAt = nextActivationSend(
        activation?.activation_sends || [],
        activation?.activation_failures || [],
        now,
      )?.toISOString();
      // set resend token. similar to java code, line 874 of UserResource.java
      const payload = {
        sub: user.user_id.toString(),
        userId: user.user_id.toString(),
        aud: OTP_ACTIVATION_JWT_AUDIENCE,
      };
      response.credential.resendToken = jwt.sign(payload, this.jwtSecret, {
        expiresIn: `${this.activationResendExpirySeconds}s`,
      });
      this.logger.log(
        `Auth0 Roles: User ${user.handle} is unverified. Added credential details.`,
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

    this.validationService.validatePassword(newPasswordPlain);

    const user = await this.userService.findUserByEmail(email); // Ensure this finds by primary email effectively
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

    // Encrypt the new password using the legacy Blowfish method from UserService
    const legacyEncodedPassword =
      this.userService.encodePasswordLegacy(newPasswordPlain);
    this.logger.debug(
      `Auth0 Action: New password encoded using legacy method for user ${user.handle}.`,
    );

    // Update the password in the security_user table using the user's handle
    await this.prismaClient.security_user.update({
      where: { user_id: user.handle }, // Find security_user record by handle
      data: { password: legacyEncodedPassword },
    });

    // Also update the modify_date on the main user record
    await this.prismaClient.user.update({
      where: { user_id: user.user_id.toNumber() },
      data: { modify_date: new Date() },
    });

    this.logger.log(
      `Auth0 Action: Password successfully changed for user ${user.handle}.`,
    );
    return { message: 'Password changed successfully.' };
  }

  /**
   * Insert User OTP similar to java.
   * @param userId User Id
   * @param mode Mode. If otpActivationMode or otp2faMode
   * @param otp The OTP
   * @param resend If allowed to resend
   * @param failCount Failure counts
   * @param expireAt Expires at
   */
  async insertUserOtp(
    userId: number,
    mode: number,
    otp: string,
    resend: boolean,
    failCount: number,
    expireAt: Date,
  ): Promise<void> {
    try {
      await this.prismaClient.user_otp_email.create({
        data: {
          user_id: userId,
          mode: mode,
          otp: otp,
          resend: resend,
          fail_count: failCount,
          expire_at: expireAt,
        },
      });
    } catch (error) {
      if (error.code === Constants.prismaUniqueConflictcode) {
        this.logger.warn(
          `Attempt to create otp for user ${userId} which already exists in mode ${mode}.`,
        );
        throw new ConflictException(
          `OTP email already exist for user ${userId} in mode ${mode}.`,
        );
      } else {
        this.logger.error(
          `Failed to create otp for user ${userId} in mode ${mode}: ${error.message}`,
          error.stack,
        );
        throw error;
      }
    }
  }

  /**
   * Updates user otp.
   * @param id The row id
   * @param userId User id
   * @param otp The new otp
   * @param resend New value for resend
   * @param failCount New value for fail count
   * @param expireAt New expires at
   */
  async updateUserOtp(
    id: number,
    userId: number,
    otp: string,
    resend: boolean,
    failCount: number,
    expireAt: Date,
  ): Promise<void> {
    try {
      await this.prismaClient.user_otp_email.update({
        where: { id: id },
        data: {
          otp: otp,
          user_id: userId,
          resend: resend,
          fail_count: failCount,
          expire_at: expireAt,
        },
      });
    } catch (error) {
      this.logger.error(
        `Failed to update otp for id ${id}: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  /**
   * Find User OTP Email by user ID and mode.  Primary email is required for user.  OTP email may not exist.
   * @param userId User ID
   * @param mode Mode to look for
   * @returns user details with otp email if exists
   * @throws NotFoundException when user not found or does not have primary email
   * @throws InternalServerErrorException when other errors occur
   */
  async findUserOtpEmailByUserId(
    userId: number,
    mode: number,
  ): Promise<UserOtpDto | null> {
    try {
      // like in UserDAO.findUserOtpEmailByUserId(), we want to ensure user exists with primary email
      const user = await this.prismaClient.user.findFirst({
        where: {
          user_id: userId,
          emails: {
            some: {
              email_type_id: Constants.standardEmailType,
              primary_ind: Constants.primaryEmailFlag,
            },
          },
        },
        select: {
          user_id: true,
          handle: true,
          status: true,
          emails: {
            select: {
              address: true,
            },
          },
        },
      });

      if (!user) {
        throw new NotFoundException('User does not exist');
      }

      // get user_otp_email if it exists, we won't error out if it does not exist
      const userOtpEmail = await this.prismaClient.user_otp_email.findFirst({
        where: {
          user_id: userId,
          mode: mode,
        },
        select: {
          id: true,
          otp: true,
          expire_at: true,
          resend: true,
          fail_count: true,
        },
      });

      // verify if there is user otp from db
      return {
        id: userOtpEmail?.id,
        userId: Number(user.user_id.toString()),
        handle: user.handle,
        status: user.status,
        email:
          Array.isArray(user.emails) && user.emails.length > 0
            ? user.emails[0].address
            : null,
        otp: userOtpEmail?.otp,
        expireAt: userOtpEmail?.expire_at,
        resend: userOtpEmail?.resend,
        failCount: userOtpEmail?.fail_count,
      };
    } catch (error) {
      if (error instanceof NotFoundException) {
        // rethrow not found exception (user not found)
        throw error;
      }
      throw new InternalServerErrorException('Failed to search for user otp');
    }
  }

  /**
   * Find User OTP by user ID and mode.
   * @param userId User ID
   * @param mode OTP mode
   * @returns UserOtpDto when found
   * @throws NotFoundException when user not found
   * @throws InternalServerErrorException when other errors occur
   */
  async findUserOtpByUserId(
    userId: number,
    mode: number,
  ): Promise<UserOtpDto | null> {
    try {
      const user = await this.prismaClient.user.findFirst({
        where: {
          user_id: userId,
        },
        select: {
          user_id: true,
          handle: true,
          status: true,
        },
      });

      if (!user) {
        throw new NotFoundException('User does not exist');
      }

      // get user_otp_email if it exists, we won't error out if it does not exist
      const userOtpEmail = await this.prismaClient.user_otp_email.findFirst({
        where: {
          user_id: userId,
          mode: mode,
        },
        select: {
          id: true,
          otp: true,
          expire_at: true,
          resend: true,
          fail_count: true,
        },
      });

      return {
        id: userOtpEmail?.id,
        userId: Number(user.user_id.toString()),
        handle: user.handle,
        status: user.status,
        otp: userOtpEmail?.otp,
        expireAt: userOtpEmail?.expire_at,
        resend: userOtpEmail?.resend,
        failCount: userOtpEmail?.fail_count,
      };
    } catch (error) {
      if (error instanceof NotFoundException) {
        // rethrow not found exception (user not found)
        throw error;
      }
      throw new InternalServerErrorException('Failed to search for user otp');
    }
  }

  /**
   * Updates user OTP with new duration and resend flag.
   * @param id ID of user otp email
   * @param duration New duration
   * @param resend Resend flag
   * @throws InternalServerErrorException When an error occurs updating user otp email
   */
  async updateUserOtpResend(id: number, duration: Date, resend: boolean) {
    try {
      await this.prismaClient.user_otp_email.update({
        where: {
          id: id,
        },
        data: {
          expire_at: duration,
          resend: resend,
        },
      });
    } catch (error) {
      this.logger.error(
        `Error updating user otp email: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error updating user otp email');
    }
  }

  /**
   * Update user OTP attempts
   * @param id OTP ID
   * @param failCount New fail count
   * @throws InternalServerErrorException When an error occurs updating user otp email
   */
  async updateUserOtpAttempt(id: number, failCount: number) {
    try {
      await this.prismaClient.user_otp_email.update({
        where: {
          id: id,
        },
        data: {
          fail_count: failCount,
        },
      });
    } catch (error) {
      this.logger.error(
        `Error updating user otp email fail count: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        "Error updating 'user otp email' fail count",
      );
    }
  }

  /**
   * Resets password for user, given the reset token and new password.
   * @param passUserDto The reset password DTO
   * @returns user when password reset is successful
   * @throws BadRequestException when validation fails
   * @throws NotFoundException when user not found
   * @throws InternalServerErrorException when other errors occur
   */
  async resetPassword(passUserDto: ResetPasswordBodyDto): Promise<UserModel> {
    const userParams = passUserDto.param;
    const { handle, email, credential } = userParams;
    // validate password
    this.validationService.validatePassword(credential?.password);
    // validate token
    if (!credential || !credential.resetToken) {
      throw new BadRequestException('Token is required.');
    }
    // find user
    let user: UserModel | null = null;
    // first by handle
    if (CommonUtils.validateString(handle)) {
      user = await this.userService.findUserByEmailOrHandle(handle);
    }
    // then by email
    if (!user && CommonUtils.validateString(email)) {
      user = await this.userService.findUserByEmailOrHandle(email);
    }
    if (!user) {
      throw new NotFoundException('User does not exist');
    }

    // get cache key
    const resetTokenCacheKey = `${PASSWORD_RESET_TOKEN_CACHE_PREFIX}:${user.user_id.toNumber()}`;
    const existingCachedToken =
      await this.cacheManager.get<string>(resetTokenCacheKey);
    if (!existingCachedToken) {
      throw new BadRequestException('Token is expired');
    }
    // compare with request
    if (existingCachedToken !== credential.resetToken) {
      throw new BadRequestException('Token is incorrect');
    }

    try {
      // now update password
      // Encrypt the new password using the legacy Blowfish method from UserService
      const legacyEncodedPassword = this.userService.encodePasswordLegacy(
        credential.password,
      );
      // Update the password in the security_user table using the user's handle
      await this.prismaClient.security_user.update({
        where: { user_id: user.handle }, // Find security_user record by handle
        data: { password: legacyEncodedPassword },
      });
    } catch (error) {
      this.logger.error(
        `Failed to update password for user ${user.handle}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Failed to update password');
    }

    // delete the token from cache
    await this.cacheManager.del(resetTokenCacheKey);
    // return user as per java code
    return user;
  }
}
