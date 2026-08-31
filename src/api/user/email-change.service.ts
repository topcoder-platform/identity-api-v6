import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  BadRequestException,
  ForbiddenException,
  GoneException,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { Cache } from 'cache-manager';
import { ConfigService } from '@nestjs/config';
import { createHmac, randomInt, randomUUID, timingSafeEqual } from 'crypto';
import * as jwt from 'jsonwebtoken';

import { Constants } from '../../core/constant/constants';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import { MemberStatus } from '../../dto/member';
import { CommonUtils } from '../../shared/util/common.utils';
import { EventService } from '../../shared/event/event.service';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { PrismaClient } from '@prisma/client';
import { UserService } from './user.service';
import { ValidationService } from './validation.service';

const EMAIL_CHANGE_OTP_CACHE_PREFIX = 'EMAIL_CHANGE_OTP';
const EMAIL_CHANGE_PROOF_CACHE_PREFIX = 'EMAIL_CHANGE_PROOF';
const EMAIL_CHANGE_PENDING_CACHE_PREFIX = 'EMAIL_CHANGE_PENDING';
const EMAIL_CHANGE_CURRENT_EMAIL_AUDIENCE = 'email_change_current_email';
const EMAIL_CHANGE_NEW_EMAIL_AUDIENCE = 'email_change_new_email';
const EMAIL_CHANGE_NOTIFICATION_TOPIC =
  'member.action.email.profile.emailchange.verification';
const DEFAULT_OTP_EXPIRY_SECONDS = 10 * 60;
const DEFAULT_OTP_RESEND_SECONDS = 60;
const DEFAULT_PROOF_EXPIRY_SECONDS = 10 * 60;
const DEFAULT_VALIDATION_EXPIRY_SECONDS = 60 * 60;
const MAX_OTP_ATTEMPTS = 5;

interface CachedOtp {
  attempts: number;
  currentEmail: string;
  expiresAt: number;
  hash: string;
  issuedAt: number;
}

interface CurrentEmailProof {
  currentEmail: string;
  userId: string;
}

interface PendingEmailChange {
  currentEmail: string;
  email: string;
  userId: string;
}

interface EmailChangeJwtPayload extends jwt.JwtPayload {
  jti?: string;
  sub?: string;
}

/**
 * Coordinates the member self-service email change flow.
 *
 * The service verifies ownership of the current primary email with a short-lived
 * OTP, issues a one-time proof for the requested change, emails a validation link
 * to the new address, and applies the existing admin email update only after that
 * link is validated.
 */
@Injectable()
export class EmailChangeService {
  private readonly logger = new Logger(EmailChangeService.name);
  private readonly jwtSecret: string;
  private readonly otpExpirySeconds: number;
  private readonly otpResendSeconds: number;
  private readonly proofExpirySeconds: number;
  private readonly validationExpirySeconds: number;

  constructor(
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient,
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache,
    private readonly configService: ConfigService,
    private readonly eventService: EventService,
    private readonly userService: UserService,
    private readonly validationService: ValidationService,
  ) {
    this.jwtSecret = this.configService.get<string>('JWT_SECRET') || '';
    this.otpExpirySeconds = this.getPositiveIntegerConfig(
      'EMAIL_CHANGE_OTP_EXPIRY_SECONDS',
      DEFAULT_OTP_EXPIRY_SECONDS,
    );
    this.otpResendSeconds = this.getPositiveIntegerConfig(
      'EMAIL_CHANGE_OTP_RESEND_SECONDS',
      DEFAULT_OTP_RESEND_SECONDS,
    );
    this.proofExpirySeconds = this.getPositiveIntegerConfig(
      'EMAIL_CHANGE_PROOF_EXPIRY_SECONDS',
      DEFAULT_PROOF_EXPIRY_SECONDS,
    );
    this.validationExpirySeconds = this.getPositiveIntegerConfig(
      'EMAIL_CHANGE_VALIDATION_EXPIRY_SECONDS',
      DEFAULT_VALIDATION_EXPIRY_SECONDS,
    );

    if (!this.jwtSecret) {
      throw new InternalServerErrorException(
        'Email change service is not properly configured.',
      );
    }
  }

  /**
   * Sends a six-digit ownership code to the user's current primary email.
   * @param userIdString ID of the member requesting an email change.
   * @returns the number of seconds before the code expires.
   * @throws BadRequestException for an invalid user ID or inactive account.
   * @throws NotFoundException when the user or primary email does not exist.
   */
  async sendCurrentEmailOtp(
    userIdString: string,
  ): Promise<{ expiresIn: number }> {
    const userId = this.parseUserId(userIdString);
    const cacheKey = this.getOtpCacheKey(userIdString);
    const existingOtp = await this.cacheManager.get<CachedOtp>(cacheKey);
    const now = Date.now();
    const resendAt = existingOtp
      ? existingOtp.issuedAt + this.otpResendSeconds * 1000
      : 0;
    if (
      existingOtp &&
      existingOtp.expiresAt > now &&
      resendAt > now
    ) {
      const retryAfter = Math.ceil((resendAt - now) / 1000);
      throw new HttpException(
        `Wait ${retryAfter} seconds before requesting another code.`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const user = await this.prismaClient.user.findUnique({
      where: { user_id: userId },
      select: { handle: true, status: true },
    });

    if (!user) {
      throw new NotFoundException('User does not exist.');
    }
    if (user.status !== MemberStatus.ACTIVE) {
      throw new BadRequestException(
        'Only active users can change their email address.',
      );
    }

    const currentPrimaryEmail = await this.prismaClient.email.findFirst({
      where: {
        user_id: userId,
        primary_ind: Constants.primaryEmailFlag,
        email_type_id: Constants.standardEmailType,
      },
      select: { address: true },
    });

    if (!currentPrimaryEmail?.address) {
      throw new NotFoundException('Primary email not found for the user.');
    }

    const otp = randomInt(0, 1_000_000).toString().padStart(6, '0');
    const issuedAt = Date.now();
    const expiresAt = issuedAt + this.otpExpirySeconds * 1000;
    await this.cacheManager.set<CachedOtp>(
      cacheKey,
      {
        attempts: 0,
        currentEmail: currentPrimaryEmail.address.trim().toLowerCase(),
        expiresAt,
        hash: this.hashOtp(otp),
        issuedAt,
      },
      this.otpExpirySeconds * 1000,
    );

    try {
      await this.sendOtpEmail(
        user.handle,
        currentPrimaryEmail.address,
        otp,
      );
    } catch (error) {
      await this.cacheManager.del(cacheKey);
      throw error;
    }

    return { expiresIn: this.otpExpirySeconds };
  }

  /**
   * Verifies the current-email OTP and returns a short-lived one-time proof.
   * @param userIdString ID of the member who requested the code.
   * @param otp six-digit code delivered to the current primary email.
   * @returns a proof token and its lifetime in seconds.
   * @throws BadRequestException when the code is wrong or too many attempts were made.
   * @throws GoneException when the code expired or is no longer available.
   */
  async verifyCurrentEmailOtp(
    userIdString: string,
    otp: string,
  ): Promise<{ expiresIn: number; verificationToken: string }> {
    this.parseUserId(userIdString);
    const cacheKey = this.getOtpCacheKey(userIdString);
    const cachedOtp = await this.cacheManager.get<CachedOtp>(cacheKey);

    if (!cachedOtp || cachedOtp.expiresAt <= Date.now()) {
      await this.cacheManager.del(cacheKey);
      throw new GoneException(
        'The verification code has expired. Request a new code.',
      );
    }
    if (cachedOtp.attempts >= MAX_OTP_ATTEMPTS) {
      await this.cacheManager.del(cacheKey);
      throw new BadRequestException(
        'Too many incorrect attempts. Request a new code.',
      );
    }

    const expectedHash = Buffer.from(cachedOtp.hash, 'hex');
    const suppliedHash = Buffer.from(this.hashOtp(otp), 'hex');
    if (
      expectedHash.length !== suppliedHash.length ||
      !timingSafeEqual(expectedHash, suppliedHash)
    ) {
      const attempts = cachedOtp.attempts + 1;
      if (attempts >= MAX_OTP_ATTEMPTS) {
        await this.cacheManager.del(cacheKey);
        throw new BadRequestException(
          'Too many incorrect attempts. Request a new code.',
        );
      }

      await this.cacheManager.set<CachedOtp>(
        cacheKey,
        { ...cachedOtp, attempts },
        Math.max(cachedOtp.expiresAt - Date.now(), 1),
      );
      throw new BadRequestException('The verification code is incorrect.');
    }

    await this.cacheManager.del(cacheKey);
    const jti = randomUUID();
    const verificationToken = jwt.sign(
      {
        aud: EMAIL_CHANGE_CURRENT_EMAIL_AUDIENCE,
        jti,
        sub: userIdString,
      },
      this.jwtSecret,
      { expiresIn: this.proofExpirySeconds },
    );
    await this.cacheManager.set<CurrentEmailProof>(
      this.getProofCacheKey(jti),
      {
        currentEmail: cachedOtp.currentEmail,
        userId: userIdString,
      },
      this.proofExpirySeconds * 1000,
    );

    return {
      expiresIn: this.proofExpirySeconds,
      verificationToken,
    };
  }

  /**
   * Starts validation of a new email after current-email ownership is proven.
   * @param userIdString ID of the member changing their email.
   * @param newEmail proposed new primary email address.
   * @param verificationToken one-time proof returned by verifyCurrentEmailOtp.
   * @returns the normalized address to which the validation email was sent.
   * @throws ForbiddenException when the proof is invalid, expired, or already used.
   * @throws BadRequestException when the new email is unchanged or invalid.
   */
  async initiateEmailChange(
    userIdString: string,
    newEmail: string,
    verificationToken: string,
  ): Promise<{ email: string }> {
    const userId = this.parseUserId(userIdString);
    const proof = this.verifyToken(
      verificationToken,
      EMAIL_CHANGE_CURRENT_EMAIL_AUDIENCE,
      'Current email verification has expired. Start again.',
    );
    if (proof.sub !== userIdString || !proof.jti) {
      throw new ForbiddenException('Current email verification is invalid.');
    }

    const proofCacheKey = this.getProofCacheKey(proof.jti);
    const cachedProof =
      await this.cacheManager.get<CurrentEmailProof>(proofCacheKey);
    if (!cachedProof || cachedProof.userId !== userIdString) {
      throw new ForbiddenException(
        'Current email verification has expired or was already used.',
      );
    }

    const normalizedEmail = newEmail.trim().toLowerCase();
    await this.validationService.validateEmail(normalizedEmail, userId);

    const [currentPrimaryEmail, user] = await Promise.all([
      this.prismaClient.email.findFirst({
        where: {
          user_id: userId,
          primary_ind: Constants.primaryEmailFlag,
          email_type_id: Constants.standardEmailType,
        },
        select: { address: true },
      }),
      this.prismaClient.user.findUnique({
        where: { user_id: userId },
        select: { handle: true },
      }),
    ]);

    if (!currentPrimaryEmail?.address || !user) {
      throw new NotFoundException('User primary email could not be found.');
    }
    const normalizedCurrentEmail = currentPrimaryEmail.address
      .trim()
      .toLowerCase();
    if (cachedProof.currentEmail !== normalizedCurrentEmail) {
      await this.cacheManager.del(proofCacheKey);
      throw new ForbiddenException(
        'The primary email changed after it was verified. Start again.',
      );
    }
    if (normalizedCurrentEmail === normalizedEmail) {
      throw new BadRequestException(
        'The new email must be different from the current email.',
      );
    }

    const validationJti = randomUUID();
    const validationToken = jwt.sign(
      {
        aud: EMAIL_CHANGE_NEW_EMAIL_AUDIENCE,
        jti: validationJti,
        sub: userIdString,
      },
      this.jwtSecret,
      { expiresIn: this.validationExpirySeconds },
    );
    const pendingCacheKey = this.getPendingCacheKey(validationJti);
    await this.cacheManager.set<PendingEmailChange>(
      pendingCacheKey,
      {
        currentEmail: normalizedCurrentEmail,
        email: normalizedEmail,
        userId: userIdString,
      },
      this.validationExpirySeconds * 1000,
    );

    try {
      await this.sendNewEmailValidation(
        user.handle,
        normalizedEmail,
        validationToken,
      );
      await this.cacheManager.del(proofCacheKey);
    } catch (error) {
      await this.cacheManager.del(pendingCacheKey);
      throw error;
    }

    return { email: normalizedEmail };
  }

  /**
   * Applies a pending email change after the new-address validation link is used.
   * @param validationToken signed token from the validation email.
   * @returns the normalized email that became primary.
   * @throws ForbiddenException when the token is invalid or no longer pending.
   * @throws GoneException when the validation token expired.
   */
  async completeEmailChange(
    validationToken: string,
  ): Promise<{ email: string }> {
    const validation = this.verifyToken(
      validationToken,
      EMAIL_CHANGE_NEW_EMAIL_AUDIENCE,
      'The email validation link has expired. Start the change again.',
    );
    if (!validation.sub || !validation.jti) {
      throw new ForbiddenException('The email validation link is invalid.');
    }

    const pendingCacheKey = this.getPendingCacheKey(validation.jti);
    const pending =
      await this.cacheManager.get<PendingEmailChange>(pendingCacheKey);
    if (
      !pending ||
      pending.userId !== validation.sub
    ) {
      throw new ForbiddenException(
        'The email validation link has expired or was already used.',
      );
    }

    const userId = this.parseUserId(validation.sub);
    const currentPrimaryEmail = await this.prismaClient.email.findFirst({
      where: {
        user_id: userId,
        primary_ind: Constants.primaryEmailFlag,
        email_type_id: Constants.standardEmailType,
      },
      select: { address: true },
    });
    if (!currentPrimaryEmail?.address) {
      throw new NotFoundException('Primary email not found for the user.');
    }
    if (
      currentPrimaryEmail.address.trim().toLowerCase() !== pending.currentEmail
    ) {
      await this.cacheManager.del(pendingCacheKey);
      throw new ForbiddenException(
        'The primary email changed while this request was pending. Start again.',
      );
    }

    const systemUser: AuthenticatedUser = {
      isAdmin: false,
      isMachine: false,
      payload: {},
      roles: [],
      scopes: [],
      userId: validation.sub,
    };
    await this.userService.updatePrimaryEmail(
      validation.sub,
      pending.email,
      systemUser,
    );
    await this.cacheManager.del(pendingCacheKey);

    this.logger.log(`Completed email change for user ${validation.sub}.`);
    return { email: pending.email };
  }

  /**
   * Reads a positive integer configuration value.
   * @param key configuration key to read.
   * @param fallback value used when the configured value is missing or invalid.
   * @returns the configured positive integer or the fallback.
   */
  private getPositiveIntegerConfig(key: string, fallback: number): number {
    const configuredValue = Number(this.configService.get<string>(key));
    return Number.isInteger(configuredValue) && configuredValue > 0
      ? configuredValue
      : fallback;
  }

  /**
   * Parses and validates a member ID.
   * @param userIdString member ID from an endpoint path.
   * @returns the positive integer user ID.
   * @throws BadRequestException when the value is not a positive integer.
   */
  private parseUserId(userIdString: string): number {
    const userId = Number(userIdString);
    if (!Number.isInteger(userId) || userId <= 0) {
      throw new BadRequestException('Invalid user ID format.');
    }
    return userId;
  }

  /**
   * Hashes an OTP before it is placed in shared cache.
   * @param otp six-digit ownership code.
   * @returns a keyed hexadecimal SHA-256 digest.
   */
  private hashOtp(otp: string): string {
    return createHmac('sha256', this.jwtSecret).update(otp).digest('hex');
  }

  /**
   * Builds the cache key for a member's current-email OTP.
   * @param userId member ID.
   * @returns namespaced OTP cache key.
   */
  private getOtpCacheKey(userId: string): string {
    return `${EMAIL_CHANGE_OTP_CACHE_PREFIX}:${userId}`;
  }

  /**
   * Builds the cache key for a verified current-email proof.
   * @param jti unique JWT identifier.
   * @returns namespaced proof cache key.
   */
  private getProofCacheKey(jti: string): string {
    return `${EMAIL_CHANGE_PROOF_CACHE_PREFIX}:${jti}`;
  }

  /**
   * Builds the cache key for a pending new-email validation.
   * @param jti unique JWT identifier.
   * @returns namespaced pending-change cache key.
   */
  private getPendingCacheKey(jti: string): string {
    return `${EMAIL_CHANGE_PENDING_CACHE_PREFIX}:${jti}`;
  }

  /**
   * Verifies one of the short-lived JWTs used by this flow.
   * @param token signed proof or validation token.
   * @param audience audience required for the current flow phase.
   * @param expiredMessage message returned when the token has expired.
   * @returns the verified email-change claims.
   * @throws GoneException when the token expired.
   * @throws ForbiddenException when the token is otherwise invalid.
   */
  private verifyToken(
    token: string,
    audience: string,
    expiredMessage: string,
  ): EmailChangeJwtPayload {
    try {
      return jwt.verify(token, this.jwtSecret, {
        audience,
      }) as EmailChangeJwtPayload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new GoneException(expiredMessage);
      }
      throw new ForbiddenException('The email change token is invalid.');
    }
  }

  /**
   * Publishes the current-email OTP through the configured SendGrid template.
   * @param handle Topcoder handle used by the email template.
   * @param email current primary email recipient.
   * @param otp six-digit ownership code.
   * @returns a promise resolved after the event is published.
   * @throws InternalServerErrorException when the template is not configured.
   */
  private async sendOtpEmail(
    handle: string,
    email: string,
    otp: string,
  ): Promise<void> {
    const sendgridTemplateId = this.configService.get<string>(
      'SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID',
    );
    if (!sendgridTemplateId) {
      throw new InternalServerErrorException(
        'Email verification template is not configured.',
      );
    }

    const domain = CommonUtils.getAppDomain(this.configService);
    await this.eventService.postDirectBusMessage('external.action.email', {
      data: {
        code: otp,
        duration: Math.ceil(this.otpExpirySeconds / 60),
        handle,
      },
      from: { email: `Topcoder <noreply@${domain}>` },
      recipients: [email],
      sendgrid_template_id: sendgridTemplateId,
      version: 'v6',
    });
  }

  /**
   * Publishes the validation link to the proposed new address.
   * @param handle Topcoder handle used by the email template.
   * @param email proposed new email recipient.
   * @param validationToken signed one-time validation token.
   * @returns a promise resolved after the event is published.
   */
  private async sendNewEmailValidation(
    handle: string,
    email: string,
    validationToken: string,
  ): Promise<void> {
    const domain = CommonUtils.getAppDomain(this.configService);
    const verificationUrlTemplate =
      this.configService.get<string>('EMAIL_CHANGE_VERIFY_URL') ||
      `https://www.${domain}/account-settings/changeEmail?action=verify&token=<emailChangeToken>`;
    const cancelUrl =
      this.configService.get<string>('EMAIL_CHANGE_CANCEL_URL') ||
      `https://www.${domain}/account-settings`;
    const verificationAgreeUrl = verificationUrlTemplate.replace(
      '<emailChangeToken>',
      encodeURIComponent(validationToken),
    );

    await this.eventService.postDirectBusMessage(
      EMAIL_CHANGE_NOTIFICATION_TOPIC,
      {
        data: {
          subject: 'Topcoder - Email Change Verification',
          userHandle: handle,
          verificationAgreeUrl,
          verificationDisagreeUrl: cancelUrl,
        },
        recipients: [email],
      },
    );
  }
}
