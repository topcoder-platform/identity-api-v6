import {
  Injectable,
  Inject,
  Logger,
  InternalServerErrorException,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import {
  PrismaClient as PrismaClientCommonOltp,
  user as UserModel,
  user_2fa as User2faModel,
  Prisma,
  email as EmailModel,
  dice_connection as DiceConnectionModel,
} from '@prisma/client-common-oltp';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import { ConfigService } from '@nestjs/config';
import { EventService } from '../../shared/event/event.service';
import { UserService } from './user.service';
import { Cache } from 'cache-manager';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import * as DTOs from '../../dto/user/user.dto';
import { DiceService } from '../../shared/dice/dice.service';
import { SlackService } from '../../shared/slack/slack.service';
import { AuthFlowService } from './auth-flow.service'; // For OTP completion
import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { RoleService } from '../role/role.service';
import { format } from 'date-fns';

export const TFA_OTP_CACHE_PREFIX_KEY = 'USER_2FA_OTP';
export const TFA_OTP_RESEND_TOKEN_CACHE_PREFIX_KEY = 'USER_2FA_RESEND_OTP';
export const TFA_OTP_EXPIRY_SECONDS = 5 * 60; // 5 minutes
export const TFA_RESEND_TOKEN_EXPIRY_SECONDS = 10 * 60; // 10 minutes
export const TFA_OTP_MAX_ATTEMPTS = 5;

// Interface for the expected decoded payload
interface DecodedResendToken extends jwt.JwtPayload {
  userId: string;
  email: string;
  type?: string;
  aud?: string | string[]; // Explicitly add audience claim
}

@Injectable()
export class TwoFactorAuthService {
  private readonly logger = new Logger(TwoFactorAuthService.name);
  private readonly otpDurationMinutes: number;
  private readonly resendTokenSecret: string;
  private readonly otp2faAudience: string = '2faemail'; // As per Java UserResource

  constructor(
    @Inject(PRISMA_CLIENT_COMMON_OLTP)
    private readonly prismaOltp: PrismaClientCommonOltp,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    private readonly configService: ConfigService,
    private readonly eventService: EventService,
    private readonly userService: UserService, // For user lookups
    private readonly diceService: DiceService,
    private readonly slackService: SlackService,
    private readonly authFlowService: AuthFlowService, // Injected for login completion
    private readonly roleService: RoleService,
  ) {
    this.otpDurationMinutes = parseInt(
      this.configService.get<string>('DEV_DICEAUTH_OTP_DURATION', '10'),
      10,
    );
    this.resendTokenSecret = this.configService.get<string>('JWT_SECRET'); // Re-use main JWT secret or define a new one
    if (!this.resendTokenSecret) {
      this.logger.error('JWT_SECRET for 2FA resend tokens is not configured!');
      throw new InternalServerErrorException(
        '2FA service is not properly configured.',
      );
    }
  }

  private generateNumericOtp(length: number = 6): string {
    let otp = '';
    const digits = '0123456789';
    for (let i = 0; i < length; i++) {
      otp += digits.charAt(Math.floor(Math.random() * digits.length));
    }
    return otp;
  }

  // private async generateResendToken(
  //   userId: string,
  //   email: string,
  // ): Promise<string> {
  //   const payload = { userId, email, type: '2fa-resend' };
  //   return jwt.sign(payload, this.resendTokenSecret, {
  //     expiresIn: `${TFA_RESEND_TOKEN_EXPIRY_SECONDS}s`,
  //   });
  // }

  // private async verifyResendToken(
  //   token: string,
  // ): Promise<{ userId: string; email: string; aud?: string } | null> {
  //   try {
  //     const decoded = jwt.verify(
  //       token,
  //       this.resendTokenSecret,
  //     ) as DecodedResendToken;

  //     if (typeof decoded === 'string') {
  //       this.logger.warn(
  //         'JWT verification returned a string, expected an object.',
  //       );
  //       return null;
  //     }

  //     // Allow general resend tokens or specific '2fa-resend' type
  //     if (decoded.type && decoded.type !== '2fa-resend') {
  //       this.logger.warn(
  //         `Invalid JWT type provided for 2FA resend: ${decoded.type}`,
  //       );
  //       return null;
  //     }
  //     // Add audience check if present
  //     // decoded.aud can be string or string[]
  //     const audience = Array.isArray(decoded.aud)
  //       ? decoded.aud[0]
  //       : decoded.aud;

  //     if (
  //       audience &&
  //       audience !== this.otp2faAudience &&
  //       audience !== 'emailactivation' // also allow activation resend for now
  //     ) {
  //       this.logger.warn(`Invalid JWT audience for 2FA resend: ${audience}`);
  //       return null;
  //     }

  //     if (!decoded.userId || !decoded.email) {
  //       this.logger.warn('JWT for 2FA resend missing userId or email.');
  //       return null;
  //     }

  //     return {
  //       userId: decoded.userId,
  //       email: decoded.email,
  //       aud: audience,
  //     };
  //   } catch (error) {
  //     this.logger.error(`Error verifying 2FA resend token: ${error.message}`);
  //     return null;
  //   }
  // }

  async getUser2faStatus(userIdString: string): Promise<DTOs.User2faDto> {
    this.logger.log(`Getting 2FA status for user: ${userIdString}`);
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid user ID format.');
    }

    const user2fa = await this.prismaOltp.user_2fa.findUnique({
      where: { user_id: userId },
    });

    if (!user2fa) {
      // If no record, implies 2FA is not set up, both are effectively false.
      // Java code returns a record even if not found, so we mimic that by returning defaults.
      this.logger.debug(
        `No user_2fa record found for user ${userId}, returning default false status.`,
      );
      return { mfaEnabled: false, diceEnabled: false };
    }
    return {
      mfaEnabled: user2fa.mfa_enabled,
      diceEnabled: user2fa.dice_enabled,
    };
  }

  async updateUser2faStatus(
    userIdString: string,
    dto: DTOs.User2faDto,
    authUser: AuthenticatedUser,
  ): Promise<DTOs.User2faDto> {
    this.logger.log(
      `Updating 2FA status for user: ${userIdString} by ${authUser.userId}`,
    );
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid user ID format.');
    }

    if (dto.mfaEnabled === undefined && dto.diceEnabled === undefined) {
      throw new BadRequestException(
        'At least one of mfaEnabled or diceEnabled must be provided.',
      );
    }
    // Per Java logic, enabling DICE was not allowed directly via this endpoint.
    if (dto.diceEnabled === true) {
      throw new BadRequestException(
        'DICE cannot be enabled directly through this endpoint. Use DICE connection flow.',
      );
    }

    let user2fa = await this.prismaOltp.user_2fa.findUnique({
      where: { user_id: userId },
    });
    const operatorId = parseInt(authUser.userId, 10);

    const oldMfaStatus = user2fa?.mfa_enabled ?? false;
    const oldDiceStatus = user2fa?.dice_enabled ?? false;
    const userHandle =
      (
        await this.prismaOltp.user.findUnique({
          where: { user_id: userId },
          select: { handle: true },
        })
      )?.handle || userIdString;

    const dataToUpdate: Prisma.user_2faUpdateInput = {};
    if (dto.mfaEnabled !== undefined) {
      dataToUpdate.mfa_enabled = dto.mfaEnabled;
      if (dto.mfaEnabled === false) {
        // If MFA is disabled, DICE must also be disabled.
        dataToUpdate.dice_enabled = false;
      }
    }
    if (
      dto.diceEnabled !== undefined &&
      dataToUpdate.mfa_enabled !== false &&
      dto.mfaEnabled !== false
    ) {
      // Only update DICE if MFA isn't being disabled now or in this update
      dataToUpdate.dice_enabled = dto.diceEnabled;
    }

    // Prisma handles created_by/modified_by if setup with a default or through a lifecycle hook typically.
    // If not, they need to be explicitly set. Assuming 'modified_by' is part of the schema.
    if (authUser && authUser.userId) {
      dataToUpdate.modified_by = parseInt(authUser.userId, 10);
      dataToUpdate.modified_at = new Date();
    }

    if (!user2fa) {
      this.logger.log(
        `No existing user_2fa record for user ${userId}. Creating new record.`,
      );
      const emailCount = await this.prismaOltp.email.count({
        where: { user_id: userId },
      });
      if (emailCount > 1) {
        this.logger.warn(
          `User ${userId} has multiple emails (${emailCount}) and is setting up 2FA for the first time.`,
        );
      }
      const mfaEnabledForCreate = dto.mfaEnabled ?? false;
      let diceEnabledForCreate = dto.diceEnabled ?? false;
      if (!mfaEnabledForCreate) {
        diceEnabledForCreate = false;
      }
      if (dto.diceEnabled && !mfaEnabledForCreate) {
        diceEnabledForCreate = false;
        this.logger.warn(
          'Attempt to create 2FA record with DICE enabled but MFA disabled. Forcing DICE to disabled.',
        );
      }

      const createData: Prisma.user_2faUncheckedCreateInput = {
        user_id: userId,
        mfa_enabled: mfaEnabledForCreate,
        dice_enabled: diceEnabledForCreate,
        created_by: 0,
        modified_by: 0,
        created_at: new Date(),
        modified_at: new Date(),
      };
      if (authUser && authUser.userId) {
        const operatorNumericId = parseInt(authUser.userId, 10);
        if (!isNaN(operatorNumericId)) {
          createData.created_by = operatorNumericId;
          createData.modified_by = operatorNumericId;
        } else {
          this.logger.error(
            'CRITICAL: authUser.userId could not be parsed to number for created_by/modified_by on user_2fa creation.',
          );
          throw new InternalServerErrorException(
            'Operator ID could not be determined for audit fields.',
          );
        }
      } else {
        this.logger.error(
          'CRITICAL: AuthUser not available for setting created_by/modified_by on user_2fa creation. These fields might be mandatory.',
        );
        throw new InternalServerErrorException(
          'Operator context not available for audit fields.',
        );
      }

      user2fa = await this.prismaOltp.user_2fa.create({
        data: createData,
      });
    } else {
      const updatePayload: Prisma.user_2faUpdateArgs['data'] = {
        ...dataToUpdate,
      };
      if (
        Object.keys(updatePayload).some(
          (key) =>
            key !== 'modified_by' &&
            updatePayload[key] !== undefined &&
            user2fa[key] !== updatePayload[key],
        )
      ) {
        user2fa = await this.prismaOltp.user_2fa.update({
          where: { user_id: userId },
          data: updatePayload,
        });
      } else {
        this.logger.log(
          `No actual changes to 2FA status for user ${userId}. Skipping update.`,
        );
      }
    }

    // If DICE was enabled and is now being disabled (implicitly by mfaEnabled: false)
    if (oldDiceStatus && !user2fa.dice_enabled) {
      this.logger.log(
        `DICE was enabled and is now disabled for user ${userId}. Deleting DICE connection if any.`,
      );
      await this.prismaOltp.dice_connection.deleteMany({
        where: { user_id: userId },
      });
      this.slackService
        .sendNotification('DICE disabled :crying_cat_face:', userHandle)
        .catch((e) => this.logger.error('Slack notification failed', e));
    }

    return {
      mfaEnabled: user2fa.mfa_enabled,
      diceEnabled: user2fa.dice_enabled,
    };
  }

  async getDiceConnection(
    userIdString: string,
    authUser: AuthenticatedUser,
  ): Promise<DTOs.DiceConnectionResponseDto> {
    this.logger.log(
      `Getting DICE connection for user: ${userIdString} (self-initiated by ${authUser.userId})`,
    );
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId) || userId.toString() !== authUser.userId) {
      throw new ForbiddenException(
        'Cannot access DICE connection for another user or invalid user ID.',
      );
    }

    // Step 1: Fetch the user
    const user = await this.prismaOltp.user.findUnique({
      where: { user_id: userId },
      select: {
        // Select only direct user fields needed immediately
        user_id: true,
        handle: true,
        first_name: true,
        last_name: true,
      },
    });

    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found.`);
    }

    // Step 2: Fetch user_2fa status
    const user2faStatus = await this.prismaOltp.user_2fa.findUnique({
      where: { user_id: userId },
      select: { mfa_enabled: true, dice_enabled: true },
    });

    if (!user2faStatus?.mfa_enabled) {
      throw new BadRequestException(
        'MFA must be enabled before initiating a DICE connection.',
      );
    }

    // Step 3: Fetch the latest dice_connection
    const latestDiceConnection =
      await this.prismaOltp.dice_connection.findFirst({
        where: { user_id: userId },
        orderBy: { created_at: 'desc' },
        select: {
          id: true,
          connection: true,
          short_url: true,
          accepted: true,
          created_at: true,
        },
      });

    // Step 4: Fetch primary email
    const primaryEmailRecord = await this.prismaOltp.email.findFirst({
      where: { user_id: userId, primary_ind: 1 },
      select: { address: true },
    });
    const primaryEmail = primaryEmailRecord?.address;

    // Use short_url for user-facing display
    if (
      latestDiceConnection &&
      latestDiceConnection.short_url &&
      !latestDiceConnection.accepted
    ) {
      this.logger.log(
        `Existing non-accepted DICE connection found for user ${userId}. URL: ${latestDiceConnection.short_url}`,
      );
      return {
        diceEnabled: user2faStatus?.dice_enabled ?? false,
        connection: latestDiceConnection.short_url,
        accepted: latestDiceConnection.accepted,
      };
    }

    if (!primaryEmail) {
      throw new InternalServerErrorException(
        'Primary email not found for the user.',
      );
    }

    const roleEntities = await this.roleService.findAll(userId);
    const roles = roleEntities.map((r) => r.roleName);

    const validTillDate = new Date();
    validTillDate.setFullYear(validTillDate.getFullYear() + 1);
    const formattedValidTill = format(validTillDate, 'dd-MMM-yyyy HH:mm:ss');

    const invitationResponse = await this.diceService.sendDiceInvitation(
      primaryEmail,
      user.handle, // Use user.handle from fetched user object
      `${user.first_name || ''} ${user.last_name || ''}`.trim(), // Use user fields
      roles,
      formattedValidTill,
    );
    this.logger.log(
      `DICE Job created/invitation sent for user ${userId}: ${JSON.stringify(invitationResponse)}`,
    );

    await this.prismaOltp.dice_connection.upsert({
      where: { user_id: userId },
      create: {
        user: { connect: { user_id: userId } },
        connection: invitationResponse.jobId,
        short_url: invitationResponse.shortUrl,
        accepted: false,
      },
      update: {
        connection: invitationResponse.jobId,
        short_url: invitationResponse.shortUrl,
        accepted: false,
      },
    });

    this.slackService
      .sendNotification('DICE connection process initiated.', user.handle)
      .catch((e) =>
        this.logger.error('Slack notification failed for DICE initiation', e),
      );

    return { diceEnabled: false /* status: 'invitation_sent' */ };
  }

  async handleDiceWebhook(
    webhookPayload: DTOs.DiceStatusWebhookBodyDto,
  ): Promise<{ message: string }> {
    this.logger.log(`Received DICE webhook: ${JSON.stringify(webhookPayload)}`);
    const { event, connectionId, emailId, shortUrl } = webhookPayload;
    let userHandleForSlack = emailId || connectionId || 'Unknown';

    try {
      let diceConnectionRecord:
        | (DiceConnectionModel & {
            user?: { handle: string; user_id: Prisma.Decimal };
          })
        | null = null;

      if (connectionId) {
        diceConnectionRecord = await this.prismaOltp.dice_connection.findFirst({
          where: { connection: connectionId },
          include: { user: { select: { handle: true, user_id: true } } },
        });
      } else if (emailId) {
        const userWithEmail = await this.prismaOltp.user.findFirst({
          where: {
            emails: {
              some: {
                address: emailId,
                primary_ind: 1,
              },
            },
          },
          include: {
            dice_connection: true,
            user_2fa: true,
          },
        });

        if (userWithEmail) {
          userHandleForSlack = userWithEmail.handle;
          if (userWithEmail.dice_connection) {
            diceConnectionRecord = {
              ...userWithEmail.dice_connection,
              user: {
                handle: userWithEmail.handle,
                user_id: userWithEmail.user_id,
              },
            };
          } else {
            this.logger.warn(
              `DICE Webhook: User ${emailId} found, but no DICE connection data associated. Event: ${event}`,
            );
          }
        }
      }

      if (diceConnectionRecord && diceConnectionRecord.user?.handle) {
        userHandleForSlack = diceConnectionRecord.user.handle;
      }

      this.logger.log(
        `Processing DICE webhook event: ${event} for connection: ${connectionId}, email: ${emailId}`,
      );

      switch (event) {
        case 'connection-invitation':
          if (!connectionId || !shortUrl || !emailId) {
            throw new BadRequestException(
              'Missing connectionId, shortUrl or emailId for connection-invitation event',
            );
          }
          let targetUserId: number;
          if (diceConnectionRecord && diceConnectionRecord.user_id) {
            targetUserId = diceConnectionRecord.user_id.toNumber();
          } else {
            const userToLink = await this.prismaOltp.user.findFirst({
              where: {
                emails: {
                  some: {
                    address: emailId,
                    primary_ind: 1,
                  },
                },
              },
              select: { user_id: true, handle: true },
            });
            if (!userToLink)
              throw new NotFoundException(
                `User with email ${emailId} not found for DICE webhook.`,
              );
            targetUserId = userToLink.user_id.toNumber();
            userHandleForSlack = userToLink.handle;
          }

          await this.prismaOltp.dice_connection.upsert({
            where: { user_id: targetUserId },
            create: {
              user: { connect: { user_id: targetUserId } },
              connection: connectionId,
              short_url: shortUrl,
              accepted: false,
            },
            update: {
              connection: connectionId,
              short_url: shortUrl,
              accepted: false,
            },
          });
          this.slackService
            .sendNotification(
              `DICE connection invitation created/updated. URL: ${shortUrl}`,
              userHandleForSlack,
            )
            .catch((e) => this.logger.error('Slack notification failed', e));
          break;
        case 'connection-response':
          if (!connectionId)
            throw new BadRequestException(
              'Missing connectionId for connection-response event',
            );
          if (!diceConnectionRecord)
            throw new NotFoundException(
              `DICE connection ${connectionId} not found for connection-response event.`,
            );

          await this.prismaOltp.dice_connection.updateMany({
            where: { connection: connectionId },
            data: { accepted: true },
          });
          this.slackService
            .sendNotification(
              'DICE connection accepted by user.',
              userHandleForSlack,
            )
            .catch((e) => this.logger.error('Slack notification failed', e));
          break;
        case 'credential-issuance':
          if (!connectionId)
            throw new BadRequestException(
              'Missing connectionId for credential-issuance event',
            );
          if (!diceConnectionRecord || !diceConnectionRecord.user_id)
            throw new NotFoundException(
              `DICE connection ${connectionId} or linked user not found for credential-issuance event.`,
            );

          await this.prismaOltp.user_2fa.update({
            where: { user_id: diceConnectionRecord.user_id.toNumber() },
            data: {
              dice_enabled: true,
              modified_by: diceConnectionRecord.user_id.toNumber(),
              modified_at: new Date(),
            },
          });
          this.logger.log(
            `DICE credential-issuance processed for user ${userHandleForSlack}. DICE enabled.`,
          );
          this.slackService
            .sendNotification(
              'DICE credential issued and enabled for user! :smile_cat:',
              userHandleForSlack,
            )
            .catch((e) => this.logger.error('Slack notification failed', e));
          break;
        case 'connection-declined':
        case 'credential-declined':
          if (!connectionId)
            this.logger.warn(
              `DICE Webhook: ${event} received without connectionId.`,
            );
          this.logger.log(
            `DICE Webhook: ${event} received for connection ${connectionId}. User: ${userHandleForSlack}. No specific DB action taken beyond logging currently.`,
          );
          this.slackService
            .sendNotification(
              `DICE process event: ${event}`,
              userHandleForSlack,
            )
            .catch((e) => this.logger.error('Slack notification failed', e));
          break;
        default:
          this.logger.warn(`Received unhandled DICE webhook event: ${event}`);
          this.slackService
            .sendNotification(
              `Received unhandled DICE event: ${event}`,
              userHandleForSlack,
            )
            .catch((e) => this.logger.error('Slack notification failed', e));
          break;
      }
    } catch (error) {
      this.logger.error(
        `Error processing DICE webhook: ${error.message}`,
        error.stack,
      );
      this.slackService
        .sendNotification(
          'Error happened with DICE webhook, please check logs.',
          userHandleForSlack,
        )
        .catch((e) => this.logger.error('Slack notification failed', e));
      throw new InternalServerErrorException('Failed to process DICE webhook.');
    }
    return { message: 'DICE webhook processed successfully.' };
  }

  async sendOtpFor2fa(userIdString: string): Promise<{ resendToken: string }> {
    this.logger.log(`Generating and sending 2FA OTP to user: ${userIdString}`);
    const userIdNum = parseInt(userIdString, 10);
    if (isNaN(userIdNum)) {
      throw new BadRequestException('Invalid user ID format.');
    }

    const user = await this.prismaOltp.user.findUnique({
      where: { user_id: userIdNum },
      select: { handle: true }, // Only select handle initially
    });

    if (!user) {
      throw new NotFoundException('User not found.');
    }

    // Fetch primary email separately
    const primaryEmailRecord = await this.prismaOltp.email.findFirst({
      where: { user_id: userIdNum, primary_ind: 1, status_id: 1 }, // Assuming active email is needed
      select: { address: true },
    });

    if (!primaryEmailRecord || !primaryEmailRecord.address) {
      throw new InternalServerErrorException(
        'Active primary email not found for the user.',
      );
    }
    const primaryEmail = primaryEmailRecord.address;

    const otp = this.generateNumericOtp();
    const otpCacheKey = `${TFA_OTP_CACHE_PREFIX_KEY}:${userIdString}`;
    await this.cacheManager.set(
      otpCacheKey,
      otp,
      TFA_OTP_EXPIRY_SECONDS * 1000,
    );
    this.logger.log(
      `2FA OTP ${otp} generated and cached for user ${userIdString} (key: ${otpCacheKey})`,
    );

    const payload = { sub: userIdString, aud: this.otp2faAudience };
    const resendToken = jwt.sign(payload, this.resendTokenSecret, {
      expiresIn: `${TFA_RESEND_TOKEN_EXPIRY_SECONDS}s`,
    });

    const domain =
      this.configService.get<string>('APP_DOMAIN') || 'topcoder-dev.com';
    const fromEmail = `Topcoder <noreply@${domain}>`;
    // Use the specific template ID for resending activation emails
    const sendgridTemplateId = this.configService.get<string>(
      'SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID',
    );
    try {
      await this.eventService.postDirectBusMessage('external.action.email', {
        data: {
          userId: userIdString,
          email: primaryEmail,
          handle: user.handle,
          code: otp,
          durationMinutes: TFA_OTP_EXPIRY_SECONDS / 60,
        },
        from: { email: fromEmail },
        version: 'v3',
        sendgrid_template_id: sendgridTemplateId,
        recipients: [primaryEmail], // The original email used for registration
      });
      this.logger.log(
        `Published 'external.action.email' event for user ${userIdString}`,
      );
    } catch (eventError) {
      this.logger.error(
        `Failed to publish 2FA OTP email event for user ${userIdString}: ${eventError.message}`,
        eventError.stack,
      );
    }

    return { resendToken };
  }

  async resendOtpEmailFor2fa(
    resendToken: string,
  ): Promise<{ message: string }> {
    this.logger.log('Attempting to resend 2FA OTP email.');

    let decodedPayload: jwt.JwtPayload;
    try {
      decodedPayload = jwt.verify(resendToken, this.resendTokenSecret, {
        audience: this.otp2faAudience,
      }) as jwt.JwtPayload;
    } catch (error) {
      this.logger.warn(`2FA resend token validation failed: ${error.message}`);
      if (error instanceof jwt.TokenExpiredError) {
        throw new BadRequestException('Resend token has expired.');
      }
      throw new BadRequestException('Invalid or expired resend token.');
    }

    const userIdString = decodedPayload.sub;
    if (!userIdString) {
      throw new BadRequestException(
        'User ID not found in resend token payload.',
      );
    }

    const userIdNum = parseInt(userIdString, 10);
    if (isNaN(userIdNum)) {
      throw new BadRequestException('Invalid user ID format in token.');
    }

    const user = await this.prismaOltp.user.findUnique({
      where: { user_id: userIdNum },
      select: { handle: true }, // Only select handle initially
    });

    if (!user) {
      throw new NotFoundException('User not found.');
    }

    // Fetch primary email separately
    const primaryEmailRecord = await this.prismaOltp.email.findFirst({
      where: { user_id: userIdNum, primary_ind: 1, status_id: 1 }, // Assuming active email is needed
      select: { address: true },
    });

    if (!primaryEmailRecord || !primaryEmailRecord.address) {
      throw new InternalServerErrorException(
        'Active primary email not found for the user.',
      );
    }
    const primaryEmail = primaryEmailRecord.address;

    const newOtp = this.generateNumericOtp();
    const otpCacheKey = `${TFA_OTP_CACHE_PREFIX_KEY}:${userIdString}`;
    await this.cacheManager.set(
      otpCacheKey,
      newOtp,
      TFA_OTP_EXPIRY_SECONDS * 1000,
    );
    this.logger.log(
      `New 2FA OTP ${newOtp} generated and cached for user ${userIdString} (key: ${otpCacheKey}) during resend.`,
    );
    const domain =
      this.configService.get<string>('APP_DOMAIN') || 'topcoder-dev.com';
    const fromEmail = `Topcoder <noreply@${domain}>`;
    // Use the specific template ID for resending activation emails
    const sendgridTemplateId = this.configService.get<string>(
      'SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID',
    );
    try {
      await this.eventService.postDirectBusMessage('external.action.email', {
        data: {
          userId: userIdString,
          email: primaryEmail,
          handle: user.handle,
          code: newOtp,
          durationMinutes: TFA_OTP_EXPIRY_SECONDS / 60,
        },
        from: { email: fromEmail },
        version: 'v3',
        sendgrid_template_id: sendgridTemplateId,
        recipients: [primaryEmail], // The original email used for registration
      });
      this.logger.log(
        `Published 'external.action.email' (resend) event for user ${userIdString}`,
      );
    } catch (eventError) {
      this.logger.error(
        `Failed to publish 2FA OTP resend email event for user ${userIdString}: ${eventError.message}`,
        eventError.stack,
      );
    }

    await this.cacheManager.del(otpCacheKey);
    this.logger.log(`2FA OTP validated and consumed for user ${userIdString}.`);

    const userForResponse = await this.prismaOltp.user.findUnique({
      where: { user_id: parseInt(userIdString, 10) },
      select: { user_id: true, handle: true },
    });

    if (!userForResponse) {
      throw new NotFoundException(
        'User not found after OTP check for final response.',
      );
    }
    this.logger.log(
      `2FA OTP check successful for ${userForResponse.handle}. Login completion to be handled by calling flow.`,
    );
    return { message: '2FA OTP email has been resent successfully.' };
  }

  async checkOtpAndCompleteLogin(
    userIdString: string,
    otp: string,
  ): Promise<{
    verified: boolean;
    message: string;
    userId: string;
    handle: string;
  }> {
    this.logger.log(`Checking 2FA OTP for user: ${userIdString}`);
    const otpCacheKey = `${TFA_OTP_CACHE_PREFIX_KEY}:${userIdString}`;
    const cachedOtp = await this.cacheManager.get<string>(otpCacheKey);

    if (!cachedOtp) {
      this.logger.warn(
        `2FA OTP not found or expired in cache for user ${userIdString}. Key: ${otpCacheKey}`,
      );
      throw new BadRequestException(
        '2FA OTP has expired or was not found. Please request a new one.',
      );
    }

    if (cachedOtp !== otp) {
      this.logger.warn(`Invalid 2FA OTP provided for user ${userIdString}.`);
      throw new BadRequestException('Invalid 2FA OTP.');
    }

    await this.cacheManager.del(otpCacheKey);
    this.logger.log(`2FA OTP validated and consumed for user ${userIdString}.`);

    const userForResponse = await this.prismaOltp.user.findUnique({
      where: { user_id: parseInt(userIdString, 10) },
      select: { user_id: true, handle: true },
    });

    if (!userForResponse) {
      throw new NotFoundException(
        'User not found after OTP check for final response.',
      );
    }
    this.logger.log(
      `2FA OTP check successful for ${userForResponse.handle}. Login completion to be handled by calling flow.`,
    );
    return {
      verified: true,
      message: 'OTP verified. Login completion pending.',
      userId: userForResponse.user_id.toString(),
      handle: userForResponse.handle,
    };
  }
}
