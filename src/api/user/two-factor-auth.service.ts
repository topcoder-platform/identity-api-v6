import {
  Injectable,
  Inject,
  Logger,
  InternalServerErrorException,
  NotFoundException,
  BadRequestException,
  GoneException,
  ForbiddenException,
} from '@nestjs/common';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { Prisma, PrismaClient } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { EventService } from '../../shared/event/event.service';
import { UserService } from './user.service';
import { Cache } from 'cache-manager';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import * as DTOs from '../../dto/user/user.dto';
import { SlackService } from '../../shared/slack/slack.service';
import { AuthFlowService } from './auth-flow.service'; // For OTP completion
import * as jwt from 'jsonwebtoken';
import { RoleService } from '../role/role.service';
import { addMinutes, isBefore } from 'date-fns';

export const TFA_OTP_CACHE_PREFIX_KEY = 'USER_2FA_OTP';
export const TFA_OTP_RESEND_TOKEN_CACHE_PREFIX_KEY = 'USER_2FA_RESEND_OTP';
export const TFA_OTP_EXPIRY_SECONDS = 5 * 60; // 5 minutes
export const TFA_RESEND_TOKEN_EXPIRY_SECONDS = 10 * 60; // 10 minutes
export const TFA_OTP_MAX_ATTEMPTS = 3; // only 3 as per legacy Java code
export const OTP_2FA_MODE = 2;

@Injectable()
export class TwoFactorAuthService {
  private readonly logger = new Logger(TwoFactorAuthService.name);
  private readonly otpDurationMinutes: number;
  private readonly resendTokenSecret: string;
  private readonly otp2faAudience: string = '2faemail'; // As per Java UserResource

  constructor(
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    private readonly configService: ConfigService,
    private readonly eventService: EventService,
    private readonly userService: UserService, // For user lookups
    private readonly slackService: SlackService,
    private readonly authFlowService: AuthFlowService, // Injected for login completion
    private readonly roleService: RoleService,
  ) {
    this.otpDurationMinutes = parseInt(
      this.configService.get<string>('AUTH_OTP_DURATION', '10'),
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

  async getUser2faStatus(
    userIdString: string,
  ): Promise<DTOs.User2faResponseDto> {
    this.logger.log(`Getting 2FA status for user: ${userIdString}`);
    const userId = parseInt(userIdString, 10);
    if (isNaN(userId)) {
      throw new BadRequestException('Invalid user ID format.');
    }

    const user2fa = await this.prismaClient.user_2fa.findUnique({
      where: { user_id: userId },
      select: {
        id: true,
        mfa_enabled: true,
        created_by: true,
        created_at: true,
        modified_by: true,
        modified_at: true,
      },
    });

    if (!user2fa) {
      throw new NotFoundException('User does not exist'); // same as UserResource.java line 1610
    }

    return {
      id: user2fa.id,
      userId: userId,
      mfaEnabled: user2fa.mfa_enabled,
      createdBy: Number(user2fa.created_by ?? 0),
      createdAt: user2fa.created_at?.toISOString(),
      modifiedBy: Number(user2fa.modified_by ?? 0),
      modifiedAt: user2fa.modified_at?.toISOString(),
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

    let user2fa = await this.prismaClient.user_2fa.findUnique({
      where: { user_id: userId },
    });
    /**
     const oldDiceStatus = user2fa?.dice_enabled ?? false;
    const userHandle =
      (
        await this.prismaClient.user.findUnique({
          where: { user_id: userId },
          select: { handle: true },
        })
      )?.handle || userIdString;
     */

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
      const emailCount = await this.prismaClient.email.count({
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

      user2fa = await this.prismaClient.user_2fa.create({
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
        user2fa = await this.prismaClient.user_2fa.update({
          where: { user_id: userId },
          data: updatePayload,
        });
      } else {
        this.logger.log(
          `No actual changes to 2FA status for user ${userId}. Skipping update.`,
        );
      }
    }

    // Dice logic not part of new implementation
    // // If DICE was enabled and is now being disabled (implicitly by mfaEnabled: false)
    // if (oldDiceStatus && !user2fa.dice_enabled) {
    //   this.logger.log(
    //     `DICE was enabled and is now disabled for user ${userId}. Deleting DICE connection if any.`,
    //   );
    //   await this.prismaClient.dice_connection.deleteMany({
    //     where: { user_id: userId },
    //   });
    //   this.slackService
    //     .sendNotification('DICE disabled :crying_cat_face:', userHandle)
    //     .catch((e) => this.logger.error('Slack notification failed', e));
    // }

    return {
      mfaEnabled: user2fa.mfa_enabled,
      diceEnabled: user2fa.dice_enabled,
    };
  }

  /**
   * Send OTP for 2FA.
   * @param userIdString The user ID
   * @returns the resend token
   */
  async sendOtpFor2fa(userIdString: string): Promise<{ resendToken: string }> {
    this.logger.log(`Generating and sending 2FA OTP to user: ${userIdString}`);
    const userIdNum = parseInt(userIdString, 10);
    if (isNaN(userIdNum)) {
      throw new BadRequestException('Invalid user ID format.');
    }

    const user = await this.prismaClient.user.findUnique({
      where: { user_id: userIdNum },
      select: { handle: true },
    });

    if (!user) {
      throw new NotFoundException('User does not exist');
    }

    const otp = this.generateNumericOtp();
    const resendToken = this.generateResendToken(
      userIdString,
      this.otp2faAudience,
      this.otpDurationMinutes * 60,
    );

    const userOtp = await this.authFlowService.findUserOtpEmailByUserId(
      userIdNum,
      OTP_2FA_MODE,
    );

    const expiresAt = addMinutes(new Date(), this.otpDurationMinutes);
    if (!userOtp || !userOtp?.id) {
      // we insert a new one
      await this.authFlowService.insertUserOtp(
        userIdNum,
        OTP_2FA_MODE,
        otp,
        false,
        0,
        expiresAt,
      );
    } else {
      // update existing otp
      await this.authFlowService.updateUserOtp(
        userOtp.id,
        userIdNum,
        otp,
        false,
        0,
        expiresAt,
      );
    }
    // we are sure at this point that email exists
    // send email event
    await this.send2faCodeEmailEvent(
      user.handle,
      otp,
      userOtp.email,
      this.otpDurationMinutes,
    );

    return { resendToken: resendToken };
  }

  private async send2faCodeEmailEvent(
    handle: string,
    otp: string,
    email: string,
    duration: number,
  ) {
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
          handle: handle,
          code: otp,
          duration: duration,
        },
        from: { email: fromEmail },
        version: 'v6',
        sendgrid_template_id: sendgridTemplateId,
        recipients: [email], // The original email used for registration
      });
      this.logger.log(
        `Published 'external.action.email' event for user ${handle}`,
      );
    } catch (eventError) {
      this.logger.error(
        `Failed to publish 2FA OTP email event for user ${handle}: ${eventError.message}`,
        eventError.stack,
      );
    }
  }

  private generateResendToken(
    userId: string,
    aud: string,
    expiryInSecods: number,
  ) {
    const payload = { aud: aud, userId: userId };
    const resendToken = jwt.sign(payload, this.resendTokenSecret, {
      expiresIn: `${expiryInSecods}s`,
    });
    console.log(`Generated resend token is: ${resendToken}`);
    return resendToken;
  }

  private verifyResendToken(userId: string, aud: string, token: string) {
    let decodedJwtPayload: jwt.JwtPayload;
    try {
      decodedJwtPayload = jwt.verify(token, this.resendTokenSecret, {
        audience: aud,
        userId: userId,
      }) as jwt.JwtPayload;
      console.log('Decoded JWT:' + JSON.stringify(decodedJwtPayload));
      // FIXME fix verification of userId
      // if (decodedJwtPayload.sub !== userId.toString()) {
      //   throw new ForbiddenException('Invalid resend token: User ID mismatch.');
      // }
    } catch (error) {
      this.logger.warn(
        `Resend activation token validation failed for user ID ${userId}: ${error.message}`,
      );
      if (error instanceof jwt.TokenExpiredError) {
        throw new GoneException('Resend token has expired.');
      }
      throw new ForbiddenException('Invalid or expired resend token.');
    }
  }

  async resendOtpEmailFor2fa(
    userId: number,
    resendToken: string,
  ): Promise<string> {
    this.logger.log('Attempting to resend 2FA OTP email.');

    // verify resend token
    this.verifyResendToken(userId + '', this.otp2faAudience, resendToken);

    const userOtp = await this.authFlowService.findUserOtpEmailByUserId(
      userId,
      OTP_2FA_MODE,
    );

    if (!userOtp) {
      throw new NotFoundException('User does not exist'); // just like in UserResource.java line 1057
    }
    if (!userOtp.id) {
      throw new NotFoundException('No otp found');
    }
    if (userOtp.resend) {
      throw new BadRequestException('Otp already resent');
    }
    if (isBefore(userOtp.expireAt, new Date())) {
      throw new BadRequestException('Password expired');
    }
    if (userOtp.failCount >= TFA_OTP_MAX_ATTEMPTS) {
      throw new BadRequestException('Too many attempts');
    }
    // update user OTP resend
    await this.authFlowService.updateUserOtpResend(
      userOtp.id,
      addMinutes(new Date(), this.otpDurationMinutes),
      true,
    );
    // we are sure email exists at this point
    await this.send2faCodeEmailEvent(
      userOtp.handle,
      userOtp.otp,
      userOtp.email,
      this.otpDurationMinutes,
    );

    return 'SUCCESS';
  }

  /**
   * Checks the OTP for 2FA and returns the result.
   * @param userId User ID
   * @param otp Current OTP to verify
   * @returns response of verification
   * @throws NotFoundException when user or otp not found
   * @throws InternalServerErrorException when other errors occur
   */
  async checkOtp(
    userId: number,
    otp: string,
  ): Promise<DTOs.UserOtpResponseDto> {
    this.logger.log(`Verifying otp for user: ${userId}`);
    const userOtp = await this.authFlowService.findUserOtpByUserId(
      userId,
      OTP_2FA_MODE,
    );

    if (!userOtp) {
      throw new NotFoundException('User does not exist');
    }
    if (!userOtp.id) {
      throw new NotFoundException('No otp found');
    }

    // build the response
    const response: DTOs.UserOtpResponseDto = {};
    if (userOtp.failCount >= TFA_OTP_MAX_ATTEMPTS) {
      response.verified = false;
      response.blocked = true;
    } else if (isBefore(userOtp.expireAt, new Date())) {
      response.verified = false;
      response.expired = true;
    } else if (userOtp.otp === otp) {
      response.verified = true;
    } else {
      response.verified = false;
      if (userOtp.failCount >= TFA_OTP_MAX_ATTEMPTS - 1) {
        response.blocked = true;
      } else if (!userOtp.resend) {
        // generate resend token
        response.resendToken = this.generateResendToken(
          userId + '',
          this.otp2faAudience,
          this.otpDurationMinutes * 60,
        );
      }
      // update user otp attempt
      await this.authFlowService.updateUserOtpAttempt(
        userOtp.id,
        userOtp.failCount + 1,
      );
    }
    return response;
  }
}
