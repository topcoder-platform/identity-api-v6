import {
  Injectable,
  Inject,
  Logger,
  InternalServerErrorException,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import {
  PrismaClient as PrismaClientCommonOltp,
  user_sso_login as UserSsoLoginModel,
  sso_login_provider as SsoLoginProviderModel,
  user_social_login as UserSocialLoginModel,
  social_login_provider as SocialLoginProviderModel,
  Prisma,
} from '@prisma/client-common-oltp';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import { UserProfileDto } from '../../dto/user/user.dto'; // Assuming UserProfileDto is suitable
import { EventService } from '../../shared/event/event.service';
import { ConfigService } from '@nestjs/config';
// Import other needed services

@Injectable()
export class UserProfileService {
  private readonly logger = new Logger(UserProfileService.name);

  constructor(
    @Inject(PRISMA_CLIENT_COMMON_OLTP)
    private readonly prismaOltp: PrismaClientCommonOltp,
    private readonly eventService: EventService,
    private readonly configService: ConfigService,
    // Inject other services
  ) {}

  private mapSsoLoginToDto(
    ssoLogin: UserSsoLoginModel & { sso_login_provider: SsoLoginProviderModel },
  ): UserProfileDto {
    if (!ssoLogin || !ssoLogin.sso_login_provider) {
      // This case should ideally not happen if queries include the provider correctly
      this.logger.error(
        `mapSsoLoginToDto called with invalid ssoLogin object: ${JSON.stringify(ssoLogin)}`,
      );
      throw new InternalServerErrorException(
        'Error mapping SSO login data due to missing provider information.',
      );
    }
    return {
      provider: ssoLogin.sso_login_provider.name,
      userId: ssoLogin.sso_user_id, // This is the ID from the provider
      name: ssoLogin.sso_user_name,
      email: ssoLogin.email,
      providerType: 'sso', // Could be derived from sso_login_provider.type if available and needed
      // context: ssoLogin.context, // If a context field is added to user_sso_login model
    };
  }

  // Helper to map UserSocialLoginModel to UserProfileDto
  private mapSocialLoginToDto(
    socialLogin: UserSocialLoginModel & {
      social_login_provider: SocialLoginProviderModel;
    },
  ): UserProfileDto {
    if (!socialLogin || !socialLogin.social_login_provider) {
      this.logger.error(
        `mapSocialLoginToDto called with invalid socialLogin object: ${JSON.stringify(socialLogin)}`,
      );
      throw new InternalServerErrorException(
        'Error mapping social login data due to missing provider information.',
      );
    }
    return {
      provider: socialLogin.social_login_provider.name,
      userId: socialLogin.social_user_id,
      name: socialLogin.social_user_name || undefined, // Ensure name is optional if null
      // email: undefined, // email is not directly on user_social_login, decide if needed from user or DTO adjustment
      providerType: 'social',
    };
  }

  async findSSOUserLoginsByUserId(userId: number): Promise<UserProfileDto[]> {
    this.logger.debug(`Finding SSO logins for user ID: ${userId}`);
    const ssoLogins = await this.prismaOltp.user_sso_login.findMany({
      where: { user_id: userId },
      include: { sso_login_provider: true }, // Essential for mapSsoLoginToDto
    });
    return ssoLogins.map((ssoLogin) => this.mapSsoLoginToDto(ssoLogin));
  }

  async createSSOUserLogin(
    userId: number,
    profileDto: UserProfileDto,
  ): Promise<UserProfileDto> {
    this.logger.log(
      `Creating SSO login for user ID: ${userId}, provider: ${profileDto.provider}, ssoUserId: ${profileDto.userId}`,
    );
    if (!profileDto.provider || !profileDto.userId) {
      throw new BadRequestException(
        'Provider name and provider-specific user ID are required.',
      );
    }

    const providerRecord = await this.prismaOltp.sso_login_provider.findFirst({
      where: { name: profileDto.provider },
    });

    if (!providerRecord) {
      this.logger.error(
        `SSO Provider ${profileDto.provider} not found. Dynamic creation is currently disabled.`,
      );
      throw new BadRequestException(
        `SSO Provider '${profileDto.provider}' is not configured in the system. Please contact an administrator.`,
      );
    }

    try {
      const newSsoLogin = await this.prismaOltp.user_sso_login.create({
        data: {
          user_id: userId,
          provider_id: providerRecord.sso_login_provider_id,
          sso_user_id: profileDto.userId,
          email: profileDto.email, // Optional, from provider
          sso_user_name: profileDto.name, // Optional, from provider
          // created_by: operatorId, // Add if schema supports
          // modified_by: operatorId, // Add if schema supports
        },
        include: { sso_login_provider: true }, // Ensure provider is included for mapping
      });

      this.logger.log(
        `SSO login linked for user ${userId}, provider ${profileDto.provider}. (Event publishing skipped)`,
      );
      return this.mapSsoLoginToDto(newSsoLogin);
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        // This error code means unique constraint failed - user_id_provider_id_sso_user_id PK likely
        this.logger.warn(
          `SSO login already exists for user ${userId}, provider ${profileDto.provider}, sso_user_id ${profileDto.userId}. Throwing ConflictException.`,
        );
        throw new ConflictException(
          'This SSO identity is already linked to this user account.',
        );
      }
      this.logger.error(
        `Error creating SSO login for user ${userId}. Error code: ${error.code}, Message: ${error.message}`,
        error.stack,
      );
      // Re-check if it was a P2002 that somehow wasn't caught above, though unlikely
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        this.logger.error(
          "Caught P2002 in final catch block - this shouldn't happen if first catch works. Rethrowing as Conflict.",
        );
        throw new ConflictException(
          'This SSO identity is already linked to this user account (final catch).',
        );
      }
      throw new InternalServerErrorException('Failed to link SSO account.');
    }
  }

  async updateSSOUserLogin(
    userId: number,
    profileDto: UserProfileDto,
  ): Promise<UserProfileDto> {
    this.logger.log(
      `Updating SSO login for user ID: ${userId}, provider: ${profileDto.provider}, ssoUserId: ${profileDto.userId}`,
    );
    if (!profileDto.provider || !profileDto.userId) {
      throw new BadRequestException(
        'Provider name and provider-specific user ID are required for update.',
      );
    }

    const providerRecord = await this.prismaOltp.sso_login_provider.findFirst({
      where: { name: profileDto.provider },
    });

    if (!providerRecord) {
      throw new NotFoundException(
        `SSO Provider '${profileDto.provider}' not found. Cannot update SSO link.`,
      );
    }

    try {
      const updatedSsoLogin = await this.prismaOltp.user_sso_login.update({
        where: {
          user_id_provider_id: {
            user_id: userId,
            provider_id: providerRecord.sso_login_provider_id,
          },
        },
        data: {
          email: profileDto.email, // Updateable fields
          sso_user_name: profileDto.name,
          // modified_by: operatorId,    // Add if schema supports
        },
        include: { sso_login_provider: true }, // Added include to ensure data for mapSsoLoginToDto
      });

      this.logger.log(
        `SSO login updated for user ${userId}, provider ${profileDto.provider}. (Event publishing skipped)`,
      );
      return this.mapSsoLoginToDto(updatedSsoLogin);
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2025'
      ) {
        // Record to update not found
        this.logger.warn(
          `SSO login not found for update: user ${userId}, provider ${profileDto.provider}, sso_user_id ${profileDto.userId}.`,
        );
        throw new NotFoundException('SSO login link to update not found.');
      }
      this.logger.error(
        `Error updating SSO login for user ${userId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'Failed to update SSO account link.',
      );
    }
  }

  async deleteSSOUserLogin(
    userId: number,
    providerName: string,
    ssoUserIdForEvent: string,
  ): Promise<void> {
    // ssoUserIdForEvent is needed because if we delete by user_id and providerName only,
    // we might not know the exact sso_user_id if it wasn't passed in the request, but it is part of PK.
    // The controller will need to ensure it gets this, perhaps from a query param if not deleting by the full composite key.
    // For now, assume it's provided or can be derived by the caller if needed for the event.
    // However, the PK of user_sso_login is user_id + provider_id + sso_user_id, so sso_user_id IS required for deletion.

    this.logger.log(
      `Deleting SSO login for user ID: ${userId}, provider: ${providerName}, ssoUserId: ${ssoUserIdForEvent}`,
    );

    const providerRecord = await this.prismaOltp.sso_login_provider.findFirst({
      where: { name: providerName },
    });

    if (!providerRecord) {
      this.logger.warn(
        `SSO Provider '${providerName}' not found. Cannot delete SSO link.`,
      );
      throw new NotFoundException(`SSO Provider '${providerName}' not found.`);
    }

    try {
      await this.prismaOltp.user_sso_login.delete({
        where: {
          user_id_provider_id: {
            user_id: userId,
            provider_id: providerRecord.sso_login_provider_id,
          },
        },
      });

      try {
        await this.eventService.postEnvelopedNotification('user.sso.unlinked', {
          userId: userId.toString(),
          profileProvider: providerName,
          profileId: ssoUserIdForEvent,
        });
      } catch (eventError) {
        this.logger.error(
          `Failed to post 'user.sso.unlinked' event for user ${userId}, provider ${providerName}. Error: ${eventError.message}`,
          eventError.stack,
        );
        // Do not rethrow; allow the main operation to be considered successful if DB part worked.
        // In a real scenario, this might go to a dead-letter queue or trigger an alert.
      }

      this.logger.log(
        `SSO login unlinked for user ${userId}, provider ${providerName}, ssoUserId ${ssoUserIdForEvent}.`,
      );
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2025'
      ) {
        // Record to delete not found
        this.logger.warn(
          `SSO login not found for deletion (P2025): user ${userId}, provider ${providerName}, sso_user_id ${ssoUserIdForEvent}.`,
        );
        throw new NotFoundException('SSO login link to delete not found.');
      }
      this.logger.error(
        `Error deleting SSO login for user ${userId}, provider ${providerName}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Failed to unlink SSO account.');
    }
  }

  async addExternalProfile(
    userId: number,
    profileDto: UserProfileDto,
  ): Promise<UserProfileDto> {
    this.logger.log(
      `Adding external social profile for user ID: ${userId}, provider: ${profileDto.provider}, providerUserId: ${profileDto.userId}`,
    );

    if (
      profileDto.providerType &&
      profileDto.providerType.toLowerCase() === 'sso'
    ) {
      this.logger.warn(
        'Attempted to add SSO profile via addExternalProfile. Use createSSOUserLogin instead.',
      );
      throw new BadRequestException(
        'Use the specific SSO linking endpoint for SSO providers.',
      );
    }

    if (!profileDto.provider || !profileDto.userId) {
      throw new BadRequestException(
        'Provider name and provider-specific user ID are required for external profiles.',
      );
    }

    const socialProvider =
      await this.prismaOltp.social_login_provider.findFirst({
        where: { name: { equals: profileDto.provider, mode: 'insensitive' } }, // Case-insensitive match for provider name
      });

    if (!socialProvider) {
      this.logger.warn(
        `Social login provider not found: ${profileDto.provider}`,
      );
      // Decide if we should create it or throw. For now, assume it must exist.
      throw new BadRequestException(
        `Social provider '${profileDto.provider}' is not configured.`,
      );
    }

    try {
      const newSocialLogin = await this.prismaOltp.user_social_login.create({
        data: {
          user_id: userId,
          social_login_provider_id: socialProvider.social_login_provider_id,
          social_user_id: profileDto.userId, // This is the user's ID on the social platform
          social_user_name: profileDto.name, // Optional: user's name/handle on the social platform
          // created_by: operatorId, // Add if schema supports and if operatorId type is correct
          // modified_by: operatorId,
        },
        include: { social_login_provider: true }, // Ensure provider is included for mapping
      });

      // Event Publishing for 'user.social_profile.linked' removed as per legacy system adherence.
      // const eventAttributes = {
      //   userId: userId.toString(),
      //   profileProvider: newSocialLogin.social_login_provider.name, // from included provider
      //   profileId: newSocialLogin.social_user_id,
      // };
      // await this.eventService.postEnvelopedNotification(
      //   'user.social_profile.linked',
      //   eventAttributes,
      // );
      // this.logger.log(
      //   `Event 'user.social_profile.linked' published for user ${userId}.`,
      // );

      this.logger.log(
        `External social profile linked for user ${userId}, provider ${newSocialLogin.social_login_provider.name}. Event 'user.social_profile.linked' was not sent, to align with legacy system.`,
      );

      return this.mapSocialLoginToDto(newSocialLogin);
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        // Unique constraint failed (likely on social_login_provider_id, social_user_id or user_id, social_login_provider_id)
        this.logger.warn(
          `Social profile already exists for user ${userId}, provider ${profileDto.provider}, provider_user_id ${profileDto.userId}. Error: ${error.message}`,
        );
        // Check which constraint failed by looking at error.meta.target
        const target = error.meta?.target as string[];
        if (
          target?.includes('user_social_login_idx1') ||
          (target?.includes('social_login_provider_id') &&
            target?.includes('social_user_id'))
        ) {
          throw new ConflictException(
            'This social identity is already linked to another Topcoder account.',
          );
        } else if (
          target?.includes('user_id') &&
          target?.includes('social_login_provider_id')
        ) {
          // This means the user already has a link for this specific provider type.
          // Depending on business rules, this might be an update or a conflict.
          // For now, treating as a conflict for simplicity, as we don't have an updateExternalProfile here.
          throw new ConflictException(
            `This account is already linked with the social provider '${profileDto.provider}'.`,
          );
        }
        throw new ConflictException(
          'This social profile is already linked or cannot be added.',
        );
      }
      this.logger.error(
        `Error adding external social profile for user ${userId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Failed to link social profile.');
    }
  }

  async findAllUserProfiles(userId: number): Promise<UserProfileDto[]> {
    this.logger.debug(
      `Finding all user profiles (SSO and Social) for user ID: ${userId}`,
    );

    const ssoProfiles = await this.findSSOUserLoginsByUserId(userId);
    this.logger.debug(
      `Found ${ssoProfiles.length} SSO profiles for user ID: ${userId}`,
    );

    const socialLogins = await this.prismaOltp.user_social_login.findMany({
      where: { user_id: userId },
      include: { social_login_provider: true },
    });
    const socialProfiles = socialLogins.map((sl) =>
      this.mapSocialLoginToDto(sl),
    );
    this.logger.debug(
      `Found ${socialProfiles.length} social profiles for user ID: ${userId}`,
    );

    return [...ssoProfiles, ...socialProfiles];
  }

  async deleteExternalProfile(
    userId: number,
    providerName: string,
  ): Promise<void> {
    this.logger.log(
      `Deleting external social profile for user ID: ${userId}, provider: ${providerName}`,
    );

    const socialProvider =
      await this.prismaOltp.social_login_provider.findFirst({
        where: { name: { equals: providerName, mode: 'insensitive' } },
      });

    if (!socialProvider) {
      this.logger.warn(
        `Social login provider not found: ${providerName}. Cannot delete profile.`,
      );
      throw new NotFoundException(
        `Social provider '${providerName}' not found.`,
      );
    }

    try {
      const deleteResult = await this.prismaOltp.user_social_login.deleteMany({
        where: {
          user_id: userId,
          social_login_provider_id: socialProvider.social_login_provider_id,
        },
      });

      if (deleteResult.count === 0) {
        this.logger.warn(
          `No external social profile found to delete for user ${userId}, provider ${providerName}.`,
        );
        throw new NotFoundException(
          'External social profile link not found to delete.',
        );
      }

      this.logger.log(
        `External social profile unlinked for user ${userId}, provider ${providerName}. Count: ${deleteResult.count}`,
      );
    } catch (error) {
      // P2025 (Record to delete not found) is handled by checking deleteResult.count above
      this.logger.error(
        `Error deleting external social profile for user ${userId}, provider ${providerName}: ${error.message}`,
        error.stack,
      );
      // Avoid re-throwing specific Prisma errors if already handled,
      // but throw a generic server error for other unexpected issues.
      if (!(error instanceof NotFoundException)) {
        throw new InternalServerErrorException(
          'Failed to unlink social profile.',
        );
      }
      throw error; // Re-throw NotFoundException if it was manually thrown
    }
  }
}
