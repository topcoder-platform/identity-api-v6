import { Inject, Injectable, Logger } from "@nestjs/common";
import { ProviderId, ProviderTypes } from "../../core/constant/provider-type.enum";
import { UserProfileDto } from "../../dto/user/user.dto";
import {
  PRISMA_CLIENT_COMMON_OLTP,
} from '../../shared/prisma/prisma.module';
import {
  Prisma,
  PrismaClient as PrismaCommonClient,
} from '@prisma/client-common-oltp';

@Injectable()
export class UserProfileHelper {

  private readonly logger = new Logger(UserProfileHelper.name);

  constructor(
    @Inject(PRISMA_CLIENT_COMMON_OLTP)
    private readonly prismaCommonClient: PrismaCommonClient,
  ) {}

  createProfile(decoded: Record<string, any>): UserProfileDto {
    const ret = new UserProfileDto();
    const identities = decoded['identities'] as Record<string, any>[];
    if (identities != null && identities.length > 0) {
      const identity = identities.find(t => this.isAdoptable(t));
      if (identity != null) {
        ret.providerType = String(identity['provider']);
        ret.provider = String(identity['connection']);
        const userIdStr = String(identity['user_id']);
        if (userIdStr != null && userIdStr.length > 0) {
          const parts = userIdStr.split('|');
          ret.userId = parts.length > 0 ? parts[parts.length - 1] : null;
        }
      }
    } else {
      let userId = null;
      if ('user_id' in decoded) {
        userId = String(decoded['user_id']);
      }
      if (userId == null && 'sub' in decoded) {
        userId = String(decoded['sub']);
      }
      if (userId != null) {
        const parts = userId.split('|');
        ret.userId = parts.length > 0 ? parts[parts.length - 1] : null;
      }
    }

    if (this.isCustomOAuthConnectionProviderType(ret.providerType)) {
      ret.providerType = ret.provider;
    }
    ret.email = String(decoded['email']);
    const providerType = ProviderTypes[ret.providerType];
    if (providerType != null && providerType.nameKey != null) {
      ret.name = String(decoded[providerType.nameKey]);
    }
    ret.isEmailVerified = ('email_verified' in decoded && decoded['email_verified']);

    return ret;
  }

  async getUserIdByProfile(profile: UserProfileDto): Promise<number | null> {
    if (profile == null) {
      throw new Error('profile must be specified.');
    }
    const providerType = ProviderTypes[profile.providerType];
    if (providerType == null) {
      throw new Error(`Unsupported provider type: ${profile.providerType}`);
    }
    const providerTypeId = providerType.id;
    if ([ProviderId.LDAP, ProviderId.AUTH0].includes(providerTypeId)) {
      return this.getLocalUserIdThrow(profile);
    }
    if (providerType.isSocial) {
      return this.findSocialUserId(profile);
    }
    if (providerType.isEnterprise) {
      return this.findEnterpriseUserId(profile);
    }
    throw new Error(`Unsupported provider type: ${profile.providerType}`);
  }

  private async findSocialUserId(profile: UserProfileDto):  Promise<number | null> {
    if (profile.userId == null) {
      throw new Error('profile must have userId');
    }
    const providerType = ProviderTypes[profile.providerType];
    let userId: Prisma.Decimal = null;
    try {
      const localUserId = this.getLocalUserIdThrow(profile);
      const record = await this.prismaCommonClient.user_social_login.findFirst({
        where: {
          social_user_id: String(localUserId),
          social_login_provider_id: providerType.id
        }
      });
      const ret = record?.user_id;
      if (ret != null) {
        return ret.toNumber();
      }
    } catch (error) {
      this.logger.error(`Error occurred in querying user with social id. ` + 
        `socialId:${this.getLocalUserIdThrow(profile)}, ` + 
        `provider:${providerType.key}`, error);
    }
    if (profile.email != null && profile.email.length > 0) {
      const record = await this.prismaCommonClient.user_social_login.findFirst({
        where: {
          social_email: profile.email,
          social_email_verified: profile.isEmailVerified,
          social_login_provider_id: providerType.id
        }
      });
      userId = record?.user_id;
    } else if (profile.name != null && profile.name.length > 0) {
      const record = await this.prismaCommonClient.user_social_login.findFirst({
        where: {
          social_user_name: profile.name,
          social_login_provider_id: providerType.id
        }
      });
      userId = record?.user_id;
    } else {
      throw new Error('The social account should have at least one valid email or one valid username.');
    }
    if (userId != null) {
      try {
        await this.prismaCommonClient.user_social_login.updateMany({
          where: { user_id: userId },
          data: { social_user_id: String(this.getLocalUserIdThrow(profile)) }
        })
      } catch (error) {
        this.logger.error(`Failed to update user with social id. userId: ${userId}`);
      }
    }
    return userId?.toNumber();
  }

  private async findEnterpriseUserId(profile: UserProfileDto): Promise<number | null> {
    // find sso provider id
    const providerRecord = await this.prismaCommonClient.sso_login_provider.findFirst({
      where: { name: profile.provider }
    });
    const ssoProviderId = providerRecord?.sso_login_provider_id;
    if (ssoProviderId == null) {
      throw new Error(`Unsupported SSO provider: ${profile.provider}`);
    }
    let userId = null;
    let userRecord = await this.prismaCommonClient.user_sso_login.findFirst({
      where: {
        email: profile.email,
        provider_id: ssoProviderId
      }
    });
    userId = userRecord?.user_id;
    if (userId == null) {
      userRecord = await this.prismaCommonClient.user_sso_login.findFirst({
        where: {
          sso_user_id: String(this.getLocalUserId(profile)),
          provider_id: ssoProviderId
        }
      });
      userId = userRecord?.user_id;
    }
    return userId?.toNumber();
  }

  private isAdoptable(identity: Record<string, any>): boolean {
    const provider = String(identity['provider']);
    if (this.isCustomOAuthConnectionProviderType(provider)) {
      return true;
    }
    const providerType = ProviderTypes[provider];
    if (!providerType) {
      return false;
    }
    if (providerType.id !== ProviderId.AUTH0) {
      return true;
    }
    const connection = String(identity['connection']);
    return connection === 'TC-User-Database';
  }

  private isCustomOAuthConnectionProviderType(providerType: string): boolean {
    return ['oauth1', 'oauth2'].includes(providerType);
  }

  private getLocalUserId(profile: UserProfileDto): number | null {
    const userIdStr = String(profile.userId);
    if (userIdStr == null || userIdStr.length === 0) {
      return null;
    }
    const parts = userIdStr.split('|');
    return parts.length > 0 ? parseInt(parts[parts.length - 1]) : null;
  }

  private getLocalUserIdThrow(profile: UserProfileDto): number | null {
    const userId = this.getLocalUserId(profile);
    if (userId == null) {
      throw new Error('user id must be provided');
    }
    return userId;
  }
}
