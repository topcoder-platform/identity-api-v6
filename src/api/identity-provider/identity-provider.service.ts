import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { Inject } from '@nestjs/common';
import { IdentityProviderDto } from './identity-provider.dto';

@Injectable()
export class IdentityProviderService {
  private readonly logger = new Logger(IdentityProviderService.name);

  constructor(
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient,
  ) {}

  /**
   * Fetch identity provider information for a user
   * - If handle provided: try SSO userId, SSO email, TC handle, Social userId (in order)
   * - If email provided: try Social email only
   * - Default: return {name: "ldap", type: "default"}
   */
  async fetchProviderInfo(
    handle?: string,
    email?: string,
  ): Promise<IdentityProviderDto> {
    this.logger.log('fetchProviderInfo called');

    if (!handle && !email) {
      throw new BadRequestException('handle or email required');
    }

    let identityProvider: IdentityProviderDto | null = null;

    //  handle parameter can be treated as handle OR email
    if (handle) {
      this.logger.log(`handle: ${handle}`);

      // 1. Try to look into SSO providers by SSO userId
      identityProvider = await this.getSSOProviderByUserId(handle);

      if (!identityProvider) {
        // 2. Try to look into SSO providers by SSO email (using handle as email)
        identityProvider = await this.getSSOProviderByEmail(handle);
      }

      if (!identityProvider) {
        // 3. Try to look into SSO providers by TC handle
        identityProvider = await this.getSSOProviderByHandle(handle);
      }

      if (!identityProvider) {
        // 4. Try to look into Social providers by Social userId
        identityProvider = await this.getSocialProviderByUserId(handle);
      }
    } else if (email) {
      this.logger.log(`email: ${email}`);
      // Java logic: only try Social provider by email
      identityProvider = await this.getSocialProviderByUserEmail(email);
    }

    if (!identityProvider) {
      identityProvider = this.createDefaultProvider();
    }

    return identityProvider;
  }

  /**
   * Get SSO provider by SSO user ID
   */
  private async getSSOProviderByUserId(
    userId: string,
  ): Promise<IdentityProviderDto | null> {
    try {
      const result = await this.prismaClient.user_sso_login.findFirst({
        where: {
          sso_user_id: userId,
        },
        select: {
          sso_login_provider: {
            select: {
              name: true,
              type: true,
            },
          },
        },
      });

      if (result?.sso_login_provider) {
        return {
          name: result.sso_login_provider.name,
          type: result.sso_login_provider.type,
        };
      }
      return null;
    } catch (error) {
      this.logger.error(
        `Error getting SSO provider by userId: ${error.message}`,
      );
      return null;
    }
  }

  /**
   * Get SSO provider by SSO email
   */
  private async getSSOProviderByEmail(
    email: string,
  ): Promise<IdentityProviderDto | null> {
    try {
      const result = await this.prismaClient.user_sso_login.findFirst({
        where: {
          email: {
            equals: email,
            mode: 'insensitive',
          },
          sso_login_provider: {
            identify_email_enabled: true,
          },
        },
        select: {
          sso_login_provider: {
            select: {
              name: true,
              type: true,
            },
          },
        },
      });

      if (result?.sso_login_provider) {
        return {
          name: result.sso_login_provider.name,
          type: result.sso_login_provider.type,
        };
      }
      return null;
    } catch (error) {
      this.logger.error(
        `Error getting SSO provider by email: ${error.message}`,
      );
      return null;
    }
  }

  /**
   * Get SSO provider by TC handle
   */
  private async getSSOProviderByHandle(
    handle: string,
  ): Promise<IdentityProviderDto | null> {
    try {
      const result = await this.prismaClient.user_sso_login.findFirst({
        where: {
          user: {
            handle: handle,
          },
          sso_login_provider: {
            identify_handle_enabled: true,
          },
        },
        select: {
          sso_login_provider: {
            select: {
              name: true,
              type: true,
            },
          },
        },
      });

      if (result?.sso_login_provider) {
        return {
          name: result.sso_login_provider.name,
          type: result.sso_login_provider.type,
        };
      }
      return null;
    } catch (error) {
      this.logger.error(
        `Error getting SSO provider by handle: ${error.message}`,
      );
      return null;
    }
  }

  /**
   * Get social provider by social user ID
   */
  private async getSocialProviderByUserId(
    userId: string,
  ): Promise<IdentityProviderDto | null> {
    try {
      const result = await this.prismaClient.user_social_login.findFirst({
        where: {
          social_user_name: userId,
        },
        select: {
          social_login_provider: {
            select: {
              name: true,
            },
          },
        },
      });

      if (result?.social_login_provider) {
        return {
          name: result.social_login_provider.name,
          type: 'social',
        };
      }
      return null;
    } catch (error) {
      this.logger.error(
        `Error getting social provider by userId: ${error.message}`,
      );
      return null;
    }
  }

  /**
   * Get social provider by social user email
   */
  private async getSocialProviderByUserEmail(
    email: string,
  ): Promise<IdentityProviderDto | null> {
    try {
      const result = await this.prismaClient.user_social_login.findFirst({
        where: {
          social_email: {
            equals: email,
            mode: 'insensitive',
          },
        },
        select: {
          social_login_provider: {
            select: {
              name: true,
            },
          },
        },
      });

      if (result?.social_login_provider) {
        return {
          name: result.social_login_provider.name || 'unknown',
          type: 'social',
        };
      }
      return null;
    } catch (error) {
      this.logger.error(
        `Error getting social provider by email: ${error.message}`,
      );
      return null;
    }
  }

  /**
   * Create default provider - EXACT Java logic
   */
  private createDefaultProvider(): IdentityProviderDto {
    return {
      name: 'ldap',
      type: 'default',
    };
  }
}
