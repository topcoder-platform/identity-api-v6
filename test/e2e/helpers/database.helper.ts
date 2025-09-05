import { PrismaClient } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';

export class DatabaseHelper {
  private prisma: PrismaClient;

  constructor() {
    this.prisma = new PrismaClient({
      datasources: {
        db: {
          url:
            process.env.IDENTITY_DB_URL ||
            'postgresql://postgres:postgres@localhost:5432/identity_test2',
        },
      },
    });
  }

  async connect() {
    await this.prisma.$connect();
  }

  async disconnect() {
    await this.prisma.$disconnect();
  }

  async cleanDatabase() {
    // Clean in reverse order of dependencies
    await this.prisma.user_sso_login.deleteMany({});
    await this.prisma.user_social_login.deleteMany({});
    await this.prisma.user_achievement.deleteMany({});
    await this.prisma.user_2fa.deleteMany({});
    await this.prisma.sso_login_provider.deleteMany({});
    await this.prisma.social_login_provider.deleteMany({});
    await this.prisma.user.deleteMany({});
  }

  async createUser(data: {
    user_id: number;
    handle: string;
    first_name?: string;
    last_name?: string;
    status?: string;
    handle_lower?: string;
  }) {
    return await this.prisma.user.create({
      data: {
        user_id: new Decimal(data.user_id),
        handle: data.handle,
        first_name: data.first_name || 'Test',
        last_name: data.last_name || 'User',
        status: data.status || 'A',
        handle_lower: data.handle_lower || data.handle.toLowerCase(),
        create_date: new Date(),
        modify_date: new Date(),
      },
    });
  }

  async createSSOProvider(data: {
    sso_login_provider_id: number;
    name: string;
    type: string;
    identify_email_enabled?: boolean;
    identify_handle_enabled?: boolean;
  }) {
    return await this.prisma.sso_login_provider.create({
      data: {
        sso_login_provider_id: new Decimal(data.sso_login_provider_id),
        name: data.name,
        type: data.type,
        identify_email_enabled: data.identify_email_enabled ?? true,
        identify_handle_enabled: data.identify_handle_enabled ?? true,
      },
    });
  }

  async createSocialProvider(data: {
    social_login_provider_id: number;
    name: string;
  }) {
    return await this.prisma.social_login_provider.create({
      data: {
        social_login_provider_id: new Decimal(data.social_login_provider_id),
        name: data.name,
      },
    });
  }

  async createUserSSOLogin(data: {
    user_id: number;
    sso_user_id: string;
    provider_id: number;
    email?: string;
    sso_user_name?: string;
  }) {
    return await this.prisma.user_sso_login.create({
      data: {
        user_id: new Decimal(data.user_id),
        sso_user_id: data.sso_user_id,
        provider_id: new Decimal(data.provider_id),
        email: data.email,
        sso_user_name: data.sso_user_name,
      },
    });
  }

  async createUserSocialLogin(data: {
    user_id: number;
    social_login_provider_id: number;
    social_user_name: string;
    social_email?: string;
    social_user_id?: string;
    social_email_verified?: boolean;
  }) {
    return await this.prisma.user_social_login.create({
      data: {
        user_id: new Decimal(data.user_id),
        social_login_provider_id: new Decimal(data.social_login_provider_id),
        social_user_name: data.social_user_name,
        social_email: data.social_email,
        social_user_id: data.social_user_id,
        social_email_verified: data.social_email_verified,
      },
    });
  }

  async seedTestData() {
    // Create test users
    await this.createUser({
      user_id: 1001,
      handle: 'test_user_sso',
      first_name: 'SSO',
      last_name: 'User',
    });

    await this.createUser({
      user_id: 1002,
      handle: 'test_user_social',
      first_name: 'Social',
      last_name: 'User',
    });

    await this.createUser({
      user_id: 1003,
      handle: 'test_user_mixed',
      first_name: 'Mixed',
      last_name: 'User',
    });

    await this.createUser({
      user_id: 1004,
      handle: 'test_user_ldap',
      first_name: 'LDAP',
      last_name: 'User',
    });

    // Create SSO providers
    await this.createSSOProvider({
      sso_login_provider_id: 101,
      name: 'okta',
      type: 'OIDC',
      identify_email_enabled: true,
      identify_handle_enabled: true,
    });

    await this.createSSOProvider({
      sso_login_provider_id: 102,
      name: 'azure-ad',
      type: 'SAML',
      identify_email_enabled: true,
      identify_handle_enabled: false,
    });

    await this.createSSOProvider({
      sso_login_provider_id: 103,
      name: 'ping-identity',
      type: 'OIDC',
      identify_email_enabled: false,
      identify_handle_enabled: true,
    });

    // Create Social providers
    await this.createSocialProvider({
      social_login_provider_id: 201,
      name: 'google',
    });

    await this.createSocialProvider({
      social_login_provider_id: 202,
      name: 'github',
    });

    await this.createSocialProvider({
      social_login_provider_id: 203,
      name: 'facebook',
    });

    // Create SSO login entries
    await this.createUserSSOLogin({
      user_id: 1001,
      sso_user_id: 'sso_user_001',
      provider_id: 101,
      email: 'ssouser@example.com',
      sso_user_name: 'SSO User 001',
    });

    await this.createUserSSOLogin({
      user_id: 1003,
      sso_user_id: 'sso_user_003',
      provider_id: 102,
      email: 'mixed@example.com',
      sso_user_name: 'Mixed User 003',
    });

    // Create Social login entries
    await this.createUserSocialLogin({
      user_id: 1002,
      social_login_provider_id: 201,
      social_user_name: 'social_user_002',
      social_email: 'socialuser@gmail.com',
      social_user_id: 'google_12345',
      social_email_verified: true,
    });

    await this.createUserSocialLogin({
      user_id: 1003,
      social_login_provider_id: 202,
      social_user_name: 'mixed_social_003',
      social_email: 'mixed@github.com',
      social_user_id: 'github_67890',
      social_email_verified: true,
    });
  }
}
