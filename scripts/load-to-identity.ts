import { PrismaClient as IdentityClient } from '@prisma/client';

export interface UserTestData {
  handle: string;
  handleLower: string;
  firstName: string;
  lastName: string;
  userId: number;
  socialEmail?: string;
  ssoEmail?: string;
  email?: string;
}

export interface IdentityProviderData {
  name: string;
  type?: string;
  id: number;
}

export interface RoleData {
  name: string;
  id: number;
}

export const TEST_USERS: Record<string, UserTestData> = {
  gundam: {
    handle: 'gundam',
    handleLower: 'gundam',
    firstName: 'Gundam',
    lastName: 'RX',
    userId: 112233,
    email: 'gundam@email.com',
  },
  jmgasper: {
    handle: 'jmgasper',
    handleLower: 'jmgasper',
    firstName: 'Justin',
    lastName: 'Gasper',
    userId: 88774396,
    email: 'jmgasper@email.com',
  },
  mess: {
    handle: 'mess',
    handleLower: 'mess',
    firstName: 'Mess',
    lastName: 'User',
    userId: 12345,
    ssoEmail: 'SsoMess@email.com',
    email: 'mess@email.com',
  },
  alea: {
    handle: 'alea',
    handleLower: 'alea',
    firstName: 'Alea',
    lastName: 'User',
    userId: 11,
    email: 'alea@email.com',
  },
  ghostar: {
    handle: 'Ghostar',
    handleLower: 'ghostar',
    firstName: 'Ghost',
    lastName: 'Star',
    userId: 22,
    email: 'ghostar@email.com',
  },
  shindo: {
    handle: 'Shindo',
    handleLower: 'shindo',
    firstName: 'Shin',
    lastName: 'Do',
    userId: 33,
    socialEmail: 'ShInDo@email.com',
    email: 'shindo@email.com',
  },
  darla: {
    handle: 'darla',
    handleLower: 'darla',
    firstName: 'Darla',
    lastName: 'Jane',
    userId: 44,
    ssoEmail: 'darla@email.com',
    email: 'darla@email.com',
  },
  gunggong: {
    handle: 'gunggong',
    handleLower: 'gunggong',
    firstName: 'Gung',
    lastName: 'Gong',
    userId: 55,
    email: 'gunggong@email.com',
  },
};

export const SSO_PROVIDERS: Record<string, IdentityProviderData> = {
  facebook: {
    name: 'facebook',
    type: 'sso',
    id: 1,
  },
  github: {
    name: 'github',
    type: 'sso',
    id: 4,
  },
  googleoauth2: {
    name: 'google-oauth2',
    type: 'sso',
    id: 2,
  },
  twitter: {
    name: 'twitter',
    type: 'sso',
    id: 3,
  },
  auth0: {
    name: 'auth0',
    type: 'sso',
    id: 200,
  },
};

export const SOCIAL_PROVIDERS: Record<string, IdentityProviderData> = {
  facebook: {
    name: 'facebook',
    id: 1,
  },
  google: {
    name: 'google',
    id: 2,
  },
  twitter: {
    name: 'twitter',
    id: 3,
  },
};

export const ROLES: Record<string, RoleData> = {
  administrator: {
    name: 'administrator',
    id: 1000,
  },
  copilot: {
    name: 'copilot',
    id: 1001,
  },
  submitter: {
    name: 'submitter',
    id: 1002,
  },
  tcuser: {
    name: 'Topcoder User',
    id: 1003,
  },
  tctalent: {
    name: 'Topcoder Talent',
    id: 1004,
  },
};

// Database clients
const identityDb = new IdentityClient({
  datasources: {
    db: {
      url: 'postgresql://postgres:identitypassword@localhost:5432/identity',
    },
  },
});

async function loadData() {
  console.log('Starting identity schema load (Raw SQL approach)...');

  try {
    // Step 1: clear tables
    await clearTables();

    // Step 2: load data
    await loadDataToTables();

    console.log('Migration completed successfully!');
  } catch (error) {
    console.error('Migration failed:', error);
    throw error;
  }
}

async function clearTables() {
  console.log('Clearing contents of tables...');

  await identityDb.user_email_xref.deleteMany({});
  await identityDb.user_otp_email.deleteMany({});
  await identityDb.security_user.deleteMany({});
  await identityDb.email.deleteMany({});
  await identityDb.user_2fa.deleteMany({});
  await identityDb.user_social_login.deleteMany({});
  await identityDb.social_login_provider.deleteMany({});
  await identityDb.user_sso_login.deleteMany({});
  await identityDb.sso_login_provider.deleteMany({});
  await identityDb.user_achievement.deleteMany({});
  await identityDb.achievement_type_lu.deleteMany({});
  await identityDb.email.deleteMany({});
  await identityDb.email_status_lu.deleteMany({});
  await identityDb.email_type_lu.deleteMany({});
  await identityDb.roleAssignment.deleteMany({});
  await identityDb.role.deleteMany({});
  await identityDb.user.deleteMany({});

  console.log('Tables cleared');
}

async function loadDataToTables() {
  console.log('Loading data to tables...');

  await identityDb.achievement_type_lu.createMany({
    data: [
      {
        achievement_type_id: 1,
        achievement_type_desc: 'achievement_type_1',
      },
      {
        achievement_type_id: 2,
        achievement_type_desc: 'achievement_type_2',
      },
    ],
  });

  await identityDb.role.createMany({
    data: [
      {
        name: ROLES.administrator.name,
        createdBy: 1,
        id: ROLES.administrator.id,
      },
      { name: ROLES.copilot.name, createdBy: 1, id: ROLES.copilot.id },
      { name: ROLES.submitter.name, createdBy: 1, id: ROLES.submitter.id },
      { name: ROLES.tcuser.name, createdBy: 1, id: ROLES.tcuser.id },
      { name: ROLES.tctalent.name, createdBy: 1, id: ROLES.tctalent.id },
    ],
  });

  await identityDb.user.createMany({
    data: [
      {
        handle: TEST_USERS.gundam.handle,
        handle_lower: TEST_USERS.gundam.handleLower,
        first_name: TEST_USERS.gundam.firstName,
        last_name: TEST_USERS.gundam.lastName,
        status: 'A',
        user_id: TEST_USERS.gundam.userId,
        reg_source: 'reg1',
        utm_campaign: 'camp1',
        utm_medium: 'medium1',
        utm_source: 'source1',
      },
      {
        handle: TEST_USERS.jmgasper.handle,
        handle_lower: TEST_USERS.jmgasper.handleLower,
        first_name: TEST_USERS.jmgasper.firstName,
        last_name: TEST_USERS.jmgasper.lastName,
        status: 'A',
        user_id: TEST_USERS.jmgasper.userId,
        reg_source: 'reg2',
        utm_campaign: 'camp2',
        utm_medium: 'medium2',
        utm_source: 'source2',
      },
      {
        handle: TEST_USERS.mess.handle,
        handle_lower: TEST_USERS.mess.handleLower,
        first_name: TEST_USERS.mess.firstName,
        last_name: TEST_USERS.mess.lastName,
        status: 'A',
        user_id: TEST_USERS.mess.userId,
        reg_source: 'reg3',
        utm_campaign: 'camp3',
        utm_medium: 'medium3',
        utm_source: 'source3',
      },
      {
        handle: TEST_USERS.alea.handle,
        handle_lower: TEST_USERS.alea.handleLower,
        first_name: TEST_USERS.alea.firstName,
        last_name: TEST_USERS.alea.lastName,
        status: 'A',
        user_id: TEST_USERS.alea.userId,
        reg_source: 'reg4',
        utm_campaign: 'camp4',
        utm_medium: 'medium4',
        utm_source: 'source4',
      },
      {
        handle: TEST_USERS.ghostar.handle,
        handle_lower: TEST_USERS.ghostar.handleLower,
        first_name: TEST_USERS.ghostar.firstName,
        last_name: TEST_USERS.ghostar.lastName,
        status: 'A',
        user_id: TEST_USERS.ghostar.userId,
        reg_source: 'reg5',
        utm_campaign: 'camp5',
        utm_medium: 'medium5',
        utm_source: 'source5',
      },
      {
        handle: TEST_USERS.shindo.handle,
        handle_lower: TEST_USERS.shindo.handleLower,
        first_name: TEST_USERS.shindo.firstName,
        last_name: TEST_USERS.shindo.lastName,
        status: 'A',
        user_id: TEST_USERS.shindo.userId,
        reg_source: 'reg6',
        utm_campaign: 'camp6',
        utm_medium: 'medium6',
        utm_source: 'source6',
      },
      {
        handle: TEST_USERS.darla.handle,
        handle_lower: TEST_USERS.darla.handleLower,
        first_name: TEST_USERS.darla.firstName,
        last_name: TEST_USERS.darla.lastName,
        status: 'A',
        user_id: TEST_USERS.darla.userId,
        reg_source: 'reg6',
        utm_campaign: 'camp6',
        utm_medium: 'medium6',
        utm_source: 'source6',
      },
      {
        handle: TEST_USERS.gunggong.handle,
        handle_lower: TEST_USERS.gunggong.handleLower,
        first_name: TEST_USERS.gunggong.firstName,
        last_name: TEST_USERS.gunggong.lastName,
        status: 'U',
        user_id: TEST_USERS.gunggong.userId,
        reg_source: 'reg7',
        utm_campaign: 'camp7',
        utm_medium: 'medium7',
        utm_source: 'source7',
      },
    ],
  });

  await identityDb.roleAssignment.createMany({
    data: [
      {
        roleId: ROLES.administrator.id,
        subjectId: TEST_USERS.gundam.userId,
        subjectType: 1,
      },
      {
        roleId: ROLES.tcuser.id,
        subjectId: TEST_USERS.jmgasper.userId,
        subjectType: 1,
      },
    ],
  });

  await identityDb.sso_login_provider.createMany({
    data: [
      {
        name: SSO_PROVIDERS.facebook.name,
        type: SSO_PROVIDERS.facebook.type,
        sso_login_provider_id: SSO_PROVIDERS.facebook.id,
        identify_handle_enabled: true,
      },
      {
        name: SSO_PROVIDERS.github.name,
        type: SSO_PROVIDERS.github.type,
        sso_login_provider_id: SSO_PROVIDERS.github.id,
        identify_email_enabled: true,
      },
      {
        name: SSO_PROVIDERS.googleoauth2.name,
        type: SSO_PROVIDERS.googleoauth2.type,
        sso_login_provider_id: SSO_PROVIDERS.googleoauth2.id,
        identify_email_enabled: true,
        identify_handle_enabled: false,
      },
      {
        name: SSO_PROVIDERS.twitter.name,
        type: SSO_PROVIDERS.twitter.type,
        sso_login_provider_id: SSO_PROVIDERS.twitter.id,
        identify_handle_enabled: true,
        identify_email_enabled: false,
      },
      {
        name: SSO_PROVIDERS.auth0.name,
        type: SSO_PROVIDERS.auth0.type,
        sso_login_provider_id: SSO_PROVIDERS.auth0.id,
      },
    ],
  });

  await identityDb.social_login_provider.createMany({
    data: [
      {
        name: SOCIAL_PROVIDERS.facebook.name,
        social_login_provider_id: SOCIAL_PROVIDERS.facebook.id,
      },
      {
        name: SOCIAL_PROVIDERS.google.name,
        social_login_provider_id: SOCIAL_PROVIDERS.google.id,
      },
      {
        name: SOCIAL_PROVIDERS.twitter.name,
        social_login_provider_id: SOCIAL_PROVIDERS.twitter.id,
      },
    ],
  });

  await identityDb.user_social_login.createMany({
    data: [
      {
        social_login_provider_id: SOCIAL_PROVIDERS.facebook.id,
        user_id: TEST_USERS.ghostar.userId,
        social_user_name: TEST_USERS.ghostar.handleLower,
        social_user_id: '123456',
      },
      {
        social_login_provider_id: SOCIAL_PROVIDERS.google.id,
        user_id: TEST_USERS.shindo.userId,
        social_user_name: 'anotherFB',
        social_email: TEST_USERS.shindo.socialEmail,
        social_user_id: '321',
      },
    ],
  });

  await identityDb.user_sso_login.createMany({
    data: [
      {
        sso_user_id: TEST_USERS.jmgasper.handle,
        provider_id: SSO_PROVIDERS.facebook.id,
        user_id: TEST_USERS.jmgasper.userId,
      },
      {
        sso_user_id: '33',
        provider_id: SSO_PROVIDERS.googleoauth2.id,
        user_id: TEST_USERS.mess.userId,
        email: TEST_USERS.mess.ssoEmail,
      },
      {
        sso_user_id: '1',
        provider_id: SSO_PROVIDERS.twitter.id,
        user_id: TEST_USERS.alea.userId,
      },
      {
        sso_user_id: 'asdf',
        provider_id: SSO_PROVIDERS.googleoauth2.id,
        user_id: TEST_USERS.gunggong.userId,
      },
      {
        sso_user_id: 'darla',
        provider_id: SSO_PROVIDERS.twitter.id,
        user_id: TEST_USERS.darla.userId,
        email: TEST_USERS.darla.ssoEmail,
      },
    ],
  });

  await identityDb.email_status_lu.createMany({
    data: [
      {
        status_id: 1,
      },
      {
        status_id: 2,
      },
    ],
  });
  await identityDb.email_type_lu.createMany({
    data: [
      {
        email_type_id: 1,
      },
    ],
  });
  await identityDb.email.createMany({
    data: [
      {
        email_id: 200,
        email_type_id: 1,
        status_id: 1,
        address: TEST_USERS.gundam.email,
        user_id: TEST_USERS.gundam.userId,
        primary_ind: 1,
      },
      {
        email_id: 201,
        email_type_id: 1,
        status_id: 1,
        address: 'forTest@email.com',
        primary_ind: 1,
      },
      {
        email_id: 202,
        email_type_id: 1,
        status_id: 1,
        address: TEST_USERS.jmgasper.email,
        user_id: TEST_USERS.jmgasper.userId,
        primary_ind: 1,
      },
      {
        email_id: 203,
        email_type_id: 1,
        status_id: 1,
        address: TEST_USERS.ghostar.email,
        user_id: TEST_USERS.ghostar.userId,
        primary_ind: 1,
      },
      {
        email_id: 204,
        email_type_id: 1,
        status_id: 1,
        address: TEST_USERS.mess.email,
        user_id: TEST_USERS.mess.userId,
        primary_ind: 1,
      },
      {
        email_id: 205,
        email_type_id: 1,
        status_id: 1,
        address: TEST_USERS.gunggong.email,
        user_id: TEST_USERS.gunggong.userId,
        primary_ind: 1,
      },
    ],
  });
  await identityDb.user_email_xref.createMany({
    data: [
      {
        user_id: TEST_USERS.gundam.userId,
        email_id: 200,
        is_primary: true,
        status_id: 1,
      },
    ],
  });
  await identityDb.user_achievement.createMany({
    data: [
      {
        user_id: TEST_USERS.jmgasper.userId,
        create_date: '2025-08-15T08:09:49.583Z',
        achievement_date: '2025-08-15T08:09:49.583Z',
        achievement_type_id: 1,
      },
      {
        user_id: TEST_USERS.jmgasper.userId,
        create_date: '2025-08-15T08:09:50.583Z',
        achievement_date: '2025-08-15T08:09:50.583Z',
        achievement_type_id: 2,
      },
    ],
  });
  await identityDb.security_user.createMany({
    data: [
      {
        user_id: TEST_USERS.gundam.handle,
        login_id: TEST_USERS.gundam.userId,
        password: 'GXsL6hOWQK4=',
      },
    ],
  });
  await identityDb.user_2fa.createMany({
    data: [
      {
        user_id: TEST_USERS.shindo.userId,
        mfa_enabled: true,
        modified_by: '1',
        created_by: '1',
      },
    ],
  });

  console.log('Lookup tables migrated');
}

// Verification function
async function verifyMigration() {
  console.log('Verifying migration...');

  const userCount = await identityDb.$queryRaw<
    { count: bigint }[]
  >`SELECT COUNT(*) as count FROM "user";`;
  const ssoLoginProviderCount = await identityDb.$queryRaw<
    { count: bigint }[]
  >`SELECT COUNT(*) as count FROM "sso_login_provider";`;
  const socialLoginProviderCount = await identityDb.$queryRaw<
    { count: bigint }[]
  >`SELECT COUNT(*) as count FROM "social_login_provider";`;
  const ssoLoginUserCount = await identityDb.$queryRaw<
    { count: bigint }[]
  >`SELECT COUNT(*) as count FROM "user_sso_login";`;
  const socialLoginUserCount = await identityDb.$queryRaw<
    { count: bigint }[]
  >`SELECT COUNT(*) as count FROM "user_social_login";`;
  const rolesCount = await identityDb.$queryRaw<
    { count: bigint }[]
  >`SELECT COUNT(*) as count FROM "role";`;
  const roleAssignmentCount = await identityDb.$queryRaw<
    { count: bigint }[]
  >`SELECT COUNT(*) as count FROM "role_assignment";`;

  console.log(`Data load verification:
    - Users: ${userCount[0].count}
    - SSO Login Provider: ${ssoLoginProviderCount[0].count}
    - User SSO Login: ${ssoLoginUserCount[0].count}
    - Social Login Provider: ${socialLoginProviderCount[0].count}
    - User Social Login: ${socialLoginUserCount[0].count}
    - Roles: ${rolesCount[0].count}
    - Role Assignment: ${roleAssignmentCount[0].count}
  `);
}

// Main execution
async function main() {
  try {
    await loadData();
    await verifyMigration();
  } catch (error) {
    console.error('Data load failed:', error);
    process.exit(1);
  } finally {
    await identityDb.$disconnect();
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

export { main as migrateData, verifyMigration };
