import { PrismaClient as TargetIdentityClient } from '@prisma/client';
import { PrismaClient as SourceIdentityClient } from '../legacy_migrate/generated/source-identity';

const DEFAULT_BATCH_SIZE = 1000;

const parseBoolFlag = (flag: string) => process.argv.includes(flag);

const requiredEnv = (key: string) => {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
};

async function migrateUserSocialLogin() {
  const dryRun = parseBoolFlag('--dry-run');
  const truncate = parseBoolFlag('--truncate');
  const batchSize = Number(process.env.USER_SOCIAL_LOGIN_BATCH_SIZE ?? DEFAULT_BATCH_SIZE);
  const insertMissingOnly = parseBoolFlag('--insert-missing-only');

  if (Number.isNaN(batchSize) || batchSize <= 0) {
    throw new Error(`Invalid USER_SOCIAL_LOGIN_BATCH_SIZE: ${process.env.USER_SOCIAL_LOGIN_BATCH_SIZE}`);
  }

  if (insertMissingOnly && truncate) {
    throw new Error('Cannot use --insert-missing-only together with --truncate');
  }

  const sourceDbUrl = requiredEnv('SOURCE_IDENTITY_PG_URL');
  const targetDbUrl = requiredEnv('IDENTITY_DB_URL');

  const sourceDb = new SourceIdentityClient({
    datasources: {
      db: { url: sourceDbUrl },
    },
  });

  const targetDb = new TargetIdentityClient({
    datasources: {
      db: { url: targetDbUrl },
    },
  });

  console.log(
    `Starting user_social_login migration (dryRun=${dryRun}, truncate=${truncate}, insertMissingOnly=${insertMissingOnly}, batchSize=${batchSize})`,
  );

  try {
    const totalRows = await sourceDb.user_social_login.count();
    if (!totalRows) {
      console.log('No rows found in source user_social_login. Nothing to migrate.');
      return;
    }

    console.log(`Found ${totalRows} rows to migrate from source user_social_login`);

    if (truncate) {
      if (dryRun) {
        console.log('[Dry Run] Would truncate target identity.user_social_login');
      } else {
        console.log('Truncating target identity.user_social_login before import...');
        await targetDb.$executeRaw`TRUNCATE TABLE identity.user_social_login RESTART IDENTITY CASCADE`;
      }
    }

    for (let offset = 0; offset < totalRows; offset += batchSize) {
      const batch = await sourceDb.user_social_login.findMany({
        orderBy: [{ user_id: 'asc' }, { social_login_provider_id: 'asc' }],
        skip: offset,
        take: batchSize,
      });

      if (!batch.length) {
        break;
      }

      if (dryRun) {
        console.log(`[Dry Run] Would migrate ${batch.length} rows (offset ${offset})`);
        continue;
      }

      const recordsToInsert = batch.map((record) => ({
          social_user_id: record.social_user_id ?? null,
          user_id: Number(record.user_id),
          social_login_provider_id: Number(record.social_login_provider_id),
          social_user_name: record.social_user_name,
          social_email: record.social_email ?? null,
          social_email_verified: record.social_email_verified ?? null,
          create_date: record.create_date ?? undefined,
          modify_date: record.modify_date ?? undefined,
        }));

      if (insertMissingOnly) {
        const existing = await targetDb.user_social_login.findMany({
          where: {
            OR: recordsToInsert.map((rec) => ({
              user_id: rec.user_id,
              social_login_provider_id: rec.social_login_provider_id,
            })),
          },
          select: {
            user_id: true,
            social_login_provider_id: true,
          },
        });

        const existingKey = new Set(existing.map((row) => `${row.user_id}-${row.social_login_provider_id}`));
        const missing = recordsToInsert.filter(
          (rec) => !existingKey.has(`${rec.user_id}-${rec.social_login_provider_id}`),
        );

        if (!missing.length) {
          console.log(`Batch at offset ${offset} skipped (all ${recordsToInsert.length} rows already present)`);
          continue;
        }

        await targetDb.user_social_login.createMany({
          data: missing,
          skipDuplicates: true,
        });

        console.log(
          `Migrated ${Math.min(offset + batch.length, totalRows)} / ${totalRows} rows (inserted ${missing.length}, skipped ${
            recordsToInsert.length - missing.length
          })`,
        );
        continue;
      }

      await targetDb.user_social_login.createMany({
        data: recordsToInsert,
        skipDuplicates: true,
      });

      console.log(`Migrated ${Math.min(offset + batch.length, totalRows)} / ${totalRows} rows`);
    }

    console.log('user_social_login migration completed');
  } finally {
    await Promise.allSettled([sourceDb.$disconnect(), targetDb.$disconnect()]);
  }
}

migrateUserSocialLogin().catch((error) => {
  console.error('user_social_login migration failed:', error);
  process.exit(1);
});
