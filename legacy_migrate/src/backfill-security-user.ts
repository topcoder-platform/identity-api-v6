/* eslint-disable no-console */
import 'dotenv/config';

import type {
  Prisma as SourcePrismaNamespace,
  PrismaClient as SourceIdentityPrismaClient,
} from '../generated/source-identity';
import type { PrismaClient as TargetPrismaClient } from '../generated/target';

const sourceModule = require('../generated/source-identity') as typeof import('../generated/source-identity');
const targetModule = require('../generated/target') as typeof import('../generated/target');

const SourceIdentityPrisma: new () => SourceIdentityPrismaClient = sourceModule.PrismaClient;
const TargetPrisma: new () => TargetPrismaClient = targetModule.PrismaClient;
const SourcePrisma = sourceModule.Prisma;
const { Prisma } = targetModule;

interface CliOptions {
  since?: Date;
  apply: boolean;
  helpRequested?: boolean;
}

interface SecurityUserRecord {
  loginId: string;
  userId: string;
  password: string;
  createUserId: string | null;
  modifyDate: Date | null;
}

interface TargetUserWithoutSecurityUser {
  loginId: string;
  handle: string | null;
  createDate: Date | null;
}

const SOURCE_FETCH_BATCH_SIZE = 500;
const TARGET_INSERT_BATCH_SIZE = 250;
const DATE_FORMAT_EXAMPLE = new Date().toISOString();

async function main(): Promise<void> {
  try {
    const options = parseCliOptions(process.argv.slice(2));

    if (options.helpRequested) {
      printUsage();
      return;
    }

    const sourceUrl = process.env.SOURCE_IDENTITY_PG_URL;
    const targetUrl = process.env.IDENTITY_DB_URL;

    if (!sourceUrl) {
      throw new Error('Environment variable SOURCE_IDENTITY_PG_URL must be set.');
    }
    if (!targetUrl) {
      throw new Error('Environment variable IDENTITY_DB_URL must be set.');
    }

    console.log(`[config] Source identity DB: ${summarizeConnection(sourceUrl)}`);
    console.log(`[config] Target identity DB: ${summarizeConnection(targetUrl)}`);

    if (options.since) {
      console.log(
        `[config] Filtering source rows where modify_date ≥ ${options.since.toISOString()}`
      );
    } else {
      console.warn('[config] No --since filter provided; scanning the entire security_user table.');
    }

    console.log(
      `[config] Mode: ${options.apply ? 'apply (will insert missing records)' : 'dry-run (no writes)'}`
    );

    const sourcePrisma = new SourceIdentityPrisma();
    const targetPrisma = new TargetPrisma();

    try {
      const candidateRecords = new Map<string, SecurityUserRecord>();

      const candidates = await loadSecurityUserRecords(sourcePrisma, options.since);

      if (candidates.length === 0) {
        console.log('[load] Source modify_date scan returned 0 candidate records.');
      } else {
        console.log(
          `[load] Loaded ${candidates.length} candidate records from the source identity database.`
        );
        candidates.forEach((record) => candidateRecords.set(record.loginId, record));
      }

      const targetGaps = await loadUsersMissingSecurityUser(targetPrisma, options.since);
      if (targetGaps.length > 0) {
        console.log(
          `[load] Found ${targetGaps.length} users in the target database without a security_user record.`
        );
        const gapLoginIds = targetGaps.map((gap) => gap.loginId);
        const gapRecords = await loadSecurityUserRecordsByLoginIds(sourcePrisma, gapLoginIds);
        console.log(
          `[load] Retrieved ${gapRecords.length} matching security_user records from the source database for target gaps.`
        );

        const foundSet = new Set(gapRecords.map((record) => record.loginId));
        const unresolvedGaps = targetGaps.filter((gap) => !foundSet.has(gap.loginId));
        if (unresolvedGaps.length > 0) {
          const sampleHandles = unresolvedGaps
            .slice(0, 10)
            .map((gap) => gap.handle ?? gap.loginId)
            .join(', ');
          console.warn(
            `[warn] ${unresolvedGaps.length} target users lack a matching security_user row in the source database. Examples: ${sampleHandles}${
              unresolvedGaps.length > 10 ? '…' : ''
            }`
          );
        }

        gapRecords.forEach((record) => candidateRecords.set(record.loginId, record));
      } else {
        console.log('[load] No users in the target database are missing security_user rows.');
      }

      if (candidateRecords.size === 0) {
        console.log('[result] No candidate security_user records to process after applying filters.');
        return;
      }

      console.log(
        `[load] Combined candidate set contains ${candidateRecords.size} unique security_user rows.`
      );

      const missingRecords = await findMissingRecords(targetPrisma, Array.from(candidateRecords.values()));

      if (missingRecords.length === 0) {
        console.log('[result] All candidate records already exist in the target database.');
        return;
      }

      console.log(
        `[result] Found ${missingRecords.length} security_user records missing from the target database.`
      );

      if (!options.apply) {
        console.log('[result] Dry-run mode. Handles that would be inserted:');
        missingRecords
          .map((record) => record.userId)
          .sort((a, b) => a.localeCompare(b))
          .forEach((handle) => console.log(`  - ${handle}`));
        console.log('[hint] Re-run with --apply to insert the missing records.');
        return;
      }

      const insertedCount = await insertMissingRecords(targetPrisma, missingRecords);
      console.log(`[result] Inserted ${insertedCount} security_user records into the target database.`);
    } finally {
      await sourcePrisma.$disconnect();
      await targetPrisma.$disconnect();
    }
  } catch (error) {
    console.error(
      '[error] Backfill failed:',
      error instanceof Error ? error.stack ?? error.message : error
    );
    process.exitCode = 1;
  }
}

function parseCliOptions(argv: string[]): CliOptions {
  const options: CliOptions = {
    apply: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--help' || arg === '-h') {
      options.helpRequested = true;
      break;
    }

    if (arg === '--apply') {
      options.apply = true;
      continue;
    }

    if (arg === '--since' || arg === '--after') {
      const value = argv[i + 1];
      if (!value) {
        throw new Error(`${arg} expects an ISO-8601 timestamp (example: ${DATE_FORMAT_EXAMPLE})`);
      }
      options.since = parseSince(value);
      i += 1;
      continue;
    }

    if (arg.startsWith('--since=')) {
      options.since = parseSince(arg.substring('--since='.length));
      continue;
    }

    if (arg.startsWith('--after=')) {
      options.since = parseSince(arg.substring('--after='.length));
      continue;
    }

    throw new Error(`Unrecognized argument: ${arg}`);
  }

  return options;
}

function printUsage(): void {
  console.log(`Backfill missing identity.security_user records

Usage:
  node -r ts-node/register src/backfill-security-user.ts --since <ISO> [--apply]

Options:
  --since <ISO>      Limit the source modify_date scan and target user create_date gap check to this timestamp
  --apply            Insert missing records (default: dry-run prints handles only)
  -h, --help         Show this message

Examples:
  node -r ts-node/register src/backfill-security-user.ts --since 2025-02-01T00:00:00Z
  node -r ts-node/register src/backfill-security-user.ts --apply --since 2025-02-01T00:00:00Z`);
}

function parseSince(raw: string): Date {
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`Invalid ISO-8601 timestamp: ${raw}. Example: ${DATE_FORMAT_EXAMPLE}`);
  }
  return parsed;
}

async function loadSecurityUserRecords(
  prisma: SourceIdentityPrismaClient,
  since?: Date
): Promise<SecurityUserRecord[]> {
  console.log('[load] Fetching security_user rows from the source database...');
  const where: Record<string, unknown> = {};
  if (since) {
    where.modify_date = { gte: since };
  }

  const records: SecurityUserRecord[] = [];
  type Cursor = { login_id: SourcePrismaNamespace.Decimal };
  let cursor: Cursor | undefined;

  while (true) {
    const batch = await prisma.security_user.findMany({
      where,
      orderBy: { login_id: 'asc' },
      cursor,
      skip: cursor ? 1 : 0,
      take: SOURCE_FETCH_BATCH_SIZE,
    });

    if (batch.length === 0) {
      break;
    }

    batch.forEach((row) => {
      records.push({
        loginId: row.login_id.toString(),
        userId: row.user_id,
        password: row.password,
        createUserId: row.create_user_id ? row.create_user_id.toString() : null,
        modifyDate: row.modify_date ?? null,
      });
    });

    cursor = { login_id: batch[batch.length - 1].login_id };
    if (records.length % 5000 < batch.length) {
      console.log(`[load] ... fetched ${records.length} records so far`);
    }
  }

  console.log(`[load] Completed source fetch. Retrieved ${records.length} records.`);
  return records;
}

async function loadSecurityUserRecordsByLoginIds(
  prisma: SourceIdentityPrismaClient,
  loginIds: string[]
): Promise<SecurityUserRecord[]> {
  if (loginIds.length === 0) {
    return [];
  }

  const records: SecurityUserRecord[] = [];
  for (let i = 0; i < loginIds.length; i += SOURCE_FETCH_BATCH_SIZE) {
    const chunk = loginIds.slice(i, i + SOURCE_FETCH_BATCH_SIZE);
    const rows = await prisma.security_user.findMany({
      where: { login_id: { in: chunk.map((value) => new SourcePrisma.Decimal(value)) } },
    });

    rows.forEach((row) => {
      records.push({
        loginId: row.login_id.toString(),
        userId: row.user_id,
        password: row.password,
        createUserId: row.create_user_id ? row.create_user_id.toString() : null,
        modifyDate: row.modify_date ?? null,
      });
    });
  }
  return records;
}

async function loadUsersMissingSecurityUser(
  prisma: TargetPrismaClient,
  since?: Date
): Promise<TargetUserWithoutSecurityUser[]> {
  const rows = await prisma.$queryRaw<
    Array<{ user_id: string; handle: string | null; create_date: Date | null }>
  >(
    Prisma.sql`
      SELECT
        u.user_id::text AS user_id,
        u.handle,
        u.create_date
      FROM identity."user" AS u
      LEFT JOIN identity.security_user AS s
        ON u.user_id = s.login_id
      WHERE s.login_id IS NULL
      ${since ? Prisma.sql`AND u.create_date >= ${since}` : Prisma.empty}
      ORDER BY u.create_date DESC NULLS LAST
    `
  );

  return rows.map((row) => ({
    loginId: row.user_id,
    handle: row.handle,
    createDate: row.create_date,
  }));
}

async function findMissingRecords(
  prisma: TargetPrismaClient,
  records: SecurityUserRecord[]
): Promise<SecurityUserRecord[]> {
  const missing: SecurityUserRecord[] = [];
  const chunkSize = 500;

  for (let i = 0; i < records.length; i += chunkSize) {
    const chunk = records.slice(i, i + chunkSize);
    const loginIds = chunk.map((record) => new Prisma.Decimal(record.loginId));
    const existing = await prisma.security_user.findMany({
      where: { login_id: { in: loginIds } },
      select: { login_id: true },
    });

    const existingSet = new Set(existing.map((row) => row.login_id.toString()));
    chunk.forEach((record) => {
      if (!existingSet.has(record.loginId)) {
        missing.push(record);
      }
    });
  }

  return missing;
}

async function insertMissingRecords(
  prisma: TargetPrismaClient,
  records: SecurityUserRecord[]
): Promise<number> {
  let totalInserted = 0;

  for (let i = 0; i < records.length; i += TARGET_INSERT_BATCH_SIZE) {
    const chunk = records.slice(i, i + TARGET_INSERT_BATCH_SIZE);
    const data = chunk.map((record) => ({
      login_id: new Prisma.Decimal(record.loginId),
      user_id: record.userId,
      password: record.password,
      create_user_id: record.createUserId ? new Prisma.Decimal(record.createUserId) : null,
      modify_date: record.modifyDate ?? null,
    }));

    const result = await prisma.security_user.createMany({
      data,
      skipDuplicates: true,
    });

    totalInserted += result.count ?? chunk.length;
  }

  return totalInserted;
}

function summarizeConnection(raw: string): string {
  try {
    const parsed = new URL(raw);
    const hostPart = `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ''}${parsed.pathname}`;
    const authStatus =
      parsed.username || parsed.password ? 'credentials set' : 'no credentials';
    const queryStatus = parsed.search ? 'query params present' : 'no query params';
    return `${hostPart} (${authStatus}; ${queryStatus})`;
  } catch (err: any) {
    return `unable to parse connection string (${err.message ?? 'unknown error'})`;
  }
}

void main();
