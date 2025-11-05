/* eslint-disable no-console */
import { createReadStream, existsSync, readFileSync } from 'fs';
import { resolve, extname } from 'path';
import readline from 'node:readline';
import { Prisma, PrismaClient } from '@prisma/client';

type DecimalInput = string | number | Prisma.Decimal;

interface CliOptions {
  useExport: boolean;
  exportPath: string;
  since?: Date;
  apply: boolean;
  helpRequested?: boolean;
}

interface RawSecurityUserRecord {
  login_id?: DecimalInput;
  loginId?: DecimalInput;
  LOGIN_ID?: DecimalInput;
  user_id?: string;
  userId?: string;
  USER_ID?: string;
  password?: string;
  PASSWORD?: string;
  create_user_id?: DecimalInput | null;
  createUserId?: DecimalInput | null;
  CREATE_USER_ID?: DecimalInput | null;
  modify_date?: string | Date | null;
  modifyDate?: string | Date | null;
  MODIFY_DATE?: string | Date | null;
  [key: string]: unknown;
}

interface SecurityUserRecord {
  loginId: string;
  userId: string;
  password: string;
  createUserId: string | null;
  modifyDate: Date | null;
}

const DEFAULT_EXPORT_PATH = resolve(
  process.cwd(),
  'legacy_migrate',
  'logs',
  'sourceIdentity.security_user.ndjson'
);

const SOURCE_IDENTITY_ENV = 'SOURCE_IDENTITY_PG_URL';
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

    if (!options.useExport && !process.env[SOURCE_IDENTITY_ENV]) {
      throw new Error(
        `Environment variable ${SOURCE_IDENTITY_ENV} is not set. Provide it or run with --export to read from a file.`
      );
    }

    let exportPath: string | undefined;
    if (options.useExport) {
      exportPath = resolveExportPath(options.exportPath);
      console.log(`[config] Source: export file ${exportPath}`);
    } else {
      console.log(
        `[config] Source: database ${summarizeConnection(process.env[SOURCE_IDENTITY_ENV]!)}`
      );
    }

    if (options.since) {
      console.log(`[config] Filtering records with modify_date ≥ ${options.since.toISOString()}`);
    } else {
      console.log('[config] No --since filter provided; all source rows will be inspected.');
    }
    console.log(
      `[config] Mode: ${options.apply ? 'apply (will insert missing records)' : 'dry-run (no writes)'}`
    );

    const targetPrisma = new PrismaClient();
    let sourcePrisma: PrismaClient | null = null;

    try {
      const records = options.useExport
        ? await loadSecurityUserRecordsFromFile(exportPath!, options.since)
        : await loadSecurityUserRecordsFromSourceDb(
            (sourcePrisma = createSourceIdentityClient()),
            options.since
          );

      if (records.length === 0) {
        console.log(
          `[result] No candidate records found in ${
            options.useExport ? 'export' : 'source database'
          } after applying filters.`
        );
        return;
      }

      console.log(
        `[load] Loaded ${records.length} candidate records from ${
          options.useExport ? 'export' : 'source database'
        }.`
      );

      const missingRecords = await findMissingRecords(targetPrisma, records);

      if (missingRecords.length === 0) {
        console.log('[result] All records already exist in the target database. Nothing to do.');
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
      console.log(`[result] Inserted ${insertedCount} security_user records.`);
    } finally {
      await targetPrisma.$disconnect();
      if (sourcePrisma) {
        await sourcePrisma.$disconnect();
      }
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
    useExport: false,
    exportPath: DEFAULT_EXPORT_PATH,
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

    if (arg === '--export' || arg === '--input' || arg === '--file') {
      options.useExport = true;
      const value = argv[i + 1];
      if (value && !value.startsWith('--')) {
        options.exportPath = value;
        i += 1;
      }
      continue;
    }

    if (arg.startsWith('--export=')) {
      options.useExport = true;
      options.exportPath = arg.substring('--export='.length);
      continue;
    }
    if (arg.startsWith('--input=')) {
      options.useExport = true;
      options.exportPath = arg.substring('--input='.length);
      continue;
    }
    if (arg.startsWith('--file=')) {
      options.useExport = true;
      options.exportPath = arg.substring('--file='.length);
      continue;
    }

    if (arg === '--since' || arg === '--after') {
      const value = argv[i + 1];
      if (!value) {
        throw new Error(`${arg} expects an ISO-8601 timestamp`);
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
  npx ts-node scripts/backfill-security-user.ts [options]

By default the script connects to the SOURCE_IDENTITY_PG_URL database. Pass --export to read from an exported JSON/NDJSON file instead.

Options:
  --since <ISO>      Only consider records with modify_date ≥ this timestamp
  --apply            Insert missing records (default: dry-run prints handles only)
  --export [path]    Read from an export file (optional path; defaults to ${DEFAULT_EXPORT_PATH})
  -h, --help         Show this message

Examples:
  npx ts-node scripts/backfill-security-user.ts --since 2025-02-01T00:00:00Z
  npx ts-node scripts/backfill-security-user.ts --apply --since 2025-02-01T00:00:00Z
  npx ts-node scripts/backfill-security-user.ts --export ./exports/security_user.ndjson --since 2025-02-01T00:00:00Z`);
}

function parseSince(raw: string): Date {
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`Invalid ISO-8601 timestamp: ${raw}. Example: ${DATE_FORMAT_EXAMPLE}`);
  }
  return parsed;
}

function resolveExportPath(rawPath: string): string {
  const resolved = resolve(process.cwd(), rawPath);
  if (!existsSync(resolved)) {
    throw new Error(`Export file not found: ${resolved}`);
  }
  return resolved;
}

async function loadSecurityUserRecordsFromFile(
  filePath: string,
  since?: Date
): Promise<SecurityUserRecord[]> {
  const extension = extname(filePath).toLowerCase();
  if (extension === '.ndjson' || extension === '.jsonl' || extension === '.log') {
    return readNdjson(filePath, since);
  }

  try {
    return readNdjson(filePath, since);
  } catch (err) {
    return readJson(filePath, since);
  }
}

async function readNdjson(filePath: string, since?: Date): Promise<SecurityUserRecord[]> {
  const stream = createReadStream(filePath, { encoding: 'utf8' });
  const rl = readline.createInterface({
    input: stream,
    crlfDelay: Number.POSITIVE_INFINITY,
  });

  const records: SecurityUserRecord[] = [];
  let lineNumber = 0;
  let warnedMissingModifyDate = false;

  for await (const line of rl) {
    lineNumber += 1;
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    let rawRecord: RawSecurityUserRecord;
    try {
      rawRecord = JSON.parse(trimmed);
    } catch (error) {
      throw new Error(`Failed to parse JSON on line ${lineNumber}: ${(error as Error).message}`);
    }
    const record = normaliseSecurityUserRecord(rawRecord, `line ${lineNumber}`);
    if (shouldIncludeRecord(record, since)) {
      if (!record.modifyDate && since && !warnedMissingModifyDate) {
        console.warn(
          '[warn] Encountered record without modify_date; including because --since was provided.'
        );
        warnedMissingModifyDate = true;
      }
      records.push(record);
    }
  }

  return records;
}

async function readJson(filePath: string, since?: Date): Promise<SecurityUserRecord[]> {
  const raw = readFileSync(filePath, 'utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Failed to parse JSON file ${filePath}: ${(error as Error).message}`);
  }

  const payload = Array.isArray(parsed)
    ? parsed
    : Array.isArray((parsed as any)?.records)
    ? (parsed as any).records
    : (() => {
        throw new Error(
          `JSON file ${filePath} must contain an array or { records: [] } structure.`
        );
      })();

  let warnedMissingModifyDate = false;
  const records: SecurityUserRecord[] = [];
  payload.forEach((rawRecord, index) => {
    const record = normaliseSecurityUserRecord(
      rawRecord as RawSecurityUserRecord,
      `index ${index}`
    );
    if (shouldIncludeRecord(record, since)) {
      if (!record.modifyDate && since && !warnedMissingModifyDate) {
        console.warn(
          '[warn] Encountered record without modify_date; including because --since was provided.'
        );
        warnedMissingModifyDate = true;
      }
      records.push(record);
    }
  });

  return records;
}

async function loadSecurityUserRecordsFromSourceDb(
  prisma: PrismaClient,
  since?: Date
): Promise<SecurityUserRecord[]> {
  console.log('[load] Fetching security_user rows from source database...');
  const where: Prisma.security_userWhereInput = {};
  if (since) {
    where.modify_date = { gte: since };
  }

  const records: SecurityUserRecord[] = [];
  let cursor: Prisma.security_userWhereUniqueInput | undefined;

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

  console.log(`[load] Completed source DB fetch. Retrieved ${records.length} records.`);
  return records;
}

function normaliseSecurityUserRecord(
  raw: RawSecurityUserRecord,
  origin: string
): SecurityUserRecord {
  const loginIdValue = raw.login_id ?? raw.loginId ?? raw.LOGIN_ID;
  if (loginIdValue == null) {
    throw new Error(`Missing login_id in export record (${origin})`);
  }
  const userIdValue = raw.user_id ?? raw.userId ?? raw.USER_ID;
  if (!userIdValue) {
    throw new Error(`Missing user_id in export record (${origin})`);
  }
  const passwordValue = raw.password ?? raw.PASSWORD;
  if (typeof passwordValue !== 'string') {
    throw new Error(`Missing password in export record (${origin})`);
  }

  const createUserIdValue =
    raw.create_user_id ?? raw.createUserId ?? raw.CREATE_USER_ID ?? null;

  const modifyRaw = raw.modify_date ?? raw.modifyDate ?? raw.MODIFY_DATE ?? null;
  let modifyDate: Date | null = null;
  if (modifyRaw != null) {
    const parsed = new Date(modifyRaw as any);
    if (!Number.isNaN(parsed.getTime())) {
      modifyDate = parsed;
    } else {
      console.warn(
        `[warn] Unable to parse modify_date "${modifyRaw}" for login_id ${loginIdValue}; treating as null.`
      );
    }
  }

  return {
    loginId: String(loginIdValue),
    userId: String(userIdValue),
    password: passwordValue,
    createUserId:
      createUserIdValue == null || createUserIdValue === ''
        ? null
        : String(createUserIdValue),
    modifyDate,
  };
}

function shouldIncludeRecord(record: SecurityUserRecord, since?: Date): boolean {
  if (!since) {
    return true;
  }
  if (record.modifyDate) {
    return record.modifyDate.getTime() >= since.getTime();
  }
  return true;
}

async function findMissingRecords(
  prisma: PrismaClient,
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
  prisma: PrismaClient,
  records: SecurityUserRecord[]
): Promise<number> {
  let totalInserted = 0;
  for (let i = 0; i < records.length; i += TARGET_INSERT_BATCH_SIZE) {
    const chunk = records.slice(i, i + TARGET_INSERT_BATCH_SIZE);
    const data = chunk.map((record) => ({
      login_id: record.loginId,
      user_id: record.userId,
      password: record.password,
      create_user_id: record.createUserId,
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

function createSourceIdentityClient(): PrismaClient {
  const url = process.env[SOURCE_IDENTITY_ENV];
  if (!url) {
    throw new Error(
      `Environment variable ${SOURCE_IDENTITY_ENV} must be set when reading from the source database.`
    );
  }
  return new PrismaClient({
    datasources: {
      db: {
        url,
      },
    },
  });
}

function summarizeConnection(raw: string): string {
  try {
    const parsed = new URL(raw);
    const hostPart = `${parsed.protocol}//${parsed.hostname}${
      parsed.port ? `:${parsed.port}` : ''
    }${parsed.pathname}`;
    const authStatus =
      parsed.username || parsed.password ? 'credentials set' : 'no credentials';
    const queryStatus = parsed.search ? 'query params present' : 'no query params';
    return `${hostPart} (${authStatus}; ${queryStatus})`;
  } catch (err: any) {
    return `unable to parse connection string (${err.message ?? 'unknown error'})`;
  }
}

void main();
