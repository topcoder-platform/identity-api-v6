/* eslint-disable no-console */
import 'dotenv/config';

const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// === CommonJS-friendly requires for generated Prisma clients
const { PrismaClient: TargetPrisma } = require('../generated/target');
const { PrismaClient: SourceAuthPrisma } = require('../generated/source-auth');
const { PrismaClient: SourceIdentityPrisma } = require('../generated/source-identity');

// ---- Helpers to keep TS happy (avoid TS7022)
type Rows<T extends (...args: any) => any> = Awaited<ReturnType<T>>;
type Row<T extends (...args: any) => any> = Rows<T>[number];

// ---- Instantiate clients
const target = new TargetPrisma();
const sourceAuth = new SourceAuthPrisma();
const sourceIdentity = new SourceIdentityPrisma();

// ---- Tunables
const BATCH_SIZE = 1000;

function redactCredentials(raw: string) {
  return raw.replace(/\/\/([^@]*?)@/, '//***@');
}

function summarizeConnection(raw: string) {
  try {
    const parsed = new URL(raw);
    const hostPart = `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ''}${parsed.pathname}`;
    const authStatus =
      parsed.username || parsed.password ? 'credentials set' : 'no credentials';
    const queryStatus = parsed.search ? 'query params present' : 'no query params';
    return `${hostPart} (${authStatus}; ${queryStatus})`;
  } catch (err: any) {
    return `unable to parse (${err.message}); raw=${redactCredentials(raw)}`;
  }
}

function logConnectionDetails(label: string, envVar: string, rawValue?: string) {
  if (!rawValue) {
    console.warn(`[config] ${label}: environment variable ${envVar} is not set`);
    return;
  }
  console.log(`[config] ${label} (${envVar}): ${summarizeConnection(rawValue)}`);
}

[
  { label: 'Target identity database', envVar: 'IDENTITY_DB_URL' },
  { label: 'Source auth database', envVar: 'SOURCE_AUTH_MYSQL_URL' },
  { label: 'Source identity database', envVar: 'SOURCE_IDENTITY_PG_URL' },
].forEach(({ label, envVar }) => logConnectionDetails(label, envVar, process.env[envVar]));

type RunMode = 'full' | 'delta';

interface CliOptions {
  mode: RunMode;
  since: Date | null;
  sinceRaw: string | null;
}

const cliOptions = parseCliOptions(process.argv.slice(2));
const CHANGE_WINDOW_START = cliOptions.mode === 'delta' ? cliOptions.since : null;
const deltaTablesLogged = new Set<string>();

if (cliOptions.mode === 'delta') {
  console.log(
    `[config] Run mode: delta (changes since ${CHANGE_WINDOW_START!.toISOString()})`
  );
} else {
  console.log('[config] Run mode: full');
}

const PARALLEL_LIMIT = resolveParallelLimit();
console.log(`[config] Parallel worker limit: ${PARALLEL_LIMIT}`);

function applyChangeWindow<T extends Record<string, any>>(
  args: T,
  fields: string[],
  label: string
): T {
  if (!CHANGE_WINDOW_START) {
    return args;
  }

  if (fields.length === 0) {
    if (!deltaTablesLogged.has(label)) {
      deltaTablesLogged.add(label);
      console.log(`[delta] ${label}: no timestamp fields; exporting full set`);
    }
    return args;
  }

  const deltaWhere = {
    OR: fields.map((field) => ({ [field]: { gte: CHANGE_WINDOW_START } })),
  };

  if (!deltaTablesLogged.has(label)) {
    deltaTablesLogged.add(label);
    console.log(
      `[delta] ${label}: filtering rows where ${fields.join(' OR ')} ≥ ${CHANGE_WINDOW_START.toISOString()}`
    );
  }

  const baseArgs: any = { ...args };
  if (baseArgs.where) {
    baseArgs.where = { AND: [baseArgs.where, deltaWhere] };
  } else {
    baseArgs.where = deltaWhere;
  }
  return baseArgs;
}

function parseCliOptions(argv: string[]): CliOptions {
  let mode: RunMode | null = null;
  let sinceRaw: string | null = process.env.MIGRATE_SINCE ?? null;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') {
      printUsage();
      process.exit(0);
    } else if (arg === '--delta') {
      mode = 'delta';
    } else if (arg === '--full') {
      mode = 'full';
    } else if (arg.startsWith('--mode=')) {
      const [, rawMode] = arg.split('=');
      if (rawMode === 'delta' || rawMode === 'full') {
        mode = rawMode;
      } else {
        throw new Error(`Unsupported --mode value: ${rawMode}`);
      }
    } else if (arg === '--since') {
      const value = argv[i + 1];
      if (!value) {
        throw new Error('--since expects an ISO-8601 timestamp value');
      }
      sinceRaw = value;
      i += 1;
    } else if (arg.startsWith('--since=')) {
      const [, value] = arg.split('=');
      if (!value) {
        throw new Error('--since expects an ISO-8601 timestamp value');
      }
      sinceRaw = value;
    }
  }

  if (!mode) {
    mode = sinceRaw ? 'delta' : 'full';
  }

  const since = sinceRaw ? new Date(sinceRaw) : null;
  if (sinceRaw && (!since || Number.isNaN(since.getTime()))) {
    throw new Error(`Invalid timestamp for --since / MIGRATE_SINCE: ${sinceRaw}`);
  }

  if (mode === 'delta' && !since) {
    throw new Error('Delta mode requires --since <ISO-8601 timestamp> or MIGRATE_SINCE');
  }

  return { mode, since, sinceRaw };
}

function printUsage() {
  console.log(`Usage: npm run migrate -- [options]

Options:
  --full                Run the complete migration (default)
  --delta               Run in delta mode (requires --since or MIGRATE_SINCE)
  --since <ISO>         ISO-8601 timestamp; limits source rows to those updated since this time
  --mode=full|delta     Alternate way to set the run mode
  -h, --help            Show this message

Environment:
  MIGRATE_SINCE         Acts like --since when provided.
`);
}


// ensure ./logs exists
function ensureLogDir() {
  const dir = path.resolve(process.cwd(), 'logs');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function appendNdjson(filename: string, record: any) {
  const dir = ensureLogDir();
  fs.appendFileSync(path.join(dir, filename), JSON.stringify(record) + '\n', 'utf8');
}

function resolveParallelLimit(defaultValue = 3): number {
  const raw = process.env.MIGRATE_PARALLEL;
  if (!raw) {
    return defaultValue;
  }

  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 1) {
    console.warn(
      `[config] MIGRATE_PARALLEL=${raw} is invalid; using default parallelism of ${defaultValue}`
    );
    return defaultValue;
  }

  return parsed;
}

async function runParallel(
  label: string,
  tasks: Array<() => Promise<void>>,
  limit = PARALLEL_LIMIT
): Promise<void> {
  if (tasks.length === 0) {
    return;
  }

  if (tasks.length === 1) {
    await tasks[0]();
    return;
  }

  const concurrency = Math.max(1, Math.min(limit, tasks.length));
  console.log(`[parallel] ${label}: running ${tasks.length} tasks (limit=${concurrency})`);

  const queue = tasks.slice();
  let aborted = false;

  async function worker(): Promise<void> {
    while (!aborted) {
      const next = queue.shift();
      if (!next) {
        return;
      }
      try {
        await next();
      } catch (err) {
        aborted = true;
        throw err;
      }
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);
}

// ===== AUTH (MySQL) → TARGET =====

async function migrateRoles() {
  console.log('→ MySQL roles → target.role');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceAuth.role.findMany> =
      await sourceAuth.role.findMany(
        applyChangeWindow(
          { skip, take: BATCH_SIZE, orderBy: { id: 'asc' } },
          ['createdAt', 'modifiedAt'],
          'sourceAuth.role'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.role.upsert({
          where: { name: r.name },
          create: {
            id: r.id,
            name: r.name,
            createdBy: r.createdBy ?? null,
            createdAt: r.createdAt ?? null,
            modifiedBy: r.modifiedBy ?? null,
            modifiedAt: r.modifiedAt ?? null,
          },
          update: {
            modifiedBy: r.modifiedBy ?? null,
            modifiedAt: r.modifiedAt ?? null,
          },
        })
      ),
      { timeout: 60_000 }
    );
    total += batch.length;
    skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ roles: ${total}`);
}

async function migrateClients() {
  console.log('→ MySQL clients → target.client');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceAuth.client.findMany> =
      await sourceAuth.client.findMany(
        applyChangeWindow(
          { skip, take: BATCH_SIZE, orderBy: { id: 'asc' } },
          ['createdAt', 'modifiedAt'],
          'sourceAuth.client'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((c: any) =>
        target.client.upsert({
          where: { clientId: c.clientId },
          create: {
            clientId: c.clientId,
            name: c.name,
            redirectUri: c.redirectUri ?? null,
            secret: c.secret ?? null,
            createdBy: c.createdBy ?? null,
            createdAt: c.createdAt ?? null,
            modifiedBy: c.modifiedBy ?? null,
            modifiedAt: c.modifiedAt ?? null,
          },
          update: {
            name: c.name,
            redirectUri: c.redirectUri ?? null,
            secret: c.secret ?? null,
            modifiedBy: c.modifiedBy ?? null,
            modifiedAt: c.modifiedAt ?? null,
          },
        })
      ),
      { timeout: 60_000 }
    );
    total += batch.length;
    skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ clients: ${total}`);
}

async function migrateRoleAssignments() {
  console.log('→ MySQL role_assignment → target.roleAssignment');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceAuth.roleAssignment.findMany> =
      await sourceAuth.roleAssignment.findMany(
        applyChangeWindow(
          { skip, take: BATCH_SIZE, orderBy: { id: 'asc' } },
          ['createdAt', 'modifiedAt'],
          'sourceAuth.roleAssignment'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((ra: any) =>
        target.roleAssignment.upsert({
          where: {
              roleId_subjectId_subjectType: {
              roleId: ra.roleId,
              subjectId: ra.subjectId,
              subjectType: 1,
            },
          },
          create: {
            id: ra.id,
            roleId: ra.roleId,
            subjectId: ra.subjectId,
            subjectType: ra.subjectType ?? 1,
            createdBy: ra.createdBy ?? null,
            createdAt: ra.createdAt ?? null,
            modifiedBy: ra.modifiedBy ?? null,
            modifiedAt: ra.modifiedAt ?? null,
          },
          update: {
            modifiedBy: ra.modifiedBy ?? null,
            modifiedAt: ra.modifiedAt ?? null,
          },
        })
      ),
      { timeout: 60_000 }
    );
    total += batch.length;
    skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ role assignments: ${total}`);
}

// ===== IDENTITY (PG) → TARGET (PG) =====
// Dependency order: lookups/providers → security/status lookups → country/invalid → users → security_user/groups → email/status/type → emails → xrefs → social/sso → otp → user_status

async function migrateAchievementTypeLu() {
  console.log('→ achievement_type_lu');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.achievement_type_lu.findMany> =
      await sourceIdentity.achievement_type_lu.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { achievement_type_id: 'asc' },
          },
          [],
          'sourceIdentity.achievement_type_lu'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.achievement_type_lu.upsert({
          where: { achievement_type_id: r.achievement_type_id },
          create: {
            achievement_type_id: r.achievement_type_id,
            achievement_type_desc: r.achievement_type_desc,
          },
          update: {
            achievement_type_desc: r.achievement_type_desc,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ achievement_type_lu: ${total}`);
}

async function migrateCountry() {
  console.log('→ country');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.country.findMany> =
      await sourceIdentity.country.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { country_code: 'asc' },
          },
          ['modify_date'],
          'sourceIdentity.country'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.country.upsert({
          where: { country_code: r.country_code },
          create: {
            country_code: r.country_code,
            country_name: r.country_name,
            modify_date: r.modify_date ?? null,
            participating: r.participating ?? null,
            default_taxform_id: r.default_taxform_id ?? null,
            longitude: r.longitude ?? null,
            latitude: r.latitude ?? null,
            region: r.region ?? null,
            iso_name: r.iso_name ?? null,
            iso_alpha2_code: r.iso_alpha2_code ?? null,
            iso_alpha3_code: r.iso_alpha3_code ?? null,
          },
          update: {
            country_name: r.country_name,
            modify_date: r.modify_date ?? null,
            participating: r.participating ?? null,
            default_taxform_id: r.default_taxform_id ?? null,
            longitude: r.longitude ?? null,
            latitude: r.latitude ?? null,
            region: r.region ?? null,
            iso_name: r.iso_name ?? null,
            iso_alpha2_code: r.iso_alpha2_code ?? null,
            iso_alpha3_code: r.iso_alpha3_code ?? null,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ country: ${total}`);
}

async function migrateEmailStatusLu() {
  console.log('→ email_status_lu');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.email_status_lu.findMany> =
      await sourceIdentity.email_status_lu.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { status_id: 'asc' },
          },
          ['create_date', 'modify_date'],
          'sourceIdentity.email_status_lu'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.email_status_lu.upsert({
          where: { status_id: r.status_id },
          create: {
            status_id: r.status_id,
            status_desc: r.status_desc ?? null,
            create_date: r.create_date ?? null,
            modify_date: r.modify_date ?? null,
          },
          update: {
            status_desc: r.status_desc ?? null,
            modify_date: r.modify_date ?? null,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ email_status_lu: ${total}`);
}

async function migrateEmailTypeLu() {
  console.log('→ email_type_lu');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.email_type_lu.findMany> =
      await sourceIdentity.email_type_lu.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { email_type_id: 'asc' },
          },
          ['create_date', 'modify_date'],
          'sourceIdentity.email_type_lu'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.email_type_lu.upsert({
          where: { email_type_id: r.email_type_id },
          create: {
            email_type_id: r.email_type_id,
            email_type_desc: r.email_type_desc ?? null,
            create_date: r.create_date ?? null,
            modify_date: r.modify_date ?? null,
          },
          update: {
            email_type_desc: r.email_type_desc ?? null,
            modify_date: r.modify_date ?? null,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ email_type_lu: ${total}`);
}

async function migrateInvalidHandles() {
  console.log('→ invalid_handles');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.invalid_handles.findMany> =
      await sourceIdentity.invalid_handles.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { invalid_handle_id: 'asc' },
          },
          [],
          'sourceIdentity.invalid_handles'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.invalid_handles.upsert({
          where: { invalid_handle_id: r.invalid_handle_id },
          create: {
            invalid_handle_id: r.invalid_handle_id,
            invalid_handle: r.invalid_handle,
          },
          update: {
            invalid_handle: r.invalid_handle,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ invalid_handles: ${total}`);
}

async function migrateSecurityStatusLu() {
  console.log('→ security_status_lu');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.security_status_lu.findMany> =
      await sourceIdentity.security_status_lu.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { security_status_id: 'asc' },
          },
          [],
          'sourceIdentity.security_status_lu'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.security_status_lu.upsert({
          where: { security_status_id: r.security_status_id },
          create: {
            security_status_id: r.security_status_id,
            status_desc: r.status_desc ?? null,
          },
          update: {
            status_desc: r.status_desc ?? null,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ security_status_lu: ${total}`);
}

async function migrateSecurityGroups() {
  console.log('→ security_groups');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.security_groups.findMany> =
      await sourceIdentity.security_groups.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { group_id: 'asc' },
          },
          [],
          'sourceIdentity.security_groups'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.security_groups.upsert({
          where: { group_id: r.group_id },
          create: {
            group_id: r.group_id,
            description: r.description,
            challenge_group_ind: r.challenge_group_ind ?? 0,
            create_user_id: r.create_user_id ?? null,
          },
          update: {
            description: r.description,
            challenge_group_ind: r.challenge_group_ind ?? 0,
            create_user_id: r.create_user_id ?? null,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ security_groups: ${total}`);
}

async function migrateSecurityUser() {
  console.log('→ security_user');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.security_user.findMany> =
      await sourceIdentity.security_user.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { login_id: 'asc' },
          },
          ['modify_date'],
          'sourceIdentity.security_user'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.security_user.upsert({
          where: { login_id: r.login_id },
          create: {
            login_id: r.login_id,
            user_id: r.user_id,          // string in your schema
            password: r.password,
            create_user_id: r.create_user_id ?? null,
            modify_date: r.modify_date ?? null,
          },
          update: {
            user_id: r.user_id,
            password: r.password,
            create_user_id: r.create_user_id ?? null,
            modify_date: r.modify_date ?? null,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ security_user: ${total}`);
}

// Providers (needed for FK on social/sso logins)
async function migrateSocialLoginProvider() {
  if (!sourceIdentity.social_login_provider) return;
  console.log('→ social_login_provider');
  let skip = 0, total = 0;
  while (true) {
    const batch: any[] =
      await sourceIdentity.social_login_provider.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { social_login_provider_id: 'asc' },
          },
          [],
          'sourceIdentity.social_login_provider'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.social_login_provider.upsert({
          where: { social_login_provider_id: r.social_login_provider_id },
          create: {
            social_login_provider_id: r.social_login_provider_id,
            name: r.name ?? null,
          },
          update: {
            name: r.name ?? null,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ social_login_provider: ${total}`);
}

async function migrateSsoLoginProvider() {
  if (!sourceIdentity.sso_login_provider) return;
  console.log('→ sso_login_provider');
  let skip = 0, total = 0;
  while (true) {
    const batch: any[] =
      await sourceIdentity.sso_login_provider.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { sso_login_provider_id: 'asc' },
          },
          [],
          'sourceIdentity.sso_login_provider'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.sso_login_provider.upsert({
          where: { sso_login_provider_id: r.sso_login_provider_id },
          create: {
            sso_login_provider_id: r.sso_login_provider_id,
            name: r.name ?? null,
            type: r.type,
            identify_email_enabled: r.identify_email_enabled ?? true,
            identify_handle_enabled: r.identify_handle_enabled ?? true,
          },
          update: {
            name: r.name ?? null,
            type: r.type,
            identify_email_enabled: r.identify_email_enabled ?? true,
            identify_handle_enabled: r.identify_handle_enabled ?? true,
          },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ sso_login_provider: ${total}`);
}

async function migrateUsers() {
  console.log('→ user (full field set)');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.user.findMany> =
      await sourceIdentity.user.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { user_id: 'asc' },
            select: {
              user_id: true,
              first_name: true,
              last_name: true,
              create_date: true,
              modify_date: true,
              handle: true,
              last_login: true,
              status: true,
              activation_code: true,
              middle_name: true,
              handle_lower: true,
              timezone_id: true,
              last_site_hit_date: true,
              name_in_another_language: true,
              password: true,
              open_id: true,
              reg_source: true,
              utm_source: true,
              utm_medium: true,
              utm_campaign: true,
            },
          },
          ['modify_date', 'create_date', 'last_login', 'last_site_hit_date'],
          'sourceIdentity.user'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((u: any) =>
        target.user.upsert({
          where: { user_id: u.user_id },
          create: {
            user_id: u.user_id,
            first_name: u.first_name ?? null,
            last_name: u.last_name ?? null,
            create_date: u.create_date ?? null,
            modify_date: u.modify_date ?? null,
            handle: u.handle,
            last_login: u.last_login ?? null,
            status: u.status,
            activation_code: u.activation_code ?? null,
            middle_name: u.middle_name ?? null,
            handle_lower: u.handle_lower ?? null,
            timezone_id: u.timezone_id ?? null,
            last_site_hit_date: u.last_site_hit_date ?? null,
            name_in_another_language: u.name_in_another_language ?? null,
            password: u.password ?? null,
            open_id: u.open_id ?? null,
            reg_source: u.reg_source ?? null,
            utm_source: u.utm_source ?? null,
            utm_medium: u.utm_medium ?? null,
            utm_campaign: u.utm_campaign ?? null,
          },
          update: {
            first_name: u.first_name ?? null,
            last_name: u.last_name ?? null,
            modify_date: u.modify_date ?? null,
            handle: u.handle,
            last_login: u.last_login ?? null,
            status: u.status,
            activation_code: u.activation_code ?? null,
            middle_name: u.middle_name ?? null,
            handle_lower: u.handle_lower ?? null,
            timezone_id: u.timezone_id ?? null,
            last_site_hit_date: u.last_site_hit_date ?? null,
            name_in_another_language: u.name_in_another_language ?? null,
            password: u.password ?? null,
            open_id: u.open_id ?? null,
            reg_source: u.reg_source ?? null,
            utm_source: u.utm_source ?? null,
            utm_medium: u.utm_medium ?? null,
            utm_campaign: u.utm_campaign ?? null,
          },
        })
      ),
      { timeout: 180_000 }
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ users: ${total}`);
}

async function migrateEmail() {
  console.log('→ email (skip rows whose user_id is missing in target.user, log them)');
  let skip = 0, total = 0, skipped = 0;

  while (true) {
    const batch: Rows<typeof sourceIdentity.email.findMany> =
      await sourceIdentity.email.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { email_id: 'asc' },
          },
          ['modify_date', 'create_date'],
          'sourceIdentity.email'
        )
      );
    if (batch.length === 0) break;

    // Build a unique list of non-null user_ids from this batch
    const userIdsRaw = batch
      .map((e: any) => e.user_id)
      .filter((v: any) => v !== null && v !== undefined);

    // Short-circuit if none
    let existingUserIdSet = new Set<string>();
    if (userIdsRaw.length > 0) {
      // Prisma Decimal values stringify safely; comparing as strings is robust across sources
      const userIdsUnique = Array.from(
        new Set(userIdsRaw.map((v: any) => (typeof v?.toString === 'function' ? v.toString() : String(v))))
      );

      const existingUsers = await target.user.findMany({
        where: { user_id: { in: userIdsUnique as any[] } },
        select: { user_id: true },
      });

      existingUserIdSet = new Set(
        existingUsers.map((u: any) => (typeof u.user_id?.toString === 'function' ? u.user_id.toString() : String(u.user_id)))
      );
    }

    // Partition valid vs. invalid email rows
    const valid: any[] = [];
    for (const e of batch as any[]) {
      if (e.user_id == null) {
        // null user is allowed by your schema — keep it
        valid.push(e);
      } else {
        const key = typeof e.user_id?.toString === 'function' ? e.user_id.toString() : String(e.user_id);
        if (existingUserIdSet.has(key)) {
          valid.push(e);
        } else {
          skipped++;
          appendNdjson('missing-email-users.ndjson', {
            reason: 'email.user_id not found in target.user',
            email_id: e.email_id,
            address: e.address ?? null,
            user_id: e.user_id,
            email_type_id: e.email_type_id ?? null,
            status_id: e.status_id ?? null,
          });
        }
      }
    }

    // Upsert only the valid rows
    if (valid.length > 0) {
      await target.$transaction(
        valid.map((e: any) =>
          target.email.upsert({
            where: { email_id: e.email_id },
            create: {
              email_id: e.email_id,
              user_id: e.user_id ?? null,
              email_type_id: e.email_type_id ?? null,
              address: e.address ?? null,
              create_date: e.create_date ?? null,
              modify_date: e.modify_date ?? null,
              primary_ind: e.primary_ind ?? null,
              status_id: e.status_id ?? null,
            },
            update: {
              user_id: e.user_id ?? null,
              email_type_id: e.email_type_id ?? null,
              address: e.address ?? null,
              modify_date: e.modify_date ?? null,
              primary_ind: e.primary_ind ?? null,
              status_id: e.status_id ?? null,
            },
          })
        ),
        { timeout: 120_000 }
      );
    }

    total += valid.length;
    skip += batch.length;
    console.log(`  … imported=${total} (skipped=${skipped} this run)`);
  }

  console.log(`✓ email: imported=${total}, skipped=${skipped}. See logs/missing-email-users.ndjson`);
}

async function migrateUserEmailXref() {
  console.log('→ user_email_xref (skip rows whose user/email missing, log them)');
  let skip = 0, total = 0, skipped = 0;

  while (true) {
    const batch: Rows<typeof sourceIdentity.user_email_xref.findMany> =
      await sourceIdentity.user_email_xref.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: [{ user_id: 'asc' }, { email_id: 'asc' }],
          },
          ['modify_date', 'create_date'],
          'sourceIdentity.user_email_xref'
        )
      );
    if (batch.length === 0) break;

    // Collect parents to validate existence
    const userIds = Array.from(new Set((batch as any[])
      .map(x => x.user_id)
      .filter((v: any) => v !== null && v !== undefined)
      .map((v: any) => (typeof v?.toString === 'function' ? v.toString() : String(v)))
    ));

    const emailIds = Array.from(new Set((batch as any[])
      .map(x => x.email_id)
      .filter((v: any) => v !== null && v !== undefined)
      .map((v: any) => (typeof v?.toString === 'function' ? v.toString() : String(v)))
    ));

    const [usersFound, emailsFound] = await Promise.all([
      userIds.length
        ? target.user.findMany({ where: { user_id: { in: userIds as any[] } }, select: { user_id: true } })
        : Promise.resolve([]),
      emailIds.length
        ? target.email.findMany({ where: { email_id: { in: emailIds as any[] } }, select: { email_id: true } })
        : Promise.resolve([]),
    ]);

    const userSet = new Set(usersFound.map((u: any) => (typeof u.user_id?.toString === 'function' ? u.user_id.toString() : String(u.user_id))));
    const emailSet = new Set(emailsFound.map((e: any) => (typeof e.email_id?.toString === 'function' ? e.email_id.toString() : String(e.email_id))));

    const valid: any[] = [];
    for (const x of batch as any[]) {
      const uKey = typeof x.user_id?.toString === 'function' ? x.user_id.toString() : String(x.user_id);
      const eKey = typeof x.email_id?.toString === 'function' ? x.email_id.toString() : String(x.email_id);
      const hasUser = userSet.has(uKey);
      const hasEmail = emailSet.has(eKey);

      if (hasUser && hasEmail) {
        valid.push(x);
      } else {
        skipped++;
        appendNdjson('bad-user-email-xref.ndjson', {
          reason: !hasUser && !hasEmail ? 'both user and email missing' : !hasUser ? 'user missing' : 'email missing',
          user_id: x.user_id,
          email_id: x.email_id,
          is_primary: x.is_primary,
          status_id: x.status_id,
        });
      }
    }

    if (valid.length > 0) {
      await target.$transaction(
        valid.map((x: any) =>
          target.user_email_xref.upsert({
            where: { user_id_email_id: { user_id: x.user_id, email_id: x.email_id } },
            create: {
              user_id: x.user_id,
              email_id: x.email_id,
              is_primary: Boolean(x.is_primary),
              status_id: x.status_id,
              create_date: x.create_date ?? null,
              modify_date: x.modify_date ?? null,
            },
            update: {
              is_primary: Boolean(x.is_primary),
              status_id: x.status_id,
              modify_date: x.modify_date ?? null,
            },
          })
        ),
        { timeout: 120_000 }
      );
    }

    total += valid.length;
    skip += batch.length;
    console.log(`  … imported=${total} (skipped=${skipped} this run)`);
  }

  console.log(`✓ user_email_xref: imported=${total}, skipped=${skipped}. See logs/bad-user-email-xref.ndjson`);
}

async function migrateUserSocialLogin() {
  console.log('→ user_social_login');
  let skip = 0,
    total = 0,
    failures = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.user_social_login.findMany> =
      await sourceIdentity.user_social_login.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: [{ user_id: 'asc' }, { social_login_provider_id: 'asc' }],
          },
          ['modify_date', 'create_date'],
          'sourceIdentity.user_social_login'
        )
      );
    if (batch.length === 0) break;

    const results = await Promise.allSettled(
      batch.map((r: any) =>
        target.user_social_login.upsert({
          where: {
            user_id_social_login_provider_id: {
              user_id: r.user_id,
              social_login_provider_id: r.social_login_provider_id,
            },
          },
          create: {
            user_id: r.user_id,
            social_login_provider_id: r.social_login_provider_id,
            social_user_id: r.social_user_id ?? null,
            social_user_name: r.social_user_name,
            social_email: r.social_email ?? null,
            social_email_verified: r.social_email_verified ?? null,
            create_date: r.create_date ?? null,
            modify_date: r.modify_date ?? null,
          },
          update: {
            social_user_id: r.social_user_id ?? null,
            social_user_name: r.social_user_name,
            social_email: r.social_email ?? null,
            social_email_verified: r.social_email_verified ?? null,
            modify_date: r.modify_date ?? null,
          },
        })
      )
    );

    results.forEach((result, idx) => {
      if (result.status === 'fulfilled') {
        total += 1;
      } else {
        const err: any = result.reason;
        const record = batch[idx];
        if (err?.code === 'P2003' && err?.meta?.constraint === 'user_social_user_fk') {
          failures += 1;
          appendNdjson('bad-user-social-login.ndjson', {
            reason: 'foreign key violation: user missing',
            user_id: record.user_id,
            social_login_provider_id: record.social_login_provider_id,
            social_user_id: record.social_user_id ?? null,
            error: err.message,
          });
        } else {
          throw err;
        }
      }
    });

    skip += batch.length;
    console.log(`  … imported=${total} (failed=${failures} so far)`);
  }
  const summarySuffix =
    failures > 0
      ? `, failed=${failures}. See logs/bad-user-social-login.ndjson`
      : '';
  console.log(`✓ user_social_login: imported=${total}${summarySuffix}`);
}

async function migrateUserSsoLogin() {
  console.log('→ user_sso_login');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.user_sso_login.findMany> =
      await sourceIdentity.user_sso_login.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: [{ user_id: 'asc' }, { provider_id: 'asc' }],
          },
          [],
          'sourceIdentity.user_sso_login'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.user_sso_login.upsert({
          where: {
            user_id_provider_id: {
              user_id: r.user_id,
              provider_id: r.provider_id,
            },
          },
          create: {
            user_id: r.user_id,
            provider_id: r.provider_id,
            sso_user_id: r.sso_user_id,
            sso_user_name: r.sso_user_name ?? null,
            email: r.email ?? null,
          },
          update: {
            sso_user_id: r.sso_user_id,
            sso_user_name: r.sso_user_name ?? null,
            email: r.email ?? null,
          },
        })
      ),
      { timeout: 120_000 }
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ user_sso_login: ${total}`);
}

async function migrateUserOtpEmail() {
  console.log('→ user_otp_email');
  let skip = 0,
    total = 0,
    failures = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.user_otp_email.findMany> =
      await sourceIdentity.user_otp_email.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { id: 'asc' },
          },
          [],
          'sourceIdentity.user_otp_email'
        )
      );
    if (batch.length === 0) break;

    const results = await Promise.allSettled(
      batch.map((r: any) =>
        target.user_otp_email.upsert({
          where: { id: r.id },
          create: {
            id: r.id,
            user_id: r.user_id,
            mode: r.mode,
            otp: r.otp,
            expire_at: r.expire_at,
            resend: r.resend ?? false,
            fail_count: r.fail_count ?? 0,
          },
          update: {
            user_id: r.user_id,
            mode: r.mode,
            otp: r.otp,
            expire_at: r.expire_at,
            resend: r.resend ?? false,
            fail_count: r.fail_count ?? 0,
          },
        })
      )
    );

    results.forEach((result, idx) => {
      if (result.status === 'fulfilled') {
        total += 1;
        return;
      }

      const err: any = result.reason;
      const record = batch[idx];
      failures += 1;

      if (err?.code === 'P2003' && err?.meta?.constraint === 'user_otp_email_user_id_fkey') {
        appendNdjson('bad-user-otp-email.ndjson', {
          reason: 'foreign key violation: user missing',
          id: record.id,
          user_id: record.user_id,
          mode: record.mode,
          otp: record.otp,
          expire_at: record.expire_at,
          resend: record.resend ?? null,
          fail_count: record.fail_count ?? null,
          error: err.message,
        });
      } else {
        appendNdjson('bad-user-otp-email.ndjson', {
          reason: 'unexpected error',
          id: record.id,
          user_id: record.user_id,
          mode: record.mode,
          otp: record.otp,
          expire_at: record.expire_at,
          resend: record.resend ?? null,
          fail_count: record.fail_count ?? null,
          error: err?.message ?? String(err),
        });
      }
    });

    skip += batch.length;
    console.log(`  … imported=${total} (failed=${failures} so far)`);
  }
  const summarySuffix =
    failures > 0 ? `, failed=${failures}. See logs/bad-user-otp-email.ndjson` : '';
  console.log(`✓ user_otp_email: imported=${total}${summarySuffix}`);
}

async function migrateUserStatusLu() {
  console.log('→ user_status_lu');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.user_status_lu.findMany> =
      await sourceIdentity.user_status_lu.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { user_status_id: 'asc' },
          },
          [],
          'sourceIdentity.user_status_lu'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.user_status_lu.upsert({
          where: { user_status_id: r.user_status_id },
          create: { user_status_id: r.user_status_id, description: r.description ?? null },
          update: { description: r.description ?? null },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ user_status_lu: ${total}`);
}

async function migrateUserStatusTypeLu() {
  console.log('→ user_status_type_lu');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.user_status_type_lu.findMany> =
      await sourceIdentity.user_status_type_lu.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: { user_status_type_id: 'asc' },
          },
          [],
          'sourceIdentity.user_status_type_lu'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.user_status_type_lu.upsert({
          where: { user_status_type_id: r.user_status_type_id },
          create: { user_status_type_id: r.user_status_type_id, description: r.description ?? null },
          update: { description: r.description ?? null },
        })
      )
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ user_status_type_lu: ${total}`);
}

async function migrateUserStatus() {
  console.log('→ user_status');
  let skip = 0, total = 0;
  while (true) {
    const batch: Rows<typeof sourceIdentity.user_status.findMany> =
      await sourceIdentity.user_status.findMany(
        applyChangeWindow(
          {
            skip,
            take: BATCH_SIZE,
            orderBy: [{ user_id: 'asc' }, { user_status_type_id: 'asc' }],
          },
          [],
          'sourceIdentity.user_status'
        )
      );
    if (batch.length === 0) break;

    await target.$transaction(
      batch.map((r: any) =>
        target.user_status.upsert({
          where: {
            user_id_user_status_type_id: {
              user_id: r.user_id,
              user_status_type_id: r.user_status_type_id,
            },
          },
          create: {
            user_id: r.user_id,
            user_status_type_id: r.user_status_type_id,
            user_status_id: r.user_status_id ?? null,
          },
          update: {
            user_status_id: r.user_status_id ?? null,
          },
        })
      ),
      { timeout: 120_000 }
    );

    total += batch.length; skip += batch.length;
    console.log(`  … ${total}`);
  }
  console.log(`✓ user_status: ${total}`);
}

// ===== Main =====

async function main() {
  const descriptor =
    cliOptions.mode === 'delta'
      ? `mode=delta, since=${CHANGE_WINDOW_START!.toISOString()}`
      : 'mode=full';
  console.log(`Starting migration… (${descriptor})`);

  // // 1) Auth (MySQL) → target
  await runParallel('auth (roles + clients)', [migrateRoles, migrateClients]);
  await migrateRoleAssignments();

  // // 2) Identity lookups/providers first (FK-safe order)
  await runParallel('identity lookups/providers', [
    migrateAchievementTypeLu,
    migrateEmailStatusLu,
    migrateEmailTypeLu,
    migrateUserStatusLu,
    migrateUserStatusTypeLu,
    migrateSecurityStatusLu,
    migrateCountry,
    migrateInvalidHandles,
    migrateSocialLoginProvider,
    migrateSsoLoginProvider,
  ]);

  // // 3) Core entities (users first for FK dependencies)
  await migrateUsers();
  await runParallel('security tables', [migrateSecurityUser, migrateSecurityGroups]);

  // 4) Email + xref (require users/emails present)
  await migrateEmail();
  //await migrateUserEmailXref();

  // 5) Social / SSO / OTP / status rows
  await runParallel('user-related tables', [
    migrateUserSocialLogin,
    migrateUserSsoLogin,
    migrateUserOtpEmail,
    migrateUserStatus,
  ]);

  console.log('✓ Migration complete.');
}

main()
  .catch((e) => {
    console.error('Migration failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await Promise.allSettled([
      target.$disconnect(),
      sourceAuth.$disconnect(),
      sourceIdentity.$disconnect(),
    ]);
  });
