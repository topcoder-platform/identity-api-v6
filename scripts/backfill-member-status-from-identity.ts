/* eslint-disable no-console */
import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import {
  MemberStatus as MemberDbStatus,
  PrismaClient as MemberPrismaClient,
} from '../prisma/member/generated/member';

type CliOptions = {
  apply: boolean;
  batchSize: number;
  limit?: number;
};

type IdentityStatus = string;

const DEFAULT_BATCH_SIZE = 500;
const TARGET_IDENTITY_STATUSES: IdentityStatus[] = ['I', '4', '5', '6'];
const APPLY_LOG_FIRST_N = 20;
const APPLY_LOG_EVERY_N = 500;

type UpdateBucket = {
  status: MemberDbStatus;
  userIds: bigint[];
};
function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    apply: false,
    batchSize: DEFAULT_BATCH_SIZE,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--apply') {
      options.apply = true;
      continue;
    }

    if (arg === '--batch-size') {
      const raw = argv[i + 1];
      if (!raw) {
        throw new Error('--batch-size expects a numeric value');
      }
      options.batchSize = parsePositiveInt(raw, '--batch-size');
      i += 1;
      continue;
    }

    if (arg.startsWith('--batch-size=')) {
      options.batchSize = parsePositiveInt(
        arg.substring('--batch-size='.length),
        '--batch-size',
      );
      continue;
    }

    if (arg === '--limit') {
      const raw = argv[i + 1];
      if (!raw) {
        throw new Error('--limit expects a numeric value');
      }
      options.limit = parsePositiveInt(raw, '--limit');
      i += 1;
      continue;
    }

    if (arg.startsWith('--limit=')) {
      options.limit = parsePositiveInt(arg.substring('--limit='.length), '--limit');
      continue;
    }

    if (arg === '--help' || arg === '-h') {
      printUsage();
      process.exit(0);
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return options;
}

function parsePositiveInt(value: string, flag: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return parsed;
}

function printUsage(): void {
  console.log(`Backfill members.member.status from identity.user.status

Usage:
  npx ts-node scripts/backfill-member-status-from-identity.ts [--apply] [--batch-size N] [--limit N]

Behavior:
  - Select users where identity.user.status is one of: I, 4, 5, 6
  - Keep only rows where members.member.status is currently ACTIVE
  - Map identity status to members status and update mismatches

Modes:
  - default: dry-run (prints summary, no writes)
  - --apply: perform updates
`);
}

function mapIdentityToMemberStatus(
  identityStatus: IdentityStatus,
): MemberDbStatus | null {
  switch (identityStatus) {
    case 'U':
      return MemberDbStatus.UNVERIFIED;
    case '4':
      return MemberDbStatus.INACTIVE_USER_REQUEST;
    case '5':
      return MemberDbStatus.INACTIVE_DUPLICATE_ACCOUNT;
    case '6':
      return MemberDbStatus.INACTIVE_IRREGULAR_ACCOUNT;
    case 'I':
      // identity has a generic inactive; member DB does not, pick the broad inactive bucket
      return MemberDbStatus.INACTIVE_USER_REQUEST;
    default:
      return null;
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const identityPrisma = new PrismaClient();
  const memberPrisma = new MemberPrismaClient();

  let scanned = 0;
  let candidates = 0;
  let updates = 0;
  let skippedUnknownIdentityStatus = 0;
  let skippedAlreadySynced = 0;
  let totalMemberRecords = 0;
  let totalActiveMemberRecords = 0;
  let totalIdentityRecords = 0;

  try {
    await identityPrisma.$connect();
    await memberPrisma.$connect();

    console.log(
      `[config] mode=${options.apply ? 'apply' : 'dry-run'}, batchSize=${options.batchSize}, limit=${options.limit ?? 'none'}`,
    );

    [totalMemberRecords, totalActiveMemberRecords, totalIdentityRecords] =
      await Promise.all([
        memberPrisma.member.count(),
        memberPrisma.member.count({
          where: { status: MemberDbStatus.ACTIVE },
        }),
        identityPrisma.user.count(),
      ]);

    let cursorUserId: number | undefined;

    while (true) {
      const users = await identityPrisma.user.findMany({
        where: { status: { in: TARGET_IDENTITY_STATUSES } },
        select: { user_id: true, status: true },
        orderBy: { user_id: 'asc' },
        take: options.batchSize,
        ...(cursorUserId
          ? {
              cursor: { user_id: cursorUserId },
              skip: 1,
            }
          : {}),
      });

      if (users.length === 0) {
        break;
      }

      cursorUserId = Number(users[users.length - 1].user_id);
      scanned += users.length;

      const userIds = users.map((u) => BigInt(String(u.user_id)));
      const memberRows = await memberPrisma.member.findMany({
        where: {
          userId: { in: userIds },
          status: MemberDbStatus.ACTIVE,
        },
        select: { userId: true, status: true },
      });
      const memberStatusById = new Map(
        memberRows.map((m) => [m.userId.toString(), m.status]),
      );

      const updateBucketsByStatus = new Map<MemberDbStatus, bigint[]>();
      let batchCandidates = 0;

      for (const user of users) {
        if (options.limit && candidates >= options.limit) {
          break;
        }

        const idStr = String(user.user_id);
        const currentMemberStatus = memberStatusById.get(idStr);
        if (!currentMemberStatus) {
          continue;
        }

        const mappedStatus = mapIdentityToMemberStatus(user.status);
        if (!mappedStatus) {
          skippedUnknownIdentityStatus += 1;
          continue;
        }

        candidates += 1;
        batchCandidates += 1;

        if (!options.apply) {
          if (candidates <= 20) {
            console.log(`[dry-run] userId=${idStr}, identity=${user.status} -> member=${mappedStatus}`);
          }
          continue;
        }

        if (candidates <= APPLY_LOG_FIRST_N) {
          console.log(
            `[apply-candidate] userId=${idStr}, identity=${user.status} -> member=${mappedStatus}`,
          );
        }

        const bucket = updateBucketsByStatus.get(mappedStatus) ?? [];
        bucket.push(BigInt(idStr));
        updateBucketsByStatus.set(mappedStatus, bucket);
      }

      if (options.apply) {
        const updateBuckets: UpdateBucket[] = Array.from(
          updateBucketsByStatus.entries(),
        ).map(([status, userIds]) => ({ status, userIds }));

        let batchUpdated = 0;
        for (const bucket of updateBuckets) {
          if (bucket.userIds.length === 0) {
            continue;
          }

          const result = await memberPrisma.member.updateMany({
            where: {
              userId: { in: bucket.userIds },
              status: MemberDbStatus.ACTIVE,
            },
            data: {
              status: bucket.status,
            },
          });

          batchUpdated += result.count;
          updates += result.count;
          if (updates % APPLY_LOG_EVERY_N === 0 || result.count > 0) {
            console.log(
              `[apply] batch status=${bucket.status}, attempted=${bucket.userIds.length}, updated=${result.count}, totalUpdated=${updates}`,
            );
          }
        }

        const batchSkipped = batchCandidates - batchUpdated;
        if (batchSkipped > 0) {
          skippedAlreadySynced += batchSkipped;
          console.log(
            `[apply-skip] batch skipped=${batchSkipped}, likely race/already synced`,
          );
        }
      }

      if (options.limit && candidates >= options.limit) {
        break;
      }
    }

    console.log('--- summary ---');
    console.log(`identity total records: ${totalIdentityRecords}`);
    console.log(`identity scanned (status in I,4,5,6): ${scanned}`);
    console.log(`member total records: ${totalMemberRecords}`);
    console.log(`member total active records: ${totalActiveMemberRecords}`);
    console.log(`candidate mismatches found: ${candidates}`);
    console.log(`updated: ${updates}`);
    console.log(`skipped unknown identity status: ${skippedUnknownIdentityStatus}`);
    console.log(`skipped already synced/racing: ${skippedAlreadySynced}`);
    console.log(`mode: ${options.apply ? 'apply' : 'dry-run'}`);
  } finally {
    await identityPrisma.$disconnect();
    await memberPrisma.$disconnect();
  }
}

void main().catch((error) => {
  console.error('[error] Backfill failed:', error);
  process.exitCode = 1;
});
