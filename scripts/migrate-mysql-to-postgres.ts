import * as mysql from 'mysql2/promise';
import { PrismaClient as PrismaClientAuthorization } from '@prisma/client-authorization';
import * as dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

const BATCH_SIZE = 1000; // Process 100 records at a time

// --- Construct PostgreSQL URL from individual components ---
const pgUser = process.env.DB_USERNAME;
const pgPassword = process.env.DB_PASSWORD;
const pgHost = process.env.DB_HOST || 'localhost'; // Default if not set
const pgPort = process.env.DB_PORT || '5432'; // Default if not set
const pgDbName = process.env.AUTHORIZATION_DB_NAME || 'authorization_db'; // Default if not set

// Basic check for required variables
if (!pgUser || !pgPassword || !pgDbName) {
  console.error(
    'Error: Missing required PostgreSQL environment variables (DB_USERNAME, DB_PASSWORD, AUTHORIZATION_DB_NAME) in .env',
  );
  process.exit(1);
}

// Construct the URL manually
const pgDatabaseUrl = `postgresql://${pgUser}:${pgPassword}@${pgHost}:${pgPort}/${pgDbName}?schema=public`;
// Removed sslmode=disable based on your .env, add it back if needed:
// const pgDatabaseUrl = `postgresql://${pgUser}:${pgPassword}@${pgHost}:${pgPort}/${pgDbName}?schema=public&sslmode=disable`;
// --------------------------------------------------------

// Instantiate Prisma Client for PostgreSQL using the constructed URL
console.log(
  `Using PostgreSQL URL: postgresql://${pgUser}:***@${pgHost}:${pgPort}/${pgDbName}?schema=public`,
); // Log without password
const prisma = new PrismaClientAuthorization({
  datasources: {
    db: {
      url: pgDatabaseUrl, // Use the manually constructed URL
    },
  },
});

async function migrateTable(
  mysqlConn: mysql.Connection,
  tableName: string,
  prismaModel: keyof PrismaClientAuthorization,
  columnMapping: { [mysqlCol: string]: string },
  transformFn?: (row: any) => any,
) {
  console.log(`\n--- Migrating table: ${tableName} ---`);
  let offset = 0;
  let totalMigrated = 0; // Count of successfully inserted records
  let totalAttempted = 0; // Count of records fetched from MySQL to attempt insertion
  let totalCount = 0;
  let batchCounter = 0;

  try {
    // Get total source count
    const [countResult]: any = await mysqlConn.query(
      `SELECT COUNT(*) as count FROM ${tableName}`,
    );
    totalCount = countResult[0].count;
    console.log(`Total records to migrate in ${tableName}: ${totalCount}`);

    if (totalCount === 0) {
      console.log(`Table ${tableName} is empty, skipping.`);
      return;
    }

    while (true) {
      batchCounter++;
      // Fetch batch from MySQL
      const [rows]: any = await mysqlConn.query(
        `SELECT * FROM ${tableName} ORDER BY id LIMIT ? OFFSET ?`,
        [BATCH_SIZE, offset],
      );

      if (rows.length === 0) {
        break; // No more rows
      }

      totalAttempted += rows.length; // Increment attempted count

      // Map data
      const dataToInsert = rows.map((row: any) => {
        const mappedRow: any = {};
        for (const mysqlCol in columnMapping) {
          const prismaField = columnMapping[mysqlCol];
          if (row[mysqlCol] instanceof Date) {
            mappedRow[prismaField] = row[mysqlCol].toISOString();
          } else if (
            typeof row[mysqlCol] === 'number' &&
            (prismaField.endsWith('At') || prismaField.endsWith('Date'))
          ) {
            mappedRow[prismaField] = new Date(row[mysqlCol]).toISOString();
          } else {
            mappedRow[prismaField] = row[mysqlCol];
          }
        }
        return transformFn ? transformFn(mappedRow) : mappedRow;
      });

      // Insert batch into PostgreSQL
      try {
        const result = await (prisma[prismaModel] as any).createMany({
          data: dataToInsert,
          skipDuplicates: true,
        });
        totalMigrated += result.count; // Add successfully inserted count
      } catch (prismaError: any) {
        console.error(
          `Error inserting batch ${batchCounter} into ${String(prismaModel)}:`,
          prismaError,
        );
        console.error(
          'Failed batch data:',
          JSON.stringify(dataToInsert, null, 2),
        );
        throw new Error(
          `Stopping migration due to error in ${String(prismaModel)} batch insertion.`,
        );
      }

      offset += rows.length;

      // Log progress periodically
      if (batchCounter % 100 === 0 || offset >= totalCount) {
        const currentSkipped = totalAttempted - totalMigrated; // Calculate skipped so far
        console.log(
          `Progress for ${tableName}: ${totalMigrated}/${totalAttempted} attempted (${totalCount} total source), ${currentSkipped} skipped (Batch ${batchCounter})`,
        );
      }

      if (offset >= totalCount) {
        break;
      }
    }
  } catch (error) {
    console.error(`Error migrating ${tableName}:`, error);
    throw error;
  }
  // Final log with skipped count
  const finalSkipped = totalAttempted - totalMigrated;
  console.log(
    `--- Finished migrating ${tableName}. Attempted: ${totalAttempted}. Migrated: ${totalMigrated}. Skipped: ${finalSkipped}. ---`,
  );

  // --- Add Sequence Reset Logic --- +
  const pgSafeTableName = tableName.replace(/`/g, '');
  try {
    // Sanitize MySQL table name for use as PostgreSQL table name
    // (e.g., remove backticks from `group`)
    // *** Add check to skip non-integer ID tables ***
    if (pgSafeTableName === 'permission_policy') {
      console.log(
        `Skipping sequence reset for table "${pgSafeTableName}" as its ID is not an integer sequence.`,
      );
    } else {
      // Construct the SQL to reset the sequence
      // Assumes the primary key column is always named 'id'
      const resetSeqSql = `SELECT setval(pg_get_serial_sequence('${pgSafeTableName}', 'id'), COALESCE(max(id), 0)+1, false) FROM "${pgSafeTableName}";`;

      console.log(
        `Attempting to reset ID sequence for table "${pgSafeTableName}"...`,
      );
      // Execute the raw SQL query
      await prisma.$executeRawUnsafe(resetSeqSql);
      console.log(`Successfully reset ID sequence for "${pgSafeTableName}".`);
    }
  } catch (seqError: any) {
    // Log a warning if sequence reset fails (e.g., table doesn't have 'id' or sequence)
    // Use pgSafeTableName in the warning message if it was defined
    const targetTableName =
      typeof pgSafeTableName !== 'undefined' ? pgSafeTableName : tableName;
    console.warn(
      `Warning: Could not automatically reset ID sequence for table "${targetTableName}". Manual check/reset might be needed. Error: ${seqError.message}`,
    );
  }
  // --- End Sequence Reset Logic ---
}

// --- Main Migration Logic ---
async function main() {
  let mysqlConn: mysql.Connection | null = null;

  try {
    // --- Add Debug Logging for MySQL Vars ---
    console.log('--- MySQL Connection Variables ---');
    console.log('MYSQL_HOST:', process.env.MYSQL_HOST);
    console.log('MYSQL_PORT:', process.env.MYSQL_PORT);
    console.log('MYSQL_USER:', process.env.MYSQL_USER);
    console.log(
      'MYSQL_PASSWORD:',
      process.env.MYSQL_PASSWORD ? '***' : 'undefined',
    ); // Don't log password
    console.log('MYSQL_DATABASE:', process.env.MYSQL_DATABASE);
    console.log('-------------------------------');
    // ----------------------------------------

    // Connect to MySQL
    console.log('Connecting to MySQL...');
    mysqlConn = await mysql.createConnection({
      host: process.env.MYSQL_HOST,
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASSWORD,
      database: process.env.MYSQL_DATABASE,
      // Ensure dates are returned as Date objects
      dateStrings: false, // Important: Read MySQL DATETIME/TIMESTAMP as JS Date objects
    });
    console.log('MySQL connected.');

    // Connect to PostgreSQL (Prisma)
    console.log('Connecting to PostgreSQL via Prisma...');
    await prisma.$connect();
    console.log('Prisma connected.');

    console.log('\nStarting migration...');
    const startTime = Date.now();

    // --- Define Mappings and Run Migrations in Order ---

    // 1. Role
    await migrateTable(mysqlConn, 'role', 'role', {
      id: 'id',
      name: 'name',
      createdBy: 'createdBy',
      createdAt: 'createdAt',
      modifiedBy: 'modifiedBy',
      modifiedAt: 'modifiedAt',
    });

    // 2. Group
    await migrateTable(
      mysqlConn,
      '`group`',
      'group',
      {
        // Note backticks for reserved keyword
        id: 'id',
        name: 'name',
        description: 'description',
        createdBy: 'createdBy',
        createdAt: 'createdAt',
        modifiedBy: 'modifiedBy',
        modifiedAt: 'modifiedAt',
        private_group: 'privateGroup', // Map snake_case -> camelCase
        self_register: 'selfRegister', // Map snake_case -> camelCase
      },
      (row) => {
        // Transform tinyint(1) to boolean for Prisma
        row.privateGroup = Boolean(row.privateGroup);
        row.selfRegister = Boolean(row.selfRegister);
        return row;
      },
    );

    // 3. Client
    await migrateTable(mysqlConn, 'client', 'client', {
      id: 'id',
      client_id: 'clientId', // Map snake_case -> camelCase
      name: 'name',
      redirect_uri: 'redirectUri', // Map snake_case -> camelCase
      secret: 'secret',
      createdBy: 'createdBy',
      createdAt: 'createdAt',
      modifiedBy: 'modifiedBy',
      modifiedAt: 'modifiedAt',
    });

    // 4. Permission Policy - Note: mediumtext mapping needs verification in Prisma schema
    await migrateTable(mysqlConn, 'permission_policy', 'permissionPolicy', {
      id: 'id',
      subjectId: 'subjectId',
      subjectType: 'subjectType',
      resource: 'resource',
      createdBy: 'createdBy',
      createdAt: 'createdAt',
      modifiedBy: 'modifiedBy',
      modifiedAt: 'modifiedAt',
      policy: 'policy', // Assuming 'policy' field is String in Prisma
    });

    // 5. Role Assignment
    await migrateTable(mysqlConn, 'role_assignment', 'roleAssignment', {
      id: 'id',
      role_id: 'roleId', // Map snake_case -> camelCase
      subject_id: 'subjectId', // Map snake_case -> camelCase
      subject_type: 'subjectType', // Map snake_case -> camelCase
      createdBy: 'createdBy',
      createdAt: 'createdAt',
      modifiedBy: 'modifiedBy',
      modifiedAt: 'modifiedAt',
    });

    // 6. Group Membership
    await migrateTable(mysqlConn, 'group_membership', 'groupMembership', {
      id: 'id',
      group_id: 'groupId', // Map snake_case -> camelCase
      member_id: 'memberId', // Map snake_case -> camelCase
      membership_type: 'membershipType', // Map snake_case -> camelCase
      createdBy: 'createdBy',
      createdAt: 'createdAt',
      modifiedBy: 'modifiedBy',
      modifiedAt: 'modifiedAt',
    });

    // 7. Client User
    await migrateTable(mysqlConn, 'client_user', 'clientUser', {
      id: 'id',
      client_id: 'clientId', // Map snake_case -> camelCase
      user_id: 'userId', // Map snake_case -> camelCase
      scope: 'scope',
      createdBy: 'createdBy',
      createdAt: 'createdAt',
      modifiedBy: 'modifiedBy',
      modifiedAt: 'modifiedAt',
    });

    // --- End Migrations ---

    const endTime = Date.now();
    console.log(
      `\nMigration finished in ${(endTime - startTime) / 1000} seconds.`,
    );
  } catch (error) {
    console.error('\nMigration failed:', error);
    process.exit(1); // Exit with error code
  } finally {
    // Ensure connections are closed
    if (mysqlConn) {
      console.log('Closing MySQL connection...');
      await mysqlConn.end();
      console.log('MySQL connection closed.');
    }
    console.log('Disconnecting Prisma...');
    await prisma.$disconnect();
    console.log('Prisma disconnected.');
  }
}

// Run the main migration function
main();
