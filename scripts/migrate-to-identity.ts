import { PrismaClient as IdentityClient } from '@prisma/client';
import mysql from 'mysql2/promise';

// Database clients
const identityDb = new IdentityClient({
  datasources: {
    db: {
      url: 'postgresql://postgres:identitypassword@localhost:5432/identity'
    }
  }
});

// Create a separate Prisma client for common_oltp database using raw connection
const createCommonOltpClient = () => new IdentityClient({
  datasources: { 
    db: { 
      url: 'postgresql://postgres:identitypassword@localhost:5433/common_oltp_db'
    } 
  }
});

// MySQL connection for authorization data
const createMysqlConnection = () => mysql.createConnection({
  host: 'localhost',
  port: 3306,
  user: 'mysql-user',
  password: 'mysql-password',
  database: 'authorization_db'
});

async function migrateData() {
  console.log('Starting identity schema migration (Raw SQL approach)...');

  try {
    // Step 1: Create tables without constraints
    await createTablesWithoutConstraints();

    // Step 2: Migrate lookup tables
    await migrateLookupTables();

    // Step 3: Migrate users from common_oltp
    await migrateUsers();

    // Step 4: Migrate authorization data from MySQL
    await migrateAuthorizationData();

    // Step 5: Migrate emails
    await migrateEmails();

    // Step 6: Migrate user relationships
    await migrateUserRelationships();

    // Step 7: Apply constraints and indexes
    await applyConstraintsAndIndexes();

    console.log('Migration completed successfully!');
  } catch (error) {
    console.error('Migration failed:', error);
    throw error;
  }
}

async function createTablesWithoutConstraints() {
  console.log('Creating tables without constraints...');

  // Drop existing tables if they exist (for clean migration)
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "role_assignments" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "user_emails" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "user_2fa" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "dice_connections" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "users" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "emails" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "roles" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "clients" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "email_types" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "email_statuses" CASCADE;`;
  await identityDb.$executeRaw`DROP TABLE IF EXISTS "achievement_types" CASCADE;`;

  // Create tables without constraints
  await identityDb.$executeRaw`
    CREATE TABLE "users" (
      "id" SERIAL PRIMARY KEY,
      "legacy_user_id" DECIMAL(10,0),
      "first_name" VARCHAR(64),
      "last_name" VARCHAR(64),
      "middle_name" VARCHAR(64),
      "handle" VARCHAR(50) NOT NULL,
      "handle_lower" VARCHAR(50),
      "status" VARCHAR(3) NOT NULL,
      "activation_code" VARCHAR(32),
      "password" VARCHAR(300),
      "open_id" VARCHAR(200),
      "name_in_another_language" VARCHAR(64),
      "timezone_id" DECIMAL(5,0),
      "reg_source" VARCHAR(20),
      "utm_source" VARCHAR(50),
      "utm_medium" VARCHAR(50),
      "utm_campaign" VARCHAR(50),
      "last_login" TIMESTAMP(6),
      "last_site_hit_date" TIMESTAMP(6),
      "created_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
      "modified_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP
    );
  `;

  await identityDb.$executeRaw`
    CREATE TABLE "emails" (
      "id" SERIAL PRIMARY KEY,
      "address" VARCHAR(100) NOT NULL,
      "type_id" INTEGER,
      "status_id" INTEGER DEFAULT 1,
      "created_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
      "modified_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP
    );
  `;



  await identityDb.$executeRaw`
    CREATE TABLE "roles" (
      "id" SERIAL PRIMARY KEY,
      "name" VARCHAR(255) NOT NULL,
      "description" VARCHAR(1000),
      "created_by" INTEGER,
      "created_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
      "modified_by" INTEGER,
      "modified_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP
    );
  `;

  await identityDb.$executeRaw`
    CREATE TABLE "clients" (
      "id" SERIAL PRIMARY KEY,
      "client_id" VARCHAR(255) NOT NULL,
      "name" VARCHAR(255) NOT NULL,
      "redirect_uri" VARCHAR(8192),
      "secret" VARCHAR(500),
      "created_by" INTEGER,
      "created_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
      "modified_by" INTEGER,
      "modified_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP
    );
  `;

  // Create lookup tables
  await identityDb.$executeRaw`
    CREATE TABLE "email_types" (
      "id" SERIAL PRIMARY KEY,
      "description" VARCHAR(100) NOT NULL,
      "created_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP
    );
  `;

  await identityDb.$executeRaw`
    CREATE TABLE "email_statuses" (
      "id" SERIAL PRIMARY KEY,
      "description" VARCHAR(100) NOT NULL,
      "created_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP
    );
  `;

  await identityDb.$executeRaw`
    CREATE TABLE "achievement_types" (
      "id" SERIAL PRIMARY KEY,
      "description" VARCHAR(64) NOT NULL
    );
  `;

  // Create relationship tables
  await identityDb.$executeRaw`
    CREATE TABLE "user_emails" (
      "user_id" INTEGER NOT NULL,
      "email_id" INTEGER NOT NULL,
      "is_primary" BOOLEAN DEFAULT false,
      "created_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP
    );
  `;



  await identityDb.$executeRaw`
    CREATE TABLE "role_assignments" (
      "id" SERIAL PRIMARY KEY,
      "role_id" INTEGER NOT NULL,
      "user_id" INTEGER NOT NULL,
      "subject_type" INTEGER DEFAULT 1,
      "created_by" INTEGER,
      "created_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
      "modified_by" INTEGER,
      "modified_at" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP
    );
  `;

  console.log('Tables created without constraints');
}

async function migrateLookupTables() {
  console.log('Migrating lookup tables...');

  // Email statuses
  await identityDb.$executeRaw`
    INSERT INTO "email_statuses" ("id", "description") VALUES 
    (1, 'Active'), (2, 'Inactive'), (3, 'Bounced');
  `;

  // Email types
  await identityDb.$executeRaw`
    INSERT INTO "email_types" ("id", "description") VALUES 
    (1, 'Primary'), (2, 'Secondary'), (3, 'Work');
  `;

  // Achievement types - create defaults
  await identityDb.$executeRaw`
    INSERT INTO "achievement_types" ("id", "description") VALUES 
    (1, 'First Login'), (2, 'Profile Complete'), (3, 'Challenge Winner');
  `;

  console.log('Lookup tables migrated');
}

async function migrateUsers() {
  console.log('Migrating users from common_oltp...');

  const commonOltpClient = createCommonOltpClient();
  
  try {
    // Query users from common_oltp using raw SQL
    const users = await commonOltpClient.$queryRaw<any[]>`
      SELECT user_id, first_name, last_name, middle_name, handle, handle_lower, 
             status, activation_code, password, open_id, name_in_another_language, 
             timezone_id, reg_source, utm_source, utm_medium, utm_campaign,
             last_login, last_site_hit_date, create_date, modify_date
      FROM common_oltp.user 
      LIMIT 1000
    `;
    console.log(`Found ${users.length} users to migrate`);

    if (users.length === 0) {
      console.log('No users found in common_oltp database. Skipping user migration.');
      return;
    }

    let migratedCount = 0;
    for (const user of users) {
      try {
        await identityDb.$executeRaw`
          INSERT INTO "users" (
            "legacy_user_id", "first_name", "last_name", "middle_name", 
            "handle", "handle_lower", "status", "activation_code", 
            "password", "open_id", "name_in_another_language", "timezone_id",
            "reg_source", "utm_source", "utm_medium", "utm_campaign",
            "last_login", "last_site_hit_date", "created_at", "modified_at"
          ) VALUES (
            ${user.user_id}, ${user.first_name}, ${user.last_name}, ${user.middle_name},
            ${user.handle}, ${user.handle_lower}, ${user.status}, ${user.activation_code},
            ${user.password}, ${user.open_id}, ${user.name_in_another_language}, ${user.timezone_id},
            ${user.reg_source}, ${user.utm_source}, ${user.utm_medium}, ${user.utm_campaign},
            ${user.last_login}, ${user.last_site_hit_date}, 
            ${user.create_date || new Date()}, ${user.modify_date || new Date()}
          );
        `;
        migratedCount++;
      } catch (error) {
        console.error(`Failed to migrate user ${user.handle}:`, error.message);
      }
    }

    console.log(`Migrated ${migratedCount} users`);
  } catch (error) {
    console.log('Error accessing common_oltp database:', error.message);
    console.log('Skipping user migration from common_oltp.');
  } finally {
    await commonOltpClient.$disconnect();
  }
}

async function migrateAuthorizationData() {
  console.log('Migrating authorization data from MySQL...');

  const mysql = await createMysqlConnection();

  try {
    // Migrate roles
    const [roles] = await mysql.execute('SELECT * FROM role');
    console.log(`Migrating ${(roles as any[]).length} roles...`);

    let roleCount = 0;
    for (const role of roles as any[]) {
      try {
        await identityDb.$executeRaw`
          INSERT INTO "roles" ("name", "created_by", "created_at", "modified_by", "modified_at")
          VALUES (${role.name}, ${role.created_by}, ${role.created_at || new Date()}, ${role.modified_by}, ${role.modified_at || new Date()});
        `;
        roleCount++;
      } catch (error) {
        console.error(`Failed to migrate role ${role.name}:`, error.message);
      }
    }

    // Migrate clients
    const [clients] = await mysql.execute('SELECT * FROM client');
    console.log(`Migrating ${(clients as any[]).length} clients...`);

    let clientCount = 0;
    for (const client of clients as any[]) {
      try {
        await identityDb.$executeRaw`
          INSERT INTO "clients" ("client_id", "name", "redirect_uri", "secret", "created_by", "created_at", "modified_by", "modified_at")
          VALUES (${client.client_id}, ${client.name}, ${client.redirect_uri}, ${client.secret}, 
                  ${client.created_by}, ${client.created_at || new Date()}, ${client.modified_by}, ${client.modified_at || new Date()});
        `;
        clientCount++;
      } catch (error) {
        console.error(`Failed to migrate client ${client.client_id}:`, error.message);
      }
    }

    console.log(`Migrated ${roleCount} roles, ${clientCount} clients`);

  } catch (error) {
    console.error('Error migrating authorization data:', error);
  } finally {
    await mysql.end();
  }
}

async function migrateEmails() {
  console.log('Migrating emails...');

  const commonOltpClient = createCommonOltpClient();
  
  try {
    // Query emails from common_oltp using raw SQL
    const emails = await commonOltpClient.$queryRaw<any[]>`
      SELECT email_id, address, email_type_id, status_id, create_date, modify_date
      FROM common_oltp.email 
      WHERE address IS NOT NULL
      LIMIT 10000
    `;
    if (emails.length === 0) {
      console.log('No emails found in common_oltp database. Skipping email migration.');
      return;
    }

    let emailCount = 0;
    for (const email of emails) {
      try {
        await identityDb.$executeRaw`
          INSERT INTO "emails" ("address", "type_id", "status_id", "created_at", "modified_at")
          VALUES (${email.address}, ${email.email_type_id || 1}, ${email.status_id || 1}, 
                  ${email.create_date || new Date()}, ${email.modify_date || new Date()});
        `;
        emailCount++;
      } catch (error) {
        // Skip duplicates silently
        if (!error.message.includes('duplicate key')) {
          console.error(`Failed to migrate email ${email.address}:`, error.message);
        }
      }
    }

    console.log(`Migrated ${emailCount} emails`);
  } catch (error) {
    console.log('Error accessing emails in common_oltp database:', error.message);
  } finally {
    await commonOltpClient.$disconnect();
  }
}

async function migrateUserRelationships() {
  console.log('Migrating user relationships...');

  const mysql = await createMysqlConnection();

  try {
    // Migrate role assignments
    const [roleAssignments] = await mysql.execute('SELECT * FROM role_assignment LIMIT 5000');
    console.log(`Migrating ${(roleAssignments as any[]).length} role assignments...`);

    let assignmentCount = 0;
    for (const assignment of roleAssignments as any[]) {
      try {
        // Find user by legacy ID
        const userResult = await identityDb.$queryRaw<{ id: number }[]>`
          SELECT "id" FROM "users" WHERE "legacy_user_id" = ${assignment.subject_id} LIMIT 1;
        `;

        if (userResult.length > 0) {
          await identityDb.$executeRaw`
            INSERT INTO "role_assignments" ("role_id", "user_id", "subject_type", "created_by", "created_at", "modified_by", "modified_at")
            VALUES (${assignment.role_id}, ${userResult[0].id}, ${assignment.subject_type}, 
                    ${assignment.created_by}, ${assignment.created_at || new Date()}, ${assignment.modified_by}, ${assignment.modified_at || new Date()});
          `;
          assignmentCount++;
        }
      } catch (error) {
        // Skip duplicates silently
        if (!error.message.includes('duplicate key')) {
          console.error(`Failed to migrate role assignment:`, error.message);
        }
      }
    }

    console.log(`Migrated ${assignmentCount} role assignments`);

  } catch (error) {
    console.error('Error migrating user relationships:', error);
  } finally {
    await mysql.end();
  }
}

async function applyConstraintsAndIndexes() {
  console.log('Applying constraints and indexes...');

  try {
    // Add unique constraints
    await identityDb.$executeRaw`ALTER TABLE "users" ADD CONSTRAINT "users_handle_key" UNIQUE ("handle");`;
    await identityDb.$executeRaw`ALTER TABLE "users" ADD CONSTRAINT "users_legacy_user_id_key" UNIQUE ("legacy_user_id");`;
    await identityDb.$executeRaw`ALTER TABLE "emails" ADD CONSTRAINT "emails_address_key" UNIQUE ("address");`;
    await identityDb.$executeRaw`ALTER TABLE "roles" ADD CONSTRAINT "roles_name_key" UNIQUE ("name");`;
    await identityDb.$executeRaw`ALTER TABLE "clients" ADD CONSTRAINT "clients_client_id_key" UNIQUE ("client_id");`;

    // Add composite unique constraints
    await identityDb.$executeRaw`ALTER TABLE "user_emails" ADD CONSTRAINT "user_emails_pkey" PRIMARY KEY ("user_id", "email_id");`;
    await identityDb.$executeRaw`ALTER TABLE "role_assignments" ADD CONSTRAINT "role_assignments_role_id_user_id_subject_type_key" UNIQUE ("role_id", "user_id", "subject_type");`;

    // Add indexes
    await identityDb.$executeRaw`CREATE INDEX "users_handle_idx" ON "users" ("handle");`;
    await identityDb.$executeRaw`CREATE INDEX "users_handle_lower_idx" ON "users" ("handle_lower");`;
    await identityDb.$executeRaw`CREATE INDEX "users_status_idx" ON "users" ("status");`;
    await identityDb.$executeRaw`CREATE INDEX "emails_address_idx" ON "emails" ("address");`;
    await identityDb.$executeRaw`CREATE INDEX "role_assignments_user_id_idx" ON "role_assignments" ("user_id");`;
    await identityDb.$executeRaw`CREATE INDEX "role_assignments_role_id_idx" ON "role_assignments" ("role_id");`;

    console.log('Constraints and indexes applied');
  } catch (error) {
    console.error('Some constraints/indexes may already exist:', error.message);
  }
}

// Verification function
async function verifyMigration() {
  console.log('Verifying migration...');

  const userCount = await identityDb.$queryRaw<{ count: bigint }[]>`SELECT COUNT(*) as count FROM "users";`;
  const roleCount = await identityDb.$queryRaw<{ count: bigint }[]>`SELECT COUNT(*) as count FROM "roles";`;
  const emailCount = await identityDb.$queryRaw<{ count: bigint }[]>`SELECT COUNT(*) as count FROM "emails";`;
  const clientCount = await identityDb.$queryRaw<{ count: bigint }[]>`SELECT COUNT(*) as count FROM "clients";`;

  console.log(`Migration verification:
    - Users: ${userCount[0].count}
    - Roles: ${roleCount[0].count}
    - Emails: ${emailCount[0].count}
    - Clients: ${clientCount[0].count}
  `);
}

// Main execution
async function main() {
  try {
    await migrateData();
    await verifyMigration();
  } catch (error) {
    console.error('Migration failed:', error);
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