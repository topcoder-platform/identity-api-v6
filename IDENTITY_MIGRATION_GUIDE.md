# Identity Schema Migration Guide

This guide walks you through migrating from the current two-schema setup (authorization + common_oltp) to a unified identity schema.

## Overview

**Current State:**
- Two PostgreSQL schemas: `authorization` and `common_oltp`
- MySQL database with legacy authorization data

**Target State:**
- Single PostgreSQL schema: `identity`
- Unified user management combining both data sources
- MySQL remains as legacy data source during migration

## Migration Process Flow

```
MySQL (Legacy Auth) → PostgreSQL Identity ←─ PostgreSQL Temp (common_oltp)
```

## Prerequisites

1. Backup all existing databases
2. Ensure Docker and Docker Compose are installed
3. Update your `.env` file with new database configurations

## Step 1: Update Environment Configuration

Add these new environment variables to your `.env` file:

```bash
# Identity Database (Final target)
IDENTITY_DB_URL=postgresql://postgres:identitypassword@localhost:5432/identity

# Temporary common_oltp database (will run on port 5433)
TEMP_COMMON_OLTP_DB_URL=postgresql://postgres:identitypassword@localhost:5433/common_oltp_db

```

## Step 2: Start New Database Infrastructure

```bash
# Stop existing containers
docker-compose down

# Start new multi-database setup
docker-compose up -d

# Verify all services are running
docker-compose ps
```

You should see:
- `postgres-temp-common-oltp` (port 5433) - Temporary PostgreSQL for common_oltp data
- `postgres-identity` (port 5432) - Final PostgreSQL for identity schema
- `mysql-legacy-auth` (port 3306) - MySQL with legacy authorization data

## Step 3: Load Data to Temporary Databases

### 3.1 Load common_oltp Data

```bash
# If you have a common_oltp dump file
docker exec -i postgres-temp-common-oltp psql -U postgres -d common_oltp_db < /path/to/common_oltp
```

### 3.2 Load Authorization Data to MySQL

```bash
# Load your authorization data to MySQL
docker exec -i mysql-legacy-auth mysql -u root -pmysql-user-root-password authorization_db < /path/to/Authorization
```

## Step 4: Run Data Migration (Before Schema Creation)

The migration script will create tables and import data in the correct order to avoid constraint violations.

### 4.1 Run the Migration Script

```bash
# Install required dependencies (if not already installed)
pnpm add -D mysql2 pg @types/pg

# Run the RAW migration script
pnpm run db:migrate-to-identity
```

### 5.2 What the New Migration Does

The **raw migration script** (`migrate-to-identity.ts`) uses a different approach:

1. **Drops existing tables** (for clean migration)
2. **Creates tables without constraints** using raw SQL
3. **Imports all data** using raw SQL INSERT statements
4. **Applies constraints and indexes** after all data is imported
5. **No Prisma migrations needed** - everything is handled in the script

**Benefits:**
- ✅ **No unique constraint violations** during import
- ✅ **Faster bulk imports** using raw SQL
- ✅ **Clean migration** - drops and recreates tables
- ✅ **Handles duplicates gracefully** 
- ✅ **No need to run Prisma migrations beforehand**

**Usage:**
```bash
# Use the raw migration
npm run db:migrate-to-identity
```