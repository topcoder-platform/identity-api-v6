# Identity Provider API Verification Guide

## 🎯 Overview
This document provides simple steps to verify the Identity Provider API with E2E and Unit tests.

## 📋 Prerequisites
- Node.js and pnpm installed
- PostgreSQL running on localhost:5432
- Application running on localhost:3000

## 🔧 Environment Setup

### 1. Create .env File
Create a `.env` file in the project root with the following content:

```bash
# POSTGRESQL DATABASES
GROUP_DB_URL="postgresql://postgres:identitypassword@localhost:5432/group"
IDENTITY_DB_URL="postgresql://postgres:identitypassword@localhost:5432/identity"
MEMBER_DB_URL="postgresql://postgres:identitypassword@localhost:5432/member"
```

### 2. Check Code Quality (Optional but Recommended)
```bash
pnpm run lint
```

### 3. Install Dependencies
```bash
pnpm install
```

**Note:** Run `pnpm run lint` before `pnpm install` to ensure code quality and catch any linting issues early.

## 🗄️ Database Setup

### 1. Create Test Database
```bash
# Connect to PostgreSQL and create test database
psql -U postgres -h localhost
CREATE DATABASE identity_test2;
\q
```

### 2. Run Database Migrations
```bash
# Set database URL and run migrations
export IDENTITY_DB_URL="postgresql://postgres:postgres@localhost:5432/identity_test2"
npx prisma migrate deploy --schema=./prisma/schema.prisma
```

## 🧪 E2E Tests

### Run All E2E Tests
```bash
pnpm run test:e2e:identity-provider


pnpm run test:e2e:identity-provider --coverage
```

## 🔬 Unit Tests

### Run All Unit Tests
```bash
pnpm run test:unit:identity-provider-all

pnpm run test:unit:identity-provider-all --coverage
```

### Run Individual Tests
```bash
# Service tests only
pnpm run test:unit:identity-provider

# Controller tests only
pnpm run test:unit:identity-provider-controller

```


## 🚀 API Testing

### Test API Endpoint
```bash
# Test with handle
curl "http://localhost:3000/v6/identityproviders?handle=testuser"

# Test with email
curl "http://localhost:3000/v6/identityproviders?email=test@example.com"

# Test with both (handle takes precedence)
curl "http://localhost:3000/v6/identityproviders?handle=testuser&email=test@example.com"
```

### Expected Response Format:
```json
{
  "result": {
    "success": true,
    "status": 200,
    "metadata": null,
    "content": {
      "name": "okta",
      "type": "OIDC"
    }
  },
  "version": "v6"
}
```

## 🐛 Troubleshooting

### Database Connection Issues
```bash
# Check if PostgreSQL is running
pg_isready -h localhost -p 5432

# Reset test database
dropdb -U postgres identity_test2
createdb -U postgres identity_test2
```

### Test Failures
```bash
# Clean and reinstall dependencies
rm -rf node_modules pnpm-lock.yaml
pnpm install

# Clear Jest cache
pnpm test --clearCache
```
