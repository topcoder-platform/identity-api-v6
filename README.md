# TC Identity Service

## Prerequisites

Before you begin, ensure you have the following installed on your system:

*   **Node.js:** Version 22.13.1 is recommended. Using [nvm](https://github.com/nvm-sh/nvm) is advised:
    ```bash
    nvm install 22.13.1
    nvm use 22.13.1
    ```
*   **pnpm:** Install globally using npm:
    ```bash
    npm install -g pnpm
    ```
*   **PostgreSQL Client (`psql`):** Required for importing the database dump. Install the command-line tools from the [official PostgreSQL website](https://www.postgresql.org/download/).
*   **MySQL Client (`mysql`):** Required for importing the legacy authorization dump before migration. Install the command-line tools from the [official MySQL website](https://www.mysql.com/downloads/).
*   **Docker:** The latest version of Docker Desktop or Docker Engine is needed to run the databases and Redis. Download from the [official Docker website](https://www.docker.com/products/docker-desktop/).

## Database Overview

This service uses two separate PostgreSQL databases running in Docker:
- `common_oltp_db`: Contains existing tables and data (from an imported dump).
- `authorization_db`: New database for tables migrated from MySQL (managed by Prisma Migrate).

Additionally, a temporary MySQL database is used during the legacy data migration process.

### Local Development Setup

Follow these steps to set up and run the application locally:

1.  **Install Dependencies:**
    Clone the repository and install the necessary Node.js packages using pnpm.
    ```bash
    pnpm install
    ```
    *(This command also runs `pnpm run prisma:generate` automatically via the `postinstall` script to generate Prisma clients for both databases.)*

2.  **Configure Environment:**
    Copy the example environment file and update the necessary variables.
    ```bash
    cp .env.sample .env
    ```
    *   **Crucially, update `AUTH_SECRET`** to a strong, unique secret key for local HS256 JWT generation. Do not use the default placeholder.
    *   **Crucially, update `AUTH0_CLIENT_SECRET`** as provided in the forum.
    *   Verify database connection URLs (`COMMON_OLTP_DB_URL`, `AUTHORIZATION_DB_URL`), database names (`COMMON_OLTP_DB_NAME`, `AUTHORIZATION_DB_NAME`), ports (`DB_PORT`, `MYSQL_PORT`), and credentials (`DB_USERNAME`, `DB_PASSWORD`). The defaults in `.env.sample` usually work with the provided `docker-compose.yml`.
    *   Ensure `JWT_VALIDATION_MODE` is set to `HS256` for local development (this is the default in `.env.sample`).

3.  **Start Services:**
    Launch the PostgreSQL databases, MySQL database (for migration), and Redis using Docker Compose.
    ```bash
    docker compose up -d
    ```
    *   Wait a few moments for the databases to initialize completely.

4.  **Import Common OLTP Data:**
    Import the `common_oltp` database dump into the `common_oltp_db` PostgreSQL database. 
    ```bash
    # Replace ~/Downloads/common_oltp with the actual path to your dump file. (Download it from forum, and extract from zip) - Use password from DB_PASSWORD of .env file
    # Ensure DB_HOST, DB_PORT, DB_USERNAME, and COMMON_OLTP_DB_NAME match your .env values.
    psql -h ${DB_HOST:-127.0.0.1} -p ${DB_PORT:-5432} -U ${DB_USERNAME:-topcoderuser} \
         -d ${COMMON_OLTP_DB_NAME:-common_oltp_db} \
         -f ~/Downloads/common_oltp -v ON_ERROR_STOP=0
    ```

5.  **Initialize Authorization Database Schema:**
    Apply the Prisma migrations to create the necessary tables in the `authorization_db` PostgreSQL database.
    ```bash
    pnpm prisma migrate dev --name init  --schema prisma/authorization/schema.prisma
    ```

6.  **Migrate Legacy Authorization Data:**
    This step involves importing data from a legacy MySQL dump into the temporary MySQL container and then migrating it to the new `authorization_db` PostgreSQL database. 
    *   **Import MySQL Dump:**
        ```bash
        # Replace ~/Downloads/Authorization with the actual path to your MySQL dump file (Download it from forum, and extract from zip)
        # Ensure MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, and MYSQL_DATABASE match your .env values.  Use the password from .env when asked.
        mysql -h ${MYSQL_HOST:-127.0.0.1} -P ${MYSQL_PORT:-3306} -u ${MYSQL_USER:-root} -p${MYSQL_PASSWORD:-mysql-user-root-password} ${MYSQL_DATABASE:-authorization_db} < ~/Downloads/Authorization
        ```
    *   **Run Migration Script:**
        ```bash
        pnpm run db:migrate-legacy
        ```

7.  **Run Unit Tests:**
    You can run the unit tests to verify the setup.
    ```bash
    pnpm run test

    tc-identity-service@1.0.0 test
    > jest

    PASS  src/api/role/role.service.spec.ts (5.636 s)
    PASS  src/api/user/user.service.spec.ts (5.657 s)
    PASS  src/api/role/role.controller.spec.ts (5.674 s)
    PASS  src/api/user/user.controller.spec.ts (6.036 s)

    Test Suites: 4 passed, 4 total
    Tests:       83 passed, 83 total
    Snapshots:   0 total
    Time:        6.715 s
    Ran all test suites.

    ```

8.  **Generate an Admin Token:**
    For interacting with the API locally (e.g., via Postman), generate a test JWT using the provided script. This requires `JWT_VALIDATION_MODE=HS256` and a defined `AUTH_SECRET` in your `.env` file.
    ```bash
    # Generate a default admin token (expires in 8 hours)
    node scripts/generate-local-token.js
    ```
    Copy the generated token (the long string starting with `eyJ...`). See the "Generating Local HS256 Tokens" section below for more options.

9.  **Update Postman Environment file**
    You'll need to update the Authorization Bearer token in the `doc/postman_environment.json` with the one generated in the previous step.
    

10. **Start the Application:**
    Run the NestJS application in development mode (with hot-reloading).
    ```bash
    pnpm run start:dev
    ```
    The API should now be available, at `http://localhost:3000`.

11. **Run Postman/Newman Tests:**
    After starting the application, you can run the individual Postman collection tests using Newman. Ensure your Postman environment (`doc/postman_environment.json`) is configured, especially the `baseUrl` and `accessToken`. 

    *   **Roles API Tests:**
        ```bash
        pnpm run test:postman:roles
        ```
    *   **Users API Tests:**
       - Import `doc/postman_environment` and `users.postman_collection.json` to your postman app. These tests cannot be fully automated because it requires getting tokens from emails. 
       - Follow the video `users-endpoint.mp4` to test all endpoints provided with a sample email. 

    Use below command to generate a user token
    ```bash
    node scripts/generate-local-token.js "100000157" "Topcoder User" "user100000147handle" "user100000147@example.com" "read:dice,write:dice" "1h"
    ```

### Prisma Setup

Prisma is configured to manage both databases separately.

1.  **For the `authorization_db` Database:**
    *   This database schema is managed by Prisma Migrate.
    *   To create the database and apply migrations during development:
        ```bash
        pnpm run prisma:migrate:authorization
        ```
    *   To apply migrations in production-like environments:
        ```bash
        pnpm run prisma:deploy:authorization
        ```
    *   Generate the client if needed:
        ```bash
        pnpm run prisma:generate:authorization
        ```


2.  **For the `common_oltp_db` Database:**
    *   This database uses an imported dump. If the dump changes, or for initial setup verification, you can update the Prisma schema to match the database:
        ```bash
        pnpm run prisma:pull:common_oltp
        ```
    *   After pulling, regenerate the client if needed (though `pnpm install` should handle it):
        ```bash
        pnpm run prisma:generate:common_oltp
        ```

3.  **Prisma Studio (for browsing data):**
    *   Open Studio for `common_oltp_db` (runs on port 5555):
        ```bash
        pnpm run prisma:studio:common_oltp
        ```
    *   Open Studio for `authorization_db` (runs on port 5556):
        ```bash
        pnpm run prisma:studio:authorization
        ```
    *   Open both studios concurrently:
        ```bash
        pnpm run prisma:studio
        ```

## Legacy MySQL Dump Import (Details)

The `pnpm run db:migrate-legacy` script handles the migration from a temporary MySQL database (populated from a dump) to the `authorization_db` PostgreSQL database.

1.  **Ensure MySQL Container is Running:** The `docker-compose up -d` command should start a MySQL service (check `docker-compose.yml`).
2.  **Import the MySQL Dump:** Use the `mysql` command-line tool to import your legacy `Authorization` dump into the running MySQL container. See Step 6 in the "Local Development Setup" for the command. Ensure connection details match your `.env` configuration (`MYSQL_HOST`, `MYSQL_PORT`, etc.).
3.  **Run the Migration Script:** Execute the script to transfer and transform the data.
    ```bash
    pnpm run db:migrate-legacy
    ```

## Environment Configuration

The following table summarizes the environment variables used by the application. Copy `.env.sample` to `.env` and customize these values as needed.

| Variable                   | Description                                                                 | Default Value (`.env.sample`) |
| :------------------------- | :-------------------------------------------------------------------------- | :---------------------------- |
| `NODE_ENV`                 | Application environment (e.g., `development`, `production`)                   | `development`                 |
| `PORT`                     | Port the application listens on                                             | `3000`                        |
|                            | **Database (PostgreSQL - Common OLTP)**                                     |                               |
| `DB_HOST`                  | Hostname for the main PostgreSQL database                                   | `127.0.0.1`                   |
| `DB_PORT`                  | Port for the main PostgreSQL database                                       | `5432`                        |
| `DB_USERNAME`              | Username for the main PostgreSQL database                                   | `topcoderuser`                |
| `DB_PASSWORD`              | Password for the main PostgreSQL database                                   | `randompassword`              |
| `COMMON_OLTP_DB_NAME`      | Name of the main PostgreSQL database                                        | `common_oltp_db`              |
|                            | **Database (PostgreSQL - Authorization)**                                   |                               |
| `AUTHORIZATION_DB_NAME`    | Name of the authorization PostgreSQL database                             | `authorization_db`            |
|                            | **Database (MySQL - Legacy Migration)**                                     |                               |
| `MYSQL_HOST`               | Hostname for the temporary MySQL database (for migration)                   | `127.0.0.1`                   |
| `MYSQL_PORT`               | Port for the temporary MySQL database                                       | `3307`                        |
| `MYSQL_USER`               | Username for the temporary MySQL database                                   | `root`                        |
| `MYSQL_PASSWORD`           | Password for the temporary MySQL database                                   | `mysql-user-root-password`    |
| `MYSQL_DATABASE`           | Name of the temporary MySQL database                                        | `authorization_db`            |
|                            | **Redis Cache**                                                             |                               |
| `REDIS_HOST`               | Hostname for the Redis cache instance                                       | `127.0.0.1`                   |
| `REDIS_PORT`               | Port for the Redis cache instance                                           | `6380`                        |
|                            | **JWT Validation**                                                          |                               |
| `JWT_VALIDATION_MODE`      | Validation mode: `HS256` (local) or `RS256` (prod/staging)                  | `HS256`                       |
| `AUTH_SECRET`              | Secret key for HS256 token generation/validation (local only). **CHANGE THIS!** | `<<<REPLACE WITH A REAL SECRET KEY>>>` |
| `JWT_ISSUER_URL`           | Expected issuer URL in JWTs                                                 | `https://api.topcoder-dev.com` |
| `JWT_AUDIENCE`             | Expected audience in JWTs                                                   | `www.example.com`             |
| `JWT_JWKS_URI`             | JWKS endpoint URI for RS256 validation (prod/staging only)                  | *(commented out)*             |
|                            | **DICE Authentication**                                                     |                               |
| `DICEAUTH_DICE_API_URL`    | Base URL for the DICE API.                                                      | `https://console-api-uat.diceid.com/v1` (example) |
| `DICEAUTH_DICE_API_KEY`    | API key for authenticating with the DICE API (used in `x-api-key` header).      | `wGu5zRfmgJ8zP...` (example)                |
| `DICEAUTH_ORG_ID`          | Organization ID for DICE API calls (used in `org_id` header).                   | `4f541723-f581-44de-b61c-5f83e8b8ef1e` (example) |
| `DICEAUTH_USER_ID`         | User ID for invoking DICE APIs (used in `invoked_by` header).                   | `a5e7e72a-fa5e-4acf-9eca-741d1443279b` (example) |
| `DICEAUTH_TC_API_KEY`      | API key used by this application to validate incoming webhooks from DICE.       | `iQEErpTqL7ZiX...` (example)                |
| `DICEAUTH_SCHEMA_NAME`     | Name of the credential schema used in DICE.                                     | `Topcoder` (example)                        |
| `DICEAUTH_SCHEMA_VERSION`  | Version of the credential schema used in DICE.                                  | `1.4` (example)                             |
| `DICEAUTH_OTP_DURATION`    | OTP validity duration in minutes (e.g., for 2FA flows). Defaults to 10 if `DEV_DICEAUTH_OTP_DURATION` is used by code and not set. | `10` (example, in minutes)                |
|                            | **Slack Integration**                                                       |                               |
| `SLACK_BOT_KEY`            | Bot token for Slack API authentication.                                         | `xoxb-3858018789-...` (example)             |
| `SLACK_CHANNEL_ID`         | Default Slack channel ID for sending notifications.                             | `C04ENKCU4TZ` (example)                     |
|                            | **SendGrid Integration**                                                    |                               |
| `SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID` | SendGrid template ID for resend activation email.           | `d-73c29be82bfa4d68beea2208b6a3c4b2` (example) |
| `SENDGRID_WELCOME_EMAIL_TEMPLATE_ID`         | SendGrid template ID for welcome email.                       | `d-26c8962fb48c42a3997053ebe5954516` (example) |
|                            | **Other**                                                                   |                               |
| `ADMIN_ROLE_NAME`          | Name of the role considered admin                                           | `administrator`               |
| `LOG_LEVEL`                | Logging level (e.g., `debug`, `info`, `warn`, `error`)                      | `info`                        |
| `JWT_SECRET`               | Secret key for signing/verifying internal JWTs (e.g., 2FA, one-time tokens).  | `just-a-random-string` (example)            |
| `LEGACY_BLOWFISH_KEY`      | Base64 encoded Blowfish key for legacy password encryption/decryption.        | `dGhpc2lzRGVmYXVmZlZhbHVl` (example)        |

### JWT Validation

The application supports two JWT validation modes, configured via `JWT_VALIDATION_MODE`:

**1. Local Development (HS256 Mode - Recommended)**

Use this mode for local testing, allowing you to generate tokens easily without needing an external IdP.

- Set `JWT_VALIDATION_MODE=HS256`
- Set `AUTH_SECRET` to a strong, unique secret key. **Do not use the default placeholder.**
- Optionally, set `JWT_ISSUER_URL` and `JWT_AUDIENCE` to match the values you intend to put in your generated tokens (defaults are provided).
- Comment out or remove `JWT_JWKS_URI`.

**2. Production/Staging (RS256 Mode - Default)**

Use this mode when deploying, validating tokens against a real identity provider (like Auth0).

- Set `JWT_VALIDATION_MODE=RS256` or omit the variable.
- Set `JWT_ISSUER_URL` to your IdP's issuer URL.
- Set `JWT_AUDIENCE` to your API's audience identifier registered with the IdP.
- Set `JWT_JWKS_URI` to the JWKS endpoint of your IdP.
- Comment out or remove `AUTH_SECRET`.

## Compile and run the project

```bash
# development
$ pnpm run start

# watch mode
$ pnpm run start:dev

# production mode
$ pnpm run start:prod
```

## Run tests

```bash
# unit tests
$ pnpm run test

# e2e tests
$ pnpm run test:e2e

# test coverage
$ pnpm run test:cov
```

## Running the Application

```bash
# Install dependencies
pnpm install

# Run database migrations (if applicable)
# Example: pnpm prisma migrate dev --schema=./prisma/authorization.prisma
# Example: pnpm prisma migrate dev --schema=./prisma/common_oltp.prisma 

# Start the application in development mode (with hot-reloading)
pnpm run start:dev
```

## Generating Local HS256 Tokens

When running in `HS256` mode locally, you can generate valid JWTs using the provided script:

1.  **Ensure `.env` is configured:**
    *   `JWT_VALIDATION_MODE=HS256`
    *   `AUTH_SECRET` is set to your chosen secret key.
    *   `JWT_ISSUER_URL`, `JWT_AUDIENCE` are set (optional, defaults used if not).

2.  **Run the script:**
    ```bash
    node scripts/generate-local-token.js [userId] [roles] [handle] [email] [expiresIn]
    ```
    - Arguments are optional and default to values similar to the `ADMIN_TOKEN`.
    - `roles`: Comma-separated list (no spaces around commas), e.g., `administrator,Topcoder\ User`
    - `expiresIn`: Time string like `1h`, `8h`, `1d`.

3.  **Examples:**
    ```bash
    # Generate default admin token (expires in 8h)
    node scripts/generate-local-token.js

    # Generate token for a regular user (ID 12345, handle 'testuser')
    node scripts/generate-local-token.js 12345 "Topcoder User" testuser test@example.com

    # Generate admin token expiring in 1 hour
    node scripts/generate-local-token.js 8547899 administrator "TonyJ" "tjefths+fix@topcoder.com" 1h
    ```

4.  **Use the Output:** Copy the generated token and use it in the `Authorization: Bearer <token>` header of your API requests (e.g., in Postman).

## Testing

```bash
# unit tests
pnpm run test

# Run Postman collection via Newman (requires app running)
pnpm run test:postman

# e2e tests (currently placeholder/not fully configured)
# pnpm run test:e2e

# test coverage
pnpm run test:cov
```

