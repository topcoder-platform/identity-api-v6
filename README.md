
**TC Identity Service README**
==========================

**Table of Contents**
-----------------

- [**TC Identity Service README**](#tc-identity-service-readme)
  - [**Table of Contents**](#table-of-contents)
  - [**Prerequisites**](#prerequisites)
  - [**Setting up Environment**](#setting-up-environment)
  - [**Deploying Locally**](#deploying-locally)
- [**Verifying through Postman Collections**](#verifying-through-postman-collections)
- [**Environment Configuration**](#environment-configuration)
  - [**Downstream Usage**](#downstream-usage)
  - [**Auth0 Integration**](#auth0-integration)

**Prerequisites**
---------------

* Node.js (Version 22.13.1 recommended)
* pnpm (Install globally using npm)
* PostgreSQL Client (`psql`) (Required for importing database dump)
* Docker (Latest version of Docker Desktop or Docker Engine)

**Setting up Environment**
-------------------------

1. Install Node.js and pnpm:
```bash
nvm install 22.13.1
nvm use 22.13.1
npm install -g pnpm
```
2. Install dependencies:
```bash
pnpm install
```
This command also runs `pnpm run prisma:generate` automatically via the `postinstall` script to generate Prisma clients for both databases.

**Deploying Locally**
---------------------

1. Configure Environment
```bash
cp .env.sample .env
# update `AUTH_SECRET` to `ldzqVaVEbqhwjM5KtZ79sG8djZpAVK8Z7qieVcC3vRjI4NirgcinKSBpPwk6mYYP`
# update `AUTH0_CLIENT_SECRET` to `ldzqVaVEbqhwjM5KtZ79sG8djZpAVK8Z7qieVcC3vRjI4NirgcinKSBpPwk6mYYP`
# update `AUTH0_CLIENT_ID` to `jGIf2pd3f44B1jqvOai30BIKTZanYBfU`
# update `LEGACY_BLOWFISH_KEY` to `dGhpc2lzRGVmYXVmZlZhbHVl`
```
2. Start the Docker containers for the databases and Redis:
```bash
docker-compose up -d
```
3. Setting up Database

Add to migration.sql for initialization:

```
CREATE SEQUENCE IF NOT EXISTS sequence_email_seq
    INCREMENT 1
    START 70100000
    MINVALUE 1
    MAXVALUE 9223372036854775807
    CACHE 1;

CREATE SEQUENCE IF NOT EXISTS sequence_user_seq
    INCREMENT 1
    START 88770000
    MINVALUE 1
    MAXVALUE 9223372036854775807
    CACHE 1;    
```

```bash
# Replace ~/Downloads/dump_all.custom with the actual path to your dump file. (Download it from forum, and extract from zip) - Use password from DB_PASSWORD of .env file
# Ensure DB_HOST, DB_PORT, DB_USERNAME, and COMMON_OLTP_DB_NAME match your .env values.
pg_restore -h ${DB_HOST:-127.0.0.1} -p ${DB_PORT:-5432} -U ${DB_USERNAME:-topcoderuser} \
 -d ${IDENTITY_DB_NAME:-identity} ~/Downloads/dump_all.custom 
# create tables to group database
pnpm run prisma:migrate:group
```
4. Start the application:
```bash
pnpm run start:dev
```
**Verifying through Postman Collections**
--------------------------------------

1. Import the Postman collection file (`doc/identity-api-v6-postman-collection.json`) into Postman.
2. Update the `baseUrl` variable in the Postman collection to point to your local application URL (e.g., `http://localhost:3000/v6`).
3. Run the API requests in the Postman collection one by one, from top to bottom to verify that the application is working correctly.
4. After you run the `users/Authentication/Session Related/Auth0 Change Password` request, locate the OTP in the application logs(something like `New activation OTP **025450** generated and cached for user 40159253 (key: USER_ACTIVATION_OTP:40159253)`), copy it, and replace the OTP in the body of the `users/Authentication/Session Related/Activate User` request.
5. After you run the `users/Profile Updates/Send Otp for check` request, locate the OTP in the application logs(something like `New activation OTP **025450** generated and cached for user 40159253 (key: USER_2FA_OTP:40159253)`), copy it, and replace the OTP in the body of the `users/Profile Updates/Check Otp` request.

 **Environment Configuration**
 ----------------------------

The following table summarizes the environment variables used by the application. Copy `.env.sample` to `.env` and customize these values as needed.

| Variable                   | Description                                                                 | Default Value (`.env.sample`) |
| :------------------------- | :-------------------------------------------------------------------------- | :---------------------------- |
| `NODE_ENV`                 | Application environment (e.g., `development`, `production`)                   | `development`                 |
| `PORT`                     | Port the application listens on                                             | `3000`                        |
|                            | **Database (PostgreSQL - Identity)**                                     |                               |
| `IDENTITY_DB_URL`      | URL of the main PostgreSQL database                                        | `postgresql://postgres:identitypassword@localhost:5432/identity`              |
|                            | **Database (PostgreSQL - Group)**                                   |                               |
| `GROUP_DB_URL`    | URL of the group PostgreSQL database                             | `postgresql://postgres:identitypassword@localhost:5431/group`            |
|                            | **Redis Cache**                                                             |                               |
| `REDIS_HOST`               | Hostname for the Redis cache instance                                       | `127.0.0.1`                   |
| `REDIS_PORT`               | Port for the Redis cache instance                                           | `6380`                        |
|                            | **JWT Validation**                                                          |                               |
| `JWT_VALIDATION_MODE`      | Validation mode: `HS256` (local) or `RS256` (prod/staging)                  | `HS256`                       |
| `AUTH_SECRET`              | Secret key for HS256 token generation/validation (local only). **CHANGE THIS!** | `<<<REPLACE WITH A REAL SECRET KEY>>>` |
| `JWT_ISSUER_URL`           | Expected issuer URL in JWTs                                                 | `https://api.topcoder-dev.com` |
| `JWT_AUDIENCE`             | Expected audience in JWTs                                                   | `www.example.com`             |
| `JWT_JWKS_URI`             | JWKS endpoint URI for RS256 validation (prod/staging only)                  | *(commented out)*             |
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

### Migrating legacy social login data

- Run `npx ts-node scripts/migrate-user-social-login.ts` to copy legacy `user_social_login` rows into `identity.user_social_login`.
- Set `SOURCE_IDENTITY_PG_URL` (legacy) and `IDENTITY_DB_URL` (target) before running; `USER_SOCIAL_LOGIN_BATCH_SIZE` tunes pagination.
- Flags available: `--dry-run` (log only), `--truncate` (clear target before load; ignored during dry-run), and `--insert-missing-only` (skip rows that already exist in the target).
- Ensure `identity.social_login_provider` is migrated first so foreign keys resolve during import.


**Downstream Usage**
--------------------

- This service is consumed by multiple Topcoder apps, as well as Auth0. Below is a quick map of where and how it’s called to help with debugging and local development.

**platform-ui**

- Local dev proxy forwards Identity routes to this service:
  - See `platform-ui/src/config/environments/local.env.ts` (proxies for `/v6/users`, `/v6/roles`, `/v6/user-roles`, `/v6/identityproviders`).
- Admin users and roles management use the following endpoints:
  - Search/list users: `GET /v6/users?fields=...&filter=...&limit=...` — `platform-ui/src/apps/admin/src/lib/services/user.service.ts`.
  - Get user by id: `GET /v6/users/{id}` — `platform-ui/src/apps/admin/src/lib/services/user.service.ts`.
  - Update email: `PATCH /v6/users/{id}/email` — `platform-ui/src/apps/admin/src/lib/services/user.service.ts`.
  - Update status: `PATCH /v6/users/{id}/status?comment=...` — `platform-ui/src/apps/admin/src/lib/services/user.service.ts`.
  - Fetch achievements: `GET /v6/users/{id}/achievements` — `platform-ui/src/apps/admin/src/lib/services/user.service.ts`.
  - Manage SSO user logins: `GET/POST/PUT/DELETE /v6/users/{id}/SSOUserLogin(s)` — `platform-ui/src/apps/admin/src/lib/services/user.service.ts`.
  - Fetch identity providers (SSO): `GET /v6/identityproviders/sso-providers` — `platform-ui/src/apps/admin/src/lib/services/identity-provider.service.ts`.
  - Roles catalog and assignments:
    - List roles: `GET /v6/roles` — `platform-ui/src/apps/admin/src/lib/services/roles.service.ts`.
    - Subject roles: `GET /v6/roles?filter=subjectID={userId}` — `platform-ui/src/apps/admin/src/lib/services/roles.service.ts`.
    - Assign role: `PATCH /v6/user-roles/{userId}` — `platform-ui/src/apps/admin/src/lib/services/roles.service.ts`.
    - Remove role: `DELETE /v6/user-roles/{userId}/{roleId}` — `platform-ui/src/apps/admin/src/lib/services/roles.service.ts`.
    - Manage role members: `GET /v6/roles/{roleId}/subjects[?page&perPage&userId&userHandle&email]` — `platform-ui/src/apps/admin/src/lib/services/roles.service.ts`.
- User password changes from the profile context use: `PATCH /v6/users/{id}` (credential payload) — `platform-ui/src/libs/core/lib/auth/user-functions/user-xhr.store.ts` and `platform-ui/src/libs/core/lib/auth/user-functions/user-endpoint.config.ts`.

**community-app**

- Community App does not call Identity API endpoints directly. It authenticates via the Accounts app/Auth0 and consumes roles embedded in the JWT to gate features.
  - Token acquisition and decoding: `community-app/src/client/index.jsx`.
  - Various parts of the app read roles from the decoded token (e.g., reviewer checks): `community-app/src/shared/containers/ReviewOpportunityDetails.jsx`.

**work-manager**

- Work Manager does not call Identity API endpoints directly. It relies on JWT roles to authorize actions (admin/manager/copilot/read-only checks).
  - Role checks based on decoded token claims: `work-manager/src/util/tc.js`.
  - Token wiring and axios auth header: `work-manager/src/services/axiosWithAuth.js`.

Swagger: when running locally, the Identity API docs are available at `http://localhost:3000/v6/users/api-docs`.


**Auth0 Integration**
---------------------

- Auth0 uses Identity API for critical authentication flows via Actions
  - Validate username/email + password during login: `POST /v6/users/login` (form data).
  - Fetch user profile and roles to embed into tokens: `POST /v6/users/roles` (form data).
  - Registration flow: create users via `POST /v6/users`, then activate with `PUT /v6/users/activate`; resend activation via `POST /v6/users/resendActivationEmail`.

Notes:
- Endpoints above are intentionally callable by Auth0 without a bearer token and are documented in the code (`identity-api-v6/src/api/user/user.controller.ts`).  These endpoints are restricted to only Auth0 IP addresses
- Roles added to JWTs are then consumed by apps like Work Manager and Community App to gate features, as well as all services, to validate user access to specific functionality.
