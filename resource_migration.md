<!-- # Identity Service Migration Analysis: Authorization, Group, and User Resources

This document outlines the functionalities of the existing Java `AuthorizationResource`, `GroupResource`, and `UserResource` and proposes a corresponding structure using TypeScript, Express (implied framework), and Prisma for the migration. The goal is to replicate the existing functionality while adhering to a controller-service pattern.

## External System & Library Dependencies

This migration relies on several external systems and core libraries. The necessary credentials and configurations must be available in the environment.

*   **Prisma:** The ORM used to interact with the two PostgreSQL database schemas (`common_oltp` and `authorization`). Requires database connection URLs (`COMMON_OLTP_DB_URL`, `AUTHORIZATION_DB_URL`). The `PrismaModule` providing the clients (`PRISMA_CLIENT_COMMON_OLTP`, `PRISMA_CLIENT_AUTHORIZATION`) is already set up. (Status: **Available**)
*   **Redis:** Used for caching various temporary data like OAuth states, JWT refresh tokens, password reset tokens, OTPs, etc. Requires Redis connection details (`REDIS_HOST`, `REDIS_PORT`, potentially `REDIS_PASSWORD`, `REDIS_DB`). The `CacheModule` is already configured. (Status: **Available**)
*   **Event Bus:** The messaging backbone abstraction used for publishing asynchronous events (e.g., user creation, triggers for email notifications). Requires connection details/endpoint for the Event Bus API client and configured topic names (e.g., `EVENT_ORIGINATOR`). The `EventService` wrapping the `EventBusServiceClient` is set up to handle publishing. *Note: Email sending itself is triggered by publishing events (e.g., to `external.action.email`) which are consumed by a separate downstream service.* (Status: **Available**)
*   **Auth0:** The primary Identity Provider (IdP) handling user login/signup via OAuth2/OIDC, M2M token validation, and user profile management. Requires Auth0 Domain, Client ID, Client Secret, M2M Client ID/Secret, and Audience configuration. (Status: **Integration Needed**)
*   **Zendesk (SSO JWT Generation):** Configuration is required (shared secret, ID prefix) to generate a specific JWT for Zendesk Single Sign-On. This service *generates* the JWT, but does not directly call Zendesk APIs. The client uses the generated JWT. (Status: **Configuration Required**)
*   **Slack:** Communication platform used for sending internal system notifications, primarily related to the 2FA integration status. Integration involves **direct API calls** to the Slack `chat.postMessage` endpoint using a Bot Token. Requires a Slack Bot Token and Channel ID. (Status: **Integration Needed**)
*   **`jsonwebtoken`:** A library needed for *generating* various JWTs (internal session tokens, reset tokens, activation resend tokens, one-time tokens). Must be added as a dependency. (Status: **Library Needed**)
*   **`bcrypt`:** A library needed for securely hashing user passwords and comparing hashes during authentication. Must be added as a dependency. (Status: **Library Needed**)


## 1. UserResource Analysis (`/users`)

This is a large resource covering user lifecycle, authentication aspects, profile management, validation, 2FA, and integrations.

**Existing Endpoints & Functionality (Highlights):**

*   **Core User:**
    *   `GET /`: List/search users (`UserDAO`). Requires Admin/`read` scope.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`
            *   `Prisma Models`: `common_oltp.user` (Read).
            *   `Core Logic`:
                1.  Check permissions: Requires Admin/`read` scope (middleware).
                2.  Extract query parameters for filtering (e.g., `handle`, `email`, `status`) and pagination (e.g., `page`, `perPage`).
                3.  Build a Prisma `where` clause based on provided filters (use `contains` or `startsWith` for strings, exact match for status).
                4.  Perform `findMany` query on `user` table with `where` clause, `skip`, and `take` for pagination. Potentially include related data like primary email, roles if needed.
                5.  Return the list of users.
            *   `Validations`: Admin/`read` scope check (middleware).
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `GET /{resourceId}`: Get user details (`UserDAO`). Requires self or Admin/`read` scope. Includes profile population.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`, `UserProfileService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.user_profile_xref` (Read), `common_oltp.social_user_profile` (Read), `common_oltp.email` (Read), potentially `authorization.Role` via `authorization.RoleAssignment`.
            *   `Core Logic`:
                1.  Extract `resourceId` (internal user ID) from path.
                2.  Check permissions: Allow if `AuthUser.userId == resourceId` or user has Admin/`read` scope. Otherwise, forbid.
                3.  Query `user` table using `findUnique` with `resourceId`.
                4.  If user not found, throw 404.
                5.  Query related data using Prisma includes or separate queries:
                    *   Emails (`email` table where `user_id = resourceId`). Find primary email.
                    *   Social profiles (`social_user_profile` via `user_profile_xref`).
                    *   Roles (`authorization.Role` via `authorization.RoleAssignment`).
                    *   Other profile details (potentially from `user` or related tables).
                6.  Combine data into a single user object.
                7.  Return the user details.
            *   `Validations`: Permission check (self or Admin).
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `POST /`: Register new user (`UserDAO`, `RoleDAO`). Public. Handles validation, activation email trigger (Event Bus event), default role assignment, event publishing (`user.created` via Event Bus).
        *   **Dependencies:** Prisma(common_oltp), Prisma(authorization), `bcrypt`, Event Bus, Redis. (Status: Prisma, Event Bus, Redis Available; bcrypt Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`, `AuthFlowService`, `ValidationService`, `RoleService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Create), `common_oltp.credential` (Create), `common_oltp.email` (Create), `authorization.Role` (Read), `authorization.RoleAssignment` (Create).
            *   `Core Logic`:
                1.  Receive registration data (handle, email, password, firstName, lastName, country) from request body.
                2.  Validate input: Check for required fields, handle format/length (using `ValidationService`), email format, password strength.
                3.  Check for duplicate handle using `ValidationService` (`/validateHandle` logic).
                4.  Check for duplicate email using `ValidationService` (`/validateEmail` logic).
                5.  Hash the password using `bcrypt`.
                6.  Create the `user` record (`prisma.user.create`).
                7.  Create the `credential` record (`prisma.credential.create`) linked to the user, storing the hashed password.
                8.  Create the `email` record (`prisma.email.create`) linked to the user, mark as primary, initially not verified.
                9.  Generate activation OTP (e.g., 6 digits).
                10. Store OTP in Redis associated with the user ID/email with an expiry (e.g., 24 hours).
                11. Assign default "User" role: Find default Role ID (`authorization.Role`), create `authorization.RoleAssignment` linking user and role.
                12. Publish `user.created` event to Event Bus (`NotificationService`).
                13. Publish activation email request event to Event Bus (`NotificationService`, includes user details and OTP).
                14. Return the created user object (excluding sensitive info like password/OTP).
            *   `Validations`: Input validation, Duplicate handle/email checks.
            *   `External Calls`: Event Bus (`user.created`, email activation trigger).
            *   `Cache`: Write activation OTP to Redis.
            *   `Cookies`: None.
    *   `PATCH /{resourceId}`: Update basic user info (name, password *with current password*) (`UserDAO`). Requires self or Admin/`update` scope. Publishes `user.updated` (Event Bus event).
        *   **Dependencies:** Prisma(common_oltp), `bcrypt`, Event Bus. (Requires auth middleware). (Status: Prisma, Event Bus Available; bcrypt Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`, `AuthFlowService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read, Update), `common_oltp.credential` (Read, Update).
            *   `Core Logic`:
                1.  Extract `resourceId` from path.
                2.  Check permissions: Allow if `AuthUser.userId == resourceId` or user has Admin/`update` scope. Otherwise, forbid.
                3.  Receive data to update (firstName, lastName, currentPassword, newPassword, etc.) from body.
                4.  Find the user by `resourceId` (`findUnique`). If not found, throw 404.
                5.  If `newPassword` is provided:
                    *   Requires `currentPassword`.
                    *   Find the user's credential (`prisma.credential.findUnique`).
                    *   Verify `currentPassword` against the stored hash using `bcrypt.compare`. If mismatch, throw error.
                    *   Hash `newPassword` using `bcrypt`.
                    *   Update the `credential` record with the new hash.
                6.  Update `user` record with other provided fields (firstName, lastName, etc.) using `prisma.user.update()`.
                7.  Publish `user.updated` event to Event Bus (`NotificationService`).
                8.  Return the updated user object.
            *   `Validations`: Permission check (self or Admin), User existence, `currentPassword` validation (if changing password).
            *   `External Calls`: Event Bus (`user.updated`).
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `DELETE /{resourceId}`: Not implemented.
        *   **Dependencies:** None. (Status: N/A)
        *   **Implementation Details:** N/A.
*   **SSO Logins:** CRUD and listing via `/users/{userId}/SSOUserLogin(s)` (`UserDAO` -> `SSOUserDAO`). Requires Admin scopes.
    *   `POST /{userId}/SSOUserLogin`: Add SSO login info.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserProfileService`
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.sso_user_login` (Create).
            *   `Core Logic`:
                1.  Extract `userId` from path.
                2.  Check permissions: Requires Admin scope.
                3.  Receive SSO data (provider, identifier) from body.
                4.  Validate input.
                5.  Check if user `userId` exists. If not, throw 404.
                6.  Check if this specific SSO login (provider + identifier) already exists. If yes, throw conflict.
                7.  Create `sso_user_login` record linked to `userId`.
                8.  Return created record.
            *   `Validations`: Admin scope, User existence, Duplicate SSO login check.
    *   `PUT /{userId}/SSOUserLogin`: Update SSO login info.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserProfileService`
            *   `Prisma Models`: `common_oltp.sso_user_login` (Read, Update).
            *   `Core Logic`:
                1.  Extract `userId` from path.
                2.  Check permissions: Requires Admin scope.
                3.  Receive SSO data (provider, identifier, ssoUserId from path/body) from body/path.
                4.  Validate input.
                5.  Find existing `sso_user_login` record by its ID (`ssoUserId`). If not found, throw 404.
                6.  Verify the record belongs to the correct `userId`.
                7.  Update the record with new provider/identifier.
                8.  Return updated record.
            *   `Validations`: Admin scope, SSO login existence, User ID match.
    *   `DELETE /{userId}/SSOUserLogin`: Delete SSO login info.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserProfileService`
            *   `Prisma Models`: `common_oltp.sso_user_login` (Read, Delete).
            *   `Core Logic`:
                1.  Extract `userId` from path.
                2.  Check permissions: Requires Admin scope.
                3.  Receive SSO data (`ssoUserId`) from path/body.
                4.  Validate input.
                5.  Find existing `sso_user_login` record by its ID (`ssoUserId`). If not found, throw 404.
                6.  Verify the record belongs to the correct `userId`.
                7.  Delete the record.
                8.  Return success.
            *   `Validations`: Admin scope, SSO login existence, User ID match.
    *   `GET /{userId}/SSOUserLogins`: List SSO logins for a user.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserProfileService`
            *   `Prisma Models`: `common_oltp.sso_user_login` (Read).
            *   `Core Logic`:
                1.  Extract `userId` from path.
                2.  Check permissions: Requires Admin scope.
                3.  Query `sso_user_login` table using `findMany` where `user_id = userId`.
                4.  Return list of records.
            *   `Validations`: Admin scope.
*   **Authentication/Session:**
    *   `POST /login` (Form): User/pass authentication (`UserDAO`). Returns user+roles. Used by Auth0 custom DB script.
        *   **Dependencies:** Prisma(common_oltp), Prisma(authorization), `bcrypt`. (Status: Prisma Available; bcrypt Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `AuthFlowService`, `UserService`, `RoleService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.credential` (Read), `common_oltp.email` (Read), `authorization.Role` (Read), `authorization.RoleAssignment` (Read).
            *   `Core Logic`:
                1.  Receive username (handle or email) and password from form body.
                2.  Find user by handle or primary email (`prisma.user.findUnique` or `findFirst`). If not found, return auth failure.
                3.  Check user status (e.g., must be 'ACTIVE'). If not active, return auth failure.
                4.  Find the user's credential (`prisma.credential.findUnique`). If not found, return auth failure.
                5.  Verify provided password against the stored hash using `bcrypt.compare`. If mismatch, return auth failure.
                6.  Retrieve user roles (`authorization.Role` via `authorization.RoleAssignment`).
                7.  Retrieve primary email (`common_oltp.email`).
                8.  Construct response object containing user details (ID, handle, name, status), primary email, roles, and potentially 2FA status.
                9.  Return the response (expected by Auth0 script).
            *   `Validations`: User existence, User status, Password verification.
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `POST /roles` (Form): Get user+roles by email/handle (`UserDAO`, `RoleDAO`). Used by Auth0 custom DB script (likely Rules).
        *   **Dependencies:** Prisma(common_oltp), Prisma(authorization). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`, `RoleService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `authorization.Role` (Read), `authorization.RoleAssignment` (Read).
            *   `Core Logic`:
                1.  Receive username (handle or email) from form body.
                2.  Find user by handle or primary email. If not found, return error.
                3.  Check user status (must be 'ACTIVE'). If not active, return error.
                4.  Retrieve user roles (`authorization.Role` via `authorization.RoleAssignment`).
                5.  Retrieve 2FA status from `user` record.
                6.  Retrieve activation status (check if `status` is 'ACTIVE').
                7.  Construct response object containing user ID, roles, 2FA status (`mfaEnabled`), activation status (`emailVerified`).
                8.  Return the response (expected by Auth0 Rule).
            *   `Validations`: User existence, User status.
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
*   **Password/Activation:**
    *   `POST /changePassword` (Form): Update password via email (`UserDAO`). Used by Auth0 custom DB script (Action).
        *   **Dependencies:** Prisma(common_oltp), `bcrypt`, Auth0 (potentially, if validating caller). (Status: Prisma Available; bcrypt Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `AuthFlowService`, `UserService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.credential` (Read, Update), `common_oltp.email` (Read).
            *   `Core Logic`:
                1.  Receive `email` and `newPassword` from form body (expected call from Auth0 Action).
                2.  *Optional Auth Check: Validate if the request truly comes from Auth0 (e.g., shared secret, IP check - needs confirmation if Java code did this).*
                3.  Find user by primary `email`. If not found, return error.
                4.  Check user status (must be 'ACTIVE'). If not, return error.
                5.  Find user's credential. If not found, return error.
                6.  Hash `newPassword` using `bcrypt`.
                7.  Update the `credential` record with the new hash.
                8.  Return success response (expected by Auth0 Action).
            *   `Validations`: User existence (by email), User status. (Potentially caller validation).
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `PUT /resetPassword`: Reset password using token (`UserDAO`, `CacheService`). Public.
        *   **Dependencies:** Redis, Prisma(common_oltp), `bcrypt`. (Status: Redis, Prisma Available; bcrypt Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `AuthFlowService`, `UserService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.credential` (Read, Update).
            *   `Core Logic`:
                1.  Receive `token` (password reset token) and `newPassword` from request body.
                2.  Validate `token` format/presence and `newPassword` strength.
                3.  Attempt to retrieve associated user ID from Redis using the `token` as the key.
                4.  If token not found in Redis or expired, throw error (invalid/expired token).
                5.  Delete the token from Redis immediately to prevent reuse.
                6.  Find the user by the retrieved ID. If not found (unlikely), throw error.
                7.  Find the user's credential. If not found, throw error.
                8.  Hash `newPassword` using `bcrypt`.
                9.  Update the `credential` record with the new hash.
                10. Return success response.
            *   `Validations`: Token validity (Redis lookup), New password strength.
            *   `External Calls`: None.
            *   `Cache`: Read/Delete password reset token from Redis.
            *   `Cookies`: None.
    *   `GET /resetToken`: Initiate password reset, send email trigger (Event Bus event). Public.
        *   `Status:` Swagger: ✅ (`GET /users/resetToken`) | Postman: ❌
        *   **Dependencies:** Prisma(common_oltp), Redis, Event Bus. (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `AuthFlowService`, `UserService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.email` (Read).
            *   `Core Logic`:
                1.  Receive `email` query parameter.
                2.  Validate email format.
                3.  Find user by primary `email`. If not found, *return success* (to avoid leaking user existence).
                4.  Generate a secure, unique password reset token (e.g., UUID or crypto random bytes).
                5.  Store `token -> userId` mapping in Redis with an expiry (e.g., 1 hour).
                6.  Publish password reset email request event to Event Bus (`NotificationService`, includes user details and reset token).
                7.  Return success response.
            *   `Validations`: Email format.
            *   `External Calls`: Event Bus (password reset email trigger).
            *   `Cache`: Write password reset token to Redis.
            *   `Cookies`: None.
    *   `PUT /activate`: Activate user with OTP (`UserDAO`, `RoleDAO`, Email/User events via Event Bus). Public.
        *   **Dependencies:** Redis, Prisma(common_oltp), Prisma(authorization), Event Bus. (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `AuthFlowService`, `UserService`, `RoleService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read, Update), `common_oltp.email` (Read, Update), `authorization.Role` (Read), `authorization.RoleAssignment` (Read).
            *   `Core Logic`:
                1.  Receive `username` (email or handle) and `otp` from request body.
                2.  Validate inputs.
                3.  Find user by email or handle. If not found, throw error.
                4.  Check user status. If already 'ACTIVE', return success or specific message.
                5.  Retrieve the expected activation OTP from Redis using a key derived from user ID/email.
                6.  If OTP not found in Redis (expired) or doesn't match provided `otp`, throw error (invalid/expired OTP).
                7.  Delete the OTP from Redis.
                8.  Update user status to 'ACTIVE' (`prisma.user.update`).
                9.  Find the user's primary email record and update its status to verified (`prisma.email.update`).
                10. *Optional: Assign additional roles based on activation if needed.*
                11. Publish `user.activated` event to Event Bus (`NotificationService`).
                12. Publish welcome email request event to Event Bus (`NotificationService`).
                13. Return success response.
            *   `Validations`: User existence, User status check, OTP validation (Redis lookup).
            *   `External Calls`: Event Bus (`user.activated`, welcome email trigger).
            *   `Cache`: Read/Delete activation OTP from Redis.
            *   `Cookies`: None.
    *   `POST /resendActivationEmail`: Resend activation OTP using token (`UserDAO`, Email event via Event Bus). Public.
        *   `Status:` Swagger: ❌ | Postman: ❌
        *   **Dependencies:** Redis, Prisma(common_oltp), Event Bus, `jsonwebtoken`. (Status: Redis, Prisma, Event Bus Available; jsonwebtoken Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `AuthFlowService`, `UserService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.email` (Read).
            *   `Core Logic`:
                1.  Receive `token` (short-lived JWT containing user identifier) from request body.
                2.  Validate and decode the `token` using `jsonwebtoken.verify` and internal secret. Extract user identifier (e.g., email).
                3.  If token invalid/expired, throw error.
                4.  Find user by identifier (email) from token payload. If not found, throw error.
                5.  Check user status. If already 'ACTIVE', return specific message (e.g., "Account already activated").
                6.  Generate a *new* activation OTP.
                7.  Store the new OTP in Redis with expiry.
                8.  Publish activation email request event to Event Bus (`NotificationService`, includes user details and *new* OTP).
                9.  Return success response.
            *   `Validations`: Token validity (JWT verification), User existence, User status check.
            *   `External Calls`: Event Bus (activation email trigger).
            *   `Cache`: Write *new* activation OTP to Redis.
            *   `Cookies`: None.
*   **Profile Updates:**
    *   `PATCH /{resourceId}/handle`: Update handle (`UserDAO`). Requires Admin/`update` scope. Publishes `user.updated` (Event Bus event).
        *   **Dependencies:** Prisma(common_oltp), Event Bus. (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`, `ValidationService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read, Update).
            *   `Core Logic`:
                1.  Extract `resourceId` from path.
                2.  Check permissions: Requires Admin/`update` scope.
                3.  Receive new `handle` from request body.
                4.  Validate handle format/length.
                5.  Check if user `resourceId` exists. If not, throw 404.
                6.  Check if the *new* handle is already taken by another user (`ValidationService` logic). If yes, throw conflict error.
                7.  Update the user record (`prisma.user.update`) with the new handle.
                8.  Publish `user.updated` event to Event Bus (`NotificationService`).
                9.  Return success response.
            *   `Validations`: Admin scope, User existence, Handle format, Duplicate handle check.
            *   `External Calls`: Event Bus (`user.updated`).
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `PATCH /{resourceId}/email`: Update primary email (`UserDAO`). Requires Admin/`update` scope. Publishes `user.updated` (Event Bus event). Sends activation OTP trigger (Event Bus event).
        *   **Dependencies:** Prisma(common_oltp), Event Bus, Redis. (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`, `ValidationService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.email` (Read, Update, Create).
            *   `Core Logic`:
                1.  Extract `resourceId` from path.
                2.  Check permissions: Requires Admin/`update` scope.
                3.  Receive new `email` from request body.
                4.  Validate email format.
                5.  Check if user `resourceId` exists. If not, throw 404.
                6.  Check if the *new* email is already associated with another user (`ValidationService` logic). If yes, throw conflict error.
                7.  Find the current primary email record for the user.
                8.  Mark the current primary email as non-primary (`prisma.email.update`).
                9.  Check if an email record for the *new* email already exists for this user (if they previously used it). If yes, update it to primary and verified=false. If no, create a new email record (`prisma.email.create`) linked to the user, mark as primary, verified=false.
                10. Generate email activation OTP.
                11. Store OTP in Redis associated with user ID/new email.
                12. Publish `user.updated` event to Event Bus (`NotificationService`).
                13. Publish email activation request event to Event Bus (`NotificationService`, for the *new* email, includes OTP).
                14. Return success response.
            *   `Validations`: Admin scope, User existence, Email format, Duplicate email check.
            *   `External Calls`: Event Bus (`user.updated`, email activation trigger).
            *   `Cache`: Write email activation OTP to Redis.
            *   `Cookies`: None.
    *   `POST /{resourceId}/email/{email}`: Update email via one-time token (`UserDAO`, `CacheService`). Requires Bearer token. Publishes `user.updated` (Event Bus event).
        *   **Dependencies:** Redis, Prisma(common_oltp), Event Bus. (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.email` (Read, Update, Create).
            *   `Core Logic`:
                1.  Extract `resourceId` and `email` (new email) from path.
                2.  Check permissions: Requires Bearer token for `resourceId` (self).
                3.  Receive `oneTimeToken` from request body.
                4.  Validate `oneTimeToken` by looking it up in Redis (key should be the token itself). Value should be the expected `resourceId`. If mismatch or not found/expired, throw error.
                5.  Delete token from Redis.
                6.  Find the user `resourceId`. If not found, throw 404.
                7.  Find current primary email, mark as non-primary.
                8.  Find/Create record for the new `email`, mark as primary and verified=true (since token verified ownership).
                9.  Publish `user.updated` event to Event Bus (`NotificationService`).
                10. Return success response.
            *   `Validations`: Bearer token auth (self), One-time token validation (Redis).
            *   `External Calls`: Event Bus (`user.updated`).
            *   `Cache`: Read/Delete one-time email update token from Redis.
            *   `Cookies`: None.
    *   `POST /{resourceId}/profiles`: Add social profile (`UserDAO`, `Auth0Client`). Requires Admin/`create` scope.
        *   **Dependencies:** Prisma(common_oltp), Auth0 (potentially). (Requires auth middleware). (Status: Prisma Available; Auth0 Integration Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `UserProfileService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.social_user_profile` (Create), `common_oltp.user_profile_xref` (Create).
            *   `Core Logic`:
                1.  Extract `resourceId` from path.
                2.  Check permissions: Requires Admin/`create` scope.
                3.  Receive social profile data (provider, socialUserId, name, email) from body.
                4.  Validate input.
                5.  Check if user `resourceId` exists. If not, throw 404.
                6.  Check if a social profile with this provider+socialUserId already exists. If yes, throw conflict.
                7.  Create `social_user_profile` record.
                8.  Create `user_profile_xref` linking the user (`resourceId`) and the new social profile.
                9.  *Auth0 Interaction: Check if Java code also linked this in Auth0 user metadata via Management API. If so, replicate that call.* (Auth0 API Call)
                10. Return created profile.
            *   `Validations`: Admin scope, User existence, Duplicate social profile check.
            *   `External Calls`: Auth0 Management API (potentially, for metadata linking).
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `DELETE /{resourceId}/profiles/{provider}`: Delete social profile (`UserDAO`). Requires Admin/`delete` scope.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserProfileService`.
            *   `Prisma Models`: `common_oltp.social_user_profile` (Read, Delete), `common_oltp.user_profile_xref` (Read, Delete).
            *   `Core Logic`:
                1.  Extract `resourceId` and `provider` from path.
                2.  Check permissions: Requires Admin/`delete` scope.
                3.  Find the `user_profile_xref` record linking `resourceId` and the `social_user_profile` where `provider` matches. If not found, throw 404.
                4.  Get the `socialUserProfileId` from the xref.
                5.  Delete the `user_profile_xref` record.
                6.  Delete the `social_user_profile` record using its ID.
                7.  *Auth0 Interaction: Check if Java code also unlinked this from Auth0 user metadata. If so, replicate.* (Auth0 API Call)
                8.  Return success.
            *   `Validations`: Admin scope, Profile existence check.
            *   `External Calls`: Auth0 Management API (potentially, for metadata unlinking).
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `PATCH /{resourceId}/status`: Update user status (`UserDAO`). Requires Admin/`update` scope. Publishes events, sends welcome email trigger (Event Bus event).
        *   **Dependencies:** Prisma(common_oltp), Event Bus. (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read, Update).
            *   `Core Logic`:
                1.  Extract `resourceId` from path.
                2.  Check permissions: Requires Admin/`update` scope.
                3.  Receive new `status` from request body.
                4.  Validate `status` value (must be one of the allowed statuses).
                5.  Find user by `resourceId`. If not found, throw 404.
                6.  Get the old status.
                7.  Update the user record (`prisma.user.update`) with the new status.
                8.  Publish `user.updated` event (or more specific `user.status.updated`) to Event Bus.
                9.  If status changed *to* 'ACTIVE' *from* a non-active state, publish welcome email request event to Event Bus.
                10. Return success.
            *   `Validations`: Admin scope, User existence, Valid status value.
            *   `External Calls`: Event Bus (`user.updated`, potentially welcome email trigger).
            *   `Cache`: None.
            *   `Cookies`: None.
*   **Roles:**
    *   `POST /updatePrimaryRole`: Change primary role (`RoleDAO`). Requires self.
        *   **Dependencies:** Prisma(authorization). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `RoleService`.
            *   `Prisma Models`: `authorization.Role` (Read), `authorization.RoleAssignment` (Read, Update).
            *   `Core Logic`:
                1.  Get authenticated user ID (`AuthUser.userId`).
                2.  Receive `primaryRoleId` from request body.
                3.  Validate `primaryRoleId`.
                4.  Check if a role with `primaryRoleId` exists (`authorization.Role`). If not, throw error.
                5.  Find all `RoleAssignment` records for the user (`userId`).
                6.  Check if the user is actually assigned the `primaryRoleId`. If not, throw error (cannot set primary role if not assigned).
                7.  Iterate through assignments: Mark the assignment matching `primaryRoleId` as `isPrimary=true`. Mark all other assignments for this user as `isPrimary=false` (`prisma.roleAssignment.updateMany`).
                8.  Return success.
            *   `Validations`: Bearer token auth (self), Role existence, User role assignment check.
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
*   **Validation:**
    *   `GET /validateHandle`: Check if handle exists/is valid.
        *   `Status:` Swagger: ✅ (`GET /users/validateHandle`) | Postman: ❌
        *   **Dependencies:** Prisma(common_oltp). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `ValidationService`.
            *   `Prisma Models`: `common_oltp.user` (Read).
            *   `Core Logic`:
                1.  Receive `value` (handle) query parameter.
                2.  Validate handle format/length/reserved words.
                3.  Query `user` table using `findUnique` on `handle_lower` (assuming case-insensitive check).
                4.  If found, return { valid: false, message: "Handle taken" }.
                5.  If not found and passes validation, return { valid: true }.
            *   `Validations`: Handle format/length/reserved words, Uniqueness check.
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `GET /validateEmail`: Check if email exists/is valid.
        *   **Dependencies:** Prisma(common_oltp). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `ValidationService`.
            *   `Prisma Models`: `common_oltp.email` (Read).
            *   `Core Logic`:
                1.  Receive `value` (email) query parameter.
                2.  Validate email format.
                3.  Query `email` table using `findFirst` where `email_address` matches (case-insensitive).
                4.  If found, return { valid: false, message: "Email taken" }.
                5.  If not found and passes validation, return { valid: true }.
            *   `Validations`: Email format, Uniqueness check.
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `GET /validateSocial`: Check if social profile exists.
        *   **Dependencies:** Prisma(common_oltp). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `ValidationService`, `UserProfileService`.
            *   `Prisma Models`: `common_oltp.social_user_profile` (Read).
            *   `Core Logic`:
                1.  Receive `provider` and `socialUserId` query parameters.
                2.  Validate inputs.
                3.  Query `social_user_profile` table using `findFirst` where `provider` and `social_user_id` match.
                4.  If found, return { valid: false, message: "Social profile already linked" }.
                5.  If not found, return { valid: true }.
            *   `Validations`: Input presence, Uniqueness check.
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.

**Core Logic:**

*   Extensive User/Credential/Profile/Email/SSO/2FA data management (`UserDAO`).
*   Complex validation logic (handle, email, country, profile types, referrals).
*   Password hashing and verification.
*   Role management (`RoleDAO`).
*   OTP generation, storage (DB), verification for activation and 2FA.
*   Token generation/verification (reset, activation resend, one-time tokens) using cache and JWT/secrets.
*   Event publishing via Event Bus (`user.created`, `user.updated`, `user.activated`, email notifications).
*   Email sending orchestration via events (using SendGrid templates).
*   Auth0 integration (fetching IdP tokens).
*   Slack notifications for 2FA events.
*   M2M scope-based authorization (`UserProfilesFactory`).

**Proposed TypeScript Structure:**

Given the complexity, splitting `UserService` is recommended.

*   **Controller:** `UserController` (`src/controllers/user.controller.ts`)
    *   Handles all `/users/...` routes.
    *   Parses requests, performs initial validation.
    *   Delegates to appropriate service methods.
    *   Formats responses.
*   **Service:** `UserService` (`src/services/user.service.ts`)
    *   Core user CRUD operations (find, create basic user, update basic info).
    *   Handles basic validation calls (delegating to `ValidationService`).
    *   Coordinates calls to other specialized services.
    *   Interacts with Prisma Client for `User` table.
*   **Service:** `UserProfileService` (`src/services/userProfile.service.ts`)
    *   Manages social profiles and SSO logins (CRUD, validation).
    *   Interacts with Prisma Client (`UserProfile`, `SSOUserLogin` related tables).
    *   Interacts with `Auth0Service` (if needed for validation/token fetching).
*   **Service:** `AuthFlowService` (`src/services/authFlow.service.ts`)
    *   Handles login (`/login`), password change (`/changePassword`), password reset (`/resetPassword`, `/resetToken`), activation (`/activate`, `/resendActivationEmail`), one-time tokens (`/oneTimeToken`).
    *   Interacts with Prisma Client (`User`, `Credential`, `UserOtp` tables).
    *   Interacts with `CacheService`.
    *   Interacts with `NotificationService` (for emails).
    *   Generates/validates various tokens (reset, resend, OTP, one-time).
*   **Service:** `TwoFactorAuthService` (`src/services/twoFactorAuth.service.ts`)
    *   Manages 2FA settings (`/2fa`), OTP handling (`/sendOtp`, `/resendOtpEmail`, `/checkOtp`).
    *   Interacts with Prisma Client (`User2fa`, `UserOtp` tables).
    *   Interacts with `NotificationService` (for OTP emails, Slack).
*   **Service:** `RoleService` (`src/services/role.service.ts`) - *May already exist from RoleResource migration*
    *   Handles role lookup (`/roles`) and assignment (`/updatePrimaryRole`, default role assignment).
    *   Interacts with Prisma Client (`Role`, `UserRole` tables).
*   **Service:** `ValidationService` (`src/services/validation.service.ts`)
    *   Handles validation logic for handle, email, social profiles (`/validate...` endpoints and internal checks).
    *   Interacts with Prisma Client.
*   **Service:** `NotificationService` (`src/services/notification.service.ts`)
    *   Handles publishing events to Event Bus.
    *   Orchestrates sending emails via SendGrid (using templates).
    *   Sends Slack notifications.
*   **Service:** `CacheService` (`src/services/cache.service.ts`) - *Likely shared*
    *   Wrapper around Redis client for get/put/delete operations with expiry.
*   **Service:** `Auth0Service` (`src/services/auth0.service.ts`) - *Likely shared with AuthService*
    *   Wrapper around Auth0 SDK/API client.

**Dependencies:**

*   Prisma Client
*   Redis client library
*   Event Bus client library (e.g., `kafkajs`)
*   `jsonwebtoken` library
*   Auth0 Node.js SDK
*   SendGrid client library
*   Slack client library
*   Auth module/middleware
*   Configuration for DB, Redis, Event Bus, Auth0, SendGrid, Slack, JWT secrets.

## 4. General Considerations

*   **Shared Utilities:** Create utility functions/modules for common tasks like error handling, request validation schemas, permission checking logic, ID parsing/validation (`TCID`).
*   **Configuration:** Centralize configuration management (environment variables, config files) for database connections, API keys, secrets, domains, template IDs, etc.
*   **Prisma Schema:** Carefully define the Prisma schema to accurately represent the relationships between User, Role, Group, Membership, Profile, Credential, etc., based on the existing DAO interactions. Pay attention to required fields, defaults, and relations.
*   **Data Migration:** Plan the migration of existing user data, ensuring password hashes are compatible or require a reset flow.
*   **Event Bus Topics:** Define clear Event Bus topic names corresponding to the existing `publishUserEvent`, `publishNotificationEvent` calls.
*   **Informix Dependency:** Decide on the strategy for `SecurityGroup`. Either migrate it to Postgres or maintain the Informix connection and DAO (`SecurityGroupService`).

This structure provides a modular approach to migrating the complex functionalities of these resources into a maintainable TypeScript codebase.

*   **2FA:**
    *   `GET /{resourceId}/2fa`: Get 2FA status (`UserDAO`). Requires self or Admin.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `TwoFactorAuthService`, `UserService`.
            *   `Prisma Models`: `common_oltp.user` (Read).
            *   `Core Logic`:
                1.  Extract `resourceId` from path.
                2.  Check permissions: Allow self or Admin/`read` scope.
                3.  Find user by `resourceId`. If not found, throw 404.
                4.  Read the `is_mfa_enabled` (or similar field name) from the user record.
                5.  Return { mfaEnabled: status }.
            *   `Validations`: Permission check (self or Admin).
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `PATCH /{resourceId}/2fa`: Update 2FA status (`UserDAO`). Requires self or Admin.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `TwoFactorAuthService`, `UserService`.
            *   `Prisma Models`: `common_oltp.user` (Read, Update).
            *   `Core Logic`:
                1.  Extract `resourceId` from path.
                2.  Check permissions: Allow self or Admin/`update` scope.
                3.  Receive new `mfaEnabled` status (boolean) from body.
                4.  Find user by `resourceId`. If not found, throw 404.
                5.  Update the `is_mfa_enabled` field on the user record.
                6.  Return success.
            *   `Validations`: Permission check (self or Admin).
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `POST /sendOtp`: Send 2FA OTP (`UserDAO`, Email event via Event Bus). Generates resend token.
        *   **Dependencies:** Prisma(common_oltp), Redis, Event Bus, `jsonwebtoken`. (Requires auth middleware, likely partial 2FA state). (Status: Prisma, Redis, Event Bus Available; jsonwebtoken Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `TwoFactorAuthService`, `UserService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.email` (Read).
            *   `Core Logic`:
                1.  Requires partially authenticated user context (e.g., user ID available after password check but before full login).
                2.  Get user ID from context.
                3.  Find user by ID. If not found, throw error.
                4.  Find user's primary email.
                5.  Generate 2FA OTP (e.g., 6 digits).
                6.  Store OTP in Redis (key includes user ID, expiry e.g., 5 minutes).
                7.  Generate a short-lived JWT "resend token" containing user identifier (e.g., email). Sign with internal secret.
                8.  Publish 2FA OTP email request event to Event Bus (`NotificationService`, includes user details, OTP).
                9.  Return the resend token in the response body.
            *   `Validations`: Requires partially authenticated state.
            *   `External Calls`: Event Bus (2FA OTP email trigger).
            *   `Cache`: Write 2FA OTP to Redis.
            *   `Cookies`: None.
    *   `POST /resendOtpEmail`: Resend 2FA OTP (`UserDAO`, Email event via Event Bus). Requires resend token.
        *   **Dependencies:** Redis, Prisma(common_oltp), Event Bus, `jsonwebtoken`. (Status: Prisma, Redis, Event Bus Available; jsonwebtoken Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `TwoFactorAuthService`, `UserService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.email` (Read).
            *   `Core Logic`:
                1.  Receive `token` (the resend token) from request body.
                2.  Validate and decode the `token` using `jsonwebtoken.verify`. Extract user identifier (email).
                3.  If token invalid/expired, throw error.
                4.  Find user by identifier (email).
                5.  Find user's primary email.
                6.  Generate a *new* 2FA OTP.
                7.  Store the new OTP in Redis with expiry.
                8.  Publish 2FA OTP email request event to Event Bus (`NotificationService`, includes user details, *new* OTP).
                9.  Return success response.
            *   `Validations`: Resend token validity (JWT verification).
            *   `External Calls`: Event Bus (2FA OTP email trigger).
            *   `Cache`: Write *new* 2FA OTP to Redis.
            *   `Cookies`: None.
    *   `POST /checkOtp`: Verify 2FA OTP (`UserDAO`). Completes login.
        *   **Dependencies:** Redis, Prisma(common_oltp), `jsonwebtoken`, Event Bus, Cookies. (Requires partially authenticated state). (Status: Redis, Prisma, Event Bus Available; jsonwebtoken Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `TwoFactorAuthService`, `AuthService`, `UserService`, `NotificationService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.email` (Read), `authorization.Role` (Read), `authorization.RoleAssignment` (Read).
            *   `Core Logic`:
                1.  Requires partially authenticated user context (user ID available).
                2.  Receive `otp` from request body.
                3.  Retrieve expected OTP from Redis using user ID key.
                4.  If OTP not found in Redis or doesn't match provided `otp`, throw error (invalid/expired OTP).
                5.  Delete OTP from Redis.
                6.  *Login Completion:* Now that 2FA is verified, proceed with full login steps (similar to callback logic in `AuthorizationResource`):
                    *   Find user details (ID, handle, email, etc.).
                    *   Find user roles.
                    *   Generate internal JWT (`tcjwt`).
                    *   Generate Zendesk SSO JWT.
                    *   Update `last_login`.
                    *   Publish `user.logged_in` event.
                    *   Generate `tcsso` token.
                    *   Set cookies (`tcjwt`, `v3jwt`?, `tcsso`).
                    *   Store tokens in cache if needed.
                7.  Return success response (e.g., user object or internal JWT).
            *   `Validations`: OTP validation (Redis lookup).
            *   `External Calls`: Event Bus (`user.logged_in`).
            *   `Cache`: Read/Delete 2FA OTP. Write session/token info.
            *   `Cookies`: Set login cookies.
*   **Other:**
    *   `GET /{resourceId}/achievements`: Get achievements (`UserDAO`). Requires Admin/`read` scope.
        *   **Dependencies:** Prisma(common_oltp). (Requires auth middleware). (Status: Available)
        *   **Implementation Details:**
            *   `Service(s)`: `UserService`, `UserProfileService`.
            *   `Prisma Models`: `common_oltp.user_achievement` (Read).
            *   `Core Logic`:
                1.  Extract `resourceId` from path.
                2.  Check permissions: Requires Admin/`read` scope.
                3.  Query `user_achievement` table using `findMany` where `user_id = resourceId`.
                4.  Return the list of achievement records.
            *   `Validations`: Admin scope.
            *   `External Calls`: None.
            *   `Cache`: None.
            *   `Cookies`: None.
    *   `POST /oneTimeToken` (Form): Get short-lived token after user/pass auth (`UserDAO`, `CacheService`). Used for email update flow.
        *   **Dependencies:** Prisma(common_oltp), `bcrypt`, Redis, `jsonwebtoken`. (Status: Prisma, Redis Available; bcrypt, jsonwebtoken Library Needed)
        *   **Implementation Details:**
            *   `Service(s)`: `AuthFlowService`, `UserService`.
            *   `Prisma Models`: `common_oltp.user` (Read), `common_oltp.credential` (Read), `common_oltp.email` (Read).
            *   `Core Logic`:
                1.  Receive `username` (handle or email) and `password` from form body.
                2.  Authenticate user/password (same logic as `POST /login` form endpoint).
                3.  If authentication fails, throw error.
                4.  Generate a secure, unique one-time token (e.g., UUID).
                5.  Store `oneTimeToken -> userId` mapping in Redis with a short expiry (e.g., 5 minutes).
                6.  Return the `oneTimeToken` in the response.
            *   `Validations`: User existence, User status, Password verification.
            *   `External Calls`: None.
            *   `Cache`: Write one-time token to Redis.
            *   `Cookies`: None. -->

# Identity Service Migration Guide

## Java to TypeScript/Express/Prisma

This document outlines how to migrate the existing Java identity service to TypeScript using Express and Prisma.

## Required Dependencies

### Available (Already Set Up)

- **Prisma**: Database access to `common_oltp` and `authorization` schemas
- **Redis**: Caching for tokens, OTPs, sessions
- **Event Bus**: For publishing events (user creation, email triggers)

### Need Integration

- **Auth0**: User authentication and management
- **Slack**: System notifications

### Need Libraries

- `jsonwebtoken`: JWT token generation
- `bcrypt`: Password hashing

## User Management (`/users`)

### Core User Operations

#### List Users - `GET /users`

- **Purpose**: Search and list users
- **Auth**: Admin or `read` scope required
- **Database**: Read from `user` table
- **Logic**: Filter by handle/email/status, paginate results

#### Get User Details - `GET /users/{id}`

- **Purpose**: Get single user with profile data
- **Auth**: Self access or Admin/`read` scope
- **Database**: Read `user`, `email`, `social_user_profile`, roles
- **Logic**: Combine user data with related profiles and permissions

#### Create User - `POST /users`

- **Purpose**: Register new user account
- **Auth**: Public endpoint
- **Database**: Create `user`, `credential`, `email` records
- **Logic**:
  1. Validate input (handle, email, password)
  2. Check for duplicates
  3. Hash password with bcrypt
  4. Create user records
  5. Generate activation OTP
  6. Store OTP in Redis
  7. Assign default role
  8. Send activation email via Event Bus

#### Update User - `PATCH /users/{id}`

- **Purpose**: Update user information
- **Auth**: Self or Admin/`update` scope
- **Database**: Update `user` and `credential` tables
- **Logic**:
  1. Verify permissions
  2. If changing password, verify current password
  3. Hash new password if provided
  4. Update user record
  5. Publish update event

### Authentication Flow

#### Login - `POST /users/login`

- **Purpose**: Authenticate user credentials
- **Auth**: Public (used by Auth0)
- **Database**: Read `user`, `credential`, `email`, roles
- **Logic**:
  1. Find user by handle or email
  2. Verify password with bcrypt
  3. Check user status is active
  4. Return user details and roles

#### Password Reset

- **Request Reset** - `GET /users/resetToken`
  - Generate reset token, store in Redis
  - Send reset email via Event Bus
- **Complete Reset** - `PUT /users/resetPassword`
  - Validate reset token from Redis
  - Hash new password and update

#### Account Activation

- **Activate** - `PUT /users/activate`
  - Validate OTP from Redis
  - Set user status to ACTIVE
  - Mark email as verified
  - Send welcome email
- **Resend Activation** - `POST /users/resendActivationEmail`
  - Decode JWT token
  - Generate new OTP
  - Send new activation email

### Profile Management

#### Handle Update - `PATCH /users/{id}/handle`

- **Auth**: Admin/`update` scope
- **Logic**: Check uniqueness, update handle

#### Email Update - `PATCH /users/{id}/email`

- **Auth**: Admin/`update` scope
- **Logic**:
  1. Validate new email
  2. Create/update email record
  3. Send verification OTP
  4. Generate activation email

#### Social Profiles

- **Add** - `POST /users/{id}/profiles`
- **Delete** - `DELETE /users/{id}/profiles/{provider}`
- **Auth**: Admin scope required

### Two-Factor Authentication

#### 2FA Status

- **Get** - `GET /users/{id}/2fa`
- **Update** - `PATCH /users/{id}/2fa`
- **Auth**: Self or Admin access

#### OTP Flow

- **Send OTP** - `POST /users/sendOtp`
  - Generate 6-digit code
  - Store in Redis with 5-minute expiry
  - Send via email
- **Resend OTP** - `POST /users/resendOtpEmail`
  - Validate resend token
  - Generate new OTP
- **Check OTP** - `POST /users/checkOtp`
  - Validate OTP from Redis
  - Complete login process

### Validation Endpoints

#### Check Availability

- **Handle** - `GET /users/validateHandle`
- **Email** - `GET /users/validateEmail`
- **Social Profile** - `GET /users/validateSocial`

All return `{ valid: boolean, message?: string }`

## Proposed TypeScript Structure

### Controllers

- `UserController` - Handle HTTP requests, validate input, format responses

### Services

- `UserService` - Core user CRUD operations
- `AuthFlowService` - Login, password reset, activation flows
- `UserProfileService` - Social profiles, SSO logins
- `TwoFactorAuthService` - 2FA and OTP management
- `ValidationService` - Handle/email/social validation
- `NotificationService` - Event Bus publishing

### Shared Services

- `RoleService` - Role management (may exist from other migrations)
- `CacheService` - Redis operations
- `Auth0Service` - Auth0 API wrapper

## Implementation Notes

### Security

- All passwords hashed with bcrypt
- OTPs stored in Redis with expiration
- JWT tokens for temporary operations
- Scope-based authorization

### Database

- Use Prisma for all database operations
- Two schemas: `common_oltp` and `authorization`
- Maintain referential integrity

### External Integrations

- Event Bus for async operations (emails, notifications)
- Redis for temporary data (OTPs, tokens, sessions)
- Auth0 for identity management
- Slack for system notifications

### Error Handling

- Return appropriate HTTP status codes
- Don't leak user existence in validation responses
- Log security events appropriately

This structure provides a clean separation of concerns while maintaining all existing functionality.
