## Topcoder Identity Service: updating Authorization, Group, User Resources with TypeScript and Postgres 

This zip contains submission for challenge `Topcoder Identity Service: updating User Resources with TypeScript and Postgres`

## Verification

- Please follow the `Readme.md` to setup databases and start the application. 
- Please see there is a new postman collection as `users.postman_collection.json`. Refer to relevant section in `Readme.md`

Please use correct variables after copying `.env.example`

```
AUTH_SECRET="test"
AUTH0_CLIENT_SECRET="ldzqVaVEbqhwjM5KtZ79sG8djZpAVK8Z7qieVcC3vRjI4NirgcinKSBpPwk6mYYP"        # Client Secret of M2M App
DICEAUTH_DICE_API_URL="https://console-api-uat.diceid.com/v1"
DICEAUTH_DICE_API_KEY="wGu5zRfmgJ8zPQWVLO2jb7820kicVgr221Qteyua"
DICEAUTH_ORG_ID="4f541723-f581-44de-b61c-5f83e8b8ef1e"
DICEAUTH_USER_ID="a5e7e72a-fa5e-4acf-9eca-741d1443279b"
DICEAUTH_TC_API_KEY="iQEErpTqL7ZiXqS2yU03DAsLx2owdR8igE9h9bUymLjHe86hh9eSvOLEXwNmwY8O5uUOtfrDHIWGuYv2Al8F2cvnJpVnQ6yU1PiNV8hEkEpxv3z548UFIpqWudN84GE8"
DICEAUTH_SCHEMA_NAME="Topcoder"
DICEAUTH_SCHEMA_VERSION="1.4"
DICEAUTH_OTP_DURATION="10"
SLACK_BOT_KEY="xoxb-3858018789-4313088279844-TtviiFrGQlvEUuwhMSr5gaE3"
SLACK_CHANNEL_ID="C04ENKCU4TZ"
JWT_SECRET="just-a-random-string"
```

Change this to any random string for local, and use actual key in dev/prod environments

```
# Legacy Blowfish Encryption Key (Base64 Encoded - !!! REPLACE WITH ACTUAL KEY FROM OLD SYSTEM !!!)
# Used for compatibility with the old password encoding scheme.
LEGACY_BLOWFISH_KEY=!!!_REPLACE_WITH_BASE64_ENCODED_KEY_!!!
```
Here is an example

```
LEGACY_BLOWFISH_KEY=dGhpc2lzRGVmYXVmZlZhbHVl
```
`.env.example has only sample values`.

## Notes

The document `resource_migration.md` explains the migration approach for each endpoint.

**Important**: User endpoints cannot be fully automated as it requires tokens and a speific order for testing reactivation flows etc.. via postman. Please use the video `doc/users-endpoint.mp4` for a step-by-step guide on how to test all APIs. Steps needs to be followed to be able to
test all endpoints. (you can play at 1.5x, the postman UI is a bit slow)

**Event Notifications**: There are some open points about notifications and email templates at the moment this submission sent which can be seen in the forum. Please be aware of them, but all functionality works.

## Addressed Issues

This section details how the issues fixed for given excel list:

1.  **Potential Race Condition in `role.service.ts` (update method, Line 146):**
    *   **Status: FIXED.**
    *   **Details:** The `update` method in `src/api/role/role.service.ts` now utilizes `this.prismaAuth.$transaction`. This ensures that checking for duplicate role names and the actual update operation are performed atomically, preventing race conditions.

2.  **Error Handling in Role Assignment (`role.service.ts` Line 220 - `assignRoleToSubject`):**
    *   **Status: FIXED.**
    *   **Details:** Previously, when a duplicate role assignment was attempted (Prisma error P2002), the error was silently ignored. The `assignRoleToSubject` method in `src/api/role/role.service.ts` has been updated to explicitly catch the `P2002` error and throw a `ConflictException` with the message "Role {roleId} is already assigned to subject {subjectId}." This provides clear feedback to the client.

3.  **Missing Input Validation:**
    *   **`roleName` length validation in `createRoleDto` and `updateRoleDto`:**
        *   **Status: ADDRESSED.**
        *   **Details:** The `RoleParamDto` (used within `CreateRoleBodyDto` and `UpdateRoleBodyDto` in `src/dto/role/role.dto.ts`) includes `@MinLength(3)` and `@MaxLength(45)` decorators for the `roleName` field, ensuring its length is validated.
    *   **Validation for `subjectId` and `roleId` being positive numbers:**
        *   **Status: ADDRESSED.**
        *   **Details:** In `src/api/role/role.controller.ts`, the role assignment routes (`assignRoleToSubject`, `deassignRoleFromSubject`, `checkSubjectHasRole`) now include explicit checks to ensure that `roleId` and `subjectId` (when parsed from the query filter) are positive numbers (e.g., `if (roleId <= 0) { throw new BadRequestException(...); }`).
    *   **Validation for `subjectType` being a valid value:**
        *   **Status: ADDRESSED (Implicitly / Not Applicable for current assignment flow).**
        *   **Details:** For the current role assignment/deassignment/checking flows, `subjectType` is hardcoded to `1` (User) within the `src/api/role/role.service.ts` methods. As the client does not provide `subjectType` for these operations, direct input validation in the controller for this specific flow is not applicable. The database schema and DTOs (like `RoleAssignmentResponseDto`) can enforce `subjectType` if it were to be user-provided in other contexts.

4.  **Postman tests don't test `deassign`:**
    *   **Status: ADDRESSED.**
    *   **Details:** The Postman collection `doc/roles api.postman_collection.json` includes a request named `"/roles deassign role (cleanup)"` which specifically tests the `DELETE /roles/{roleId}/deassign?filter=subjectID={subjectId}` endpoint. The test checks for a 200 status code, which is the expected response for a successful deassignment.

5.  **Postman tests don't test `hasrole`:**
    *   **Status: ADDRESSED.**
    *   **Details:** The Postman collection `doc/roles api.postman_collection.json` now includes a request named `"Check Subject Has Role (After Assign)"`. This test is strategically placed after a role assignment and verifies that the `GET /roles/{roleId}/hasrole?filter=subjectID={subjectId}` endpoint correctly returns a 200 status and the expected role ID for an assigned role.

6.  **Postman environment variables:**
    *   **Status: ADDRESSED.**
    *   **Details:** There is now a environment export which has the access token or other global parameters `doc/postman_environment.json`.    