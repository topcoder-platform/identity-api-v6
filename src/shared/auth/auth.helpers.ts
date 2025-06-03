import { ForbiddenException, UnauthorizedException } from '@nestjs/common';

// Define a simple structure for the authenticated user object expected in the request
// Adjust this based on your actual JWT payload structure
interface AuthenticatedUser {
  userId: string | number; // User ID from token
  roles: string[]; // Roles from token
  scope?: string; // Scopes from token (often space-separated)
  isMachine?: boolean; // Flag if it's an M2M token
}

/**
 * Checks if the authenticated user has the required permissions.
 *
 * Checks performed:
 * 1. User must be authenticated.
 * 2. If targetUserId is provided, checks if the user matches the target OR has admin role/scope.
 * 3. If targetUserId is null/undefined, checks if the user has admin role/scope.
 *
 * @param authUser The authenticated user object from the request (e.g., req.user).
 * @param allowedScopes Array of scopes that grant permission (for machine tokens).
 * @param adminRoles Array of role names considered admin.
 * @param targetUserId Optional ID of the resource being accessed (if checking self vs. admin).
 */
export function checkAdminOrScope(
  authUser: AuthenticatedUser | undefined,
  allowedScopes: string[] = [],
  adminRoles: string[] = ['admin', 'administrator'], // Example admin roles
  targetUserId?: string | number | null,
): void {
  if (!authUser) {
    throw new UnauthorizedException('Authentication required.');
  }

  const userIdNum =
    typeof authUser.userId === 'string'
      ? parseInt(authUser.userId, 10)
      : authUser.userId;
  const targetUserIdNum = targetUserId
    ? typeof targetUserId === 'string'
      ? parseInt(targetUserId, 10)
      : targetUserId
    : null;

  // Check if user is accessing their own resource
  if (targetUserIdNum !== null && userIdNum === targetUserIdNum) {
    return; // User is accessing their own resource
  }

  // Check if user is an admin
  if (
    authUser.roles &&
    authUser.roles.some((role) => adminRoles.includes(role.toLowerCase()))
  ) {
    return; // User is an admin
  }

  // Check if user is a machine client with required scope
  if (authUser.isMachine && authUser.scope) {
    const scopes = authUser.scope.split(' ');
    if (allowedScopes.some((allowedScope) => scopes.includes(allowedScope))) {
      return; // Machine client has required scope
    }
  }

  // If none of the above conditions are met, throw Forbidden
  throw new ForbiddenException('Insufficient permissions.');
}
