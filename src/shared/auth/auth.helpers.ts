import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { auth, Principal } from 'tc-core-library-js';

/** Match any explicitly accepted, case-sensitive service grant through shared core.
 * @param user Normalized principal from authentication middleware.
 * @param scopes Accepted grants for the operation; empty lists deny service access.
 * @returns Whether a verified service principal has an accepted grant; never throws.
 */
export function hasServiceScopes(user: unknown, scopes: string[]): boolean {
  return scopes.length > 0 && auth.hasScopes(user as Principal, scopes, 'any');
}

/** Authorize a member owner/admin or a service with an explicit accepted grant.
 * @param authUser Normalized authenticated identity.
 * @param allowedScopes Any one of these grants authorizes a service.
 * @param adminRoles Case-insensitive member administrator role names.
 * @param targetUserId Optional member resource owner ID.
 * @returns Nothing when authorized.
 * @throws UnauthorizedException if absent; ForbiddenException if denied.
 */
export function checkAdminOrScope(
  authUser: { kind?: string; userId?: string | number; roles?: string[] } | undefined,
  allowedScopes: string[] = [],
  adminRoles: string[] = ['admin', 'administrator'],
  targetUserId?: string | number | null,
): void {
  if (!authUser) throw new UnauthorizedException('Authentication required.');
  if (authUser.kind === 'service') {
    if (hasServiceScopes(authUser, allowedScopes)) return;
  } else if (authUser.kind === 'user') {
    if (targetUserId != null && String(authUser.userId) === String(targetUserId)) return;
    if (authUser.roles?.some(role => adminRoles.includes(role.toLowerCase()))) return;
  }
  throw new ForbiddenException('Insufficient permissions.');
}
