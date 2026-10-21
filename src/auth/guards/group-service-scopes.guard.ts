import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { hasServiceScopes } from '../../shared/auth/auth.helpers';

/** Apply explicit read/write scope policies to every Group route for service callers.
 * Existing member authorization remains in the controller/service layer.
 */
@Injectable()
export class GroupServiceScopesGuard implements CanActivate {
  /** Inspect the HTTP method and normalized caller; returns true or throws 403.
   * @param context Nest HTTP execution context containing the verified principal.
   * GET/HEAD require a read/write/all grant; mutations require write/all.
   */
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.authUser || request.user;
    if (user?.kind !== 'service') return true;
    const accepted = ['write:groups', 'all:groups'];
    if (['GET', 'HEAD'].includes(request.method)) accepted.push('read:groups');
    if (!hasServiceScopes(user, accepted)) throw new ForbiddenException('Insufficient group scope');
    return true;
  }
}
