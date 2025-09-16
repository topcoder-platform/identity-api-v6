import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required || required.length === 0) return true;

    const req = context.switchToHttp().getRequest();
    const user = req.authUser || req.user;
    if (!user) throw new ForbiddenException('Missing auth user');

    const rawRoles = (user.roles ?? user.role) as string[] | string | undefined;
    const roles: string[] = Array.isArray(rawRoles)
      ? rawRoles
      : String(rawRoles || '')
          .split(',')
          .map((r) => r.trim())
          .filter(Boolean);

    const ok = roles.some((r) => required.includes(r));
    if (!ok) throw new ForbiddenException('Insufficient role');
    return true;
  }
}
