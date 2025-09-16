import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SELF_OR_ADMIN_PARAM_KEY } from '../decorators/self-or-admin.decorator';

@Injectable()
export class SelfOrAdminGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    const user = req?.authUser || req?.user;
    if (!user) throw new UnauthorizedException('Authentication required');
    if (user.isAdmin) return true;

    const paramKeys = this.reflector.getAllAndOverride<string[]>(
      SELF_OR_ADMIN_PARAM_KEY,
      [context.getHandler(), context.getClass()],
    ) || ['resourceId', 'userId'];

    let target: string | undefined;
    for (const key of paramKeys) {
      if (req.params && req.params[key] !== undefined) {
        target = String(req.params[key]);
        break;
      }
    }

    if (target === undefined) {
      // As a minor convenience, also check query for userId/resourceId
      for (const key of paramKeys) {
        if (req.query && req.query[key] !== undefined) {
          target = String(req.query[key]);
          break;
        }
      }
    }

    if (target === undefined) {
      throw new ForbiddenException('Target user id not found in request');
    }

    if (String(user.userId) !== String(target)) {
      throw new ForbiddenException('Permission denied: self or admin required');
    }
    return true;
  }
}
