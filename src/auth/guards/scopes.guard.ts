import { auth, Principal } from 'tc-core-library-js';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SCOPES_KEY } from '../decorators/scopes.decorator';

/** Enforces all declared grants on verified service principals only. */
@Injectable()
export class ScopesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  /** Check declared scopes for the execution context; returns true or throws ForbiddenException. */
  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<string[]>(SCOPES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required || required.length === 0) return true;

    const req = context.switchToHttp().getRequest();
    const user = req.authUser || req.user;
    if (!user) throw new ForbiddenException('Missing auth user');

    const ok = auth.hasScopes(user as Principal, required);
    if (!ok) throw new ForbiddenException('Missing required scope(s)');
    return true;
  }
}
