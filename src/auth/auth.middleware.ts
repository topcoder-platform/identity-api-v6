import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { auth } from 'tc-core-library-js';

/** Validates optional bearer credentials once through shared core. Public routes
 * allow absent headers; supplied invalid tokens fail closed. No identity is inferred.
 */
@Injectable()
export class AuthMiddleware implements NestMiddleware {
  private readonly validator = auth.createValidator();

  /** Populate normalized Identity context for downstream guards/controllers.
   * @param req Express request with optional Authorization header.
   * @param res Response used for sanitized 401 failures.
   * @param next Continues after successful validation or absent credentials.
   * @returns Completion of validation; invalid credentials return 401, never throw.
   */
  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    const header = req.headers.authorization;
    if (header === undefined) { next(); return; }
    try {
      const match = /^Bearer ([^\s]+)$/i.exec(header);
      if (!match) throw new Error('Invalid bearer token');
      const principal = await this.validator.verify(match[1]);
      const user = {
        ...principal,
        userId: principal.kind === 'user' ? String(principal.userId) : undefined,
        isAdmin: principal.kind === 'user' && principal.roles.some(role =>
          role.toLowerCase() === (process.env.ADMIN_ROLE_NAME || 'administrator').toLowerCase()),
      };
      (req as Request & { authUser: unknown }).authUser = user;
      req.user = user;
    } catch {
      res.status(401).json({ message: 'Invalid or expired token' });
      return;
    }
    next();
  }
}
