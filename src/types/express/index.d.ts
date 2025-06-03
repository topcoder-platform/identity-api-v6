import { AuthenticatedUser } from '../../core/auth/jwt.strategy';

declare global {
  namespace Express {
    export interface Request {
      user?: AuthenticatedUser;
    }
  }
}
