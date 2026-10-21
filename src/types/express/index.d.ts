import { AuthenticatedUser } from '../../core/auth/auth.types';

declare global {
  namespace Express {
    export interface Request {
      user?: AuthenticatedUser;
    }
  }
}
