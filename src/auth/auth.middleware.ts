import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as tcCore from 'tc-core-library-js';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  private jwtAuthenticator: any;

  constructor() {
    const secret = process.env.AUTH_SECRET;
    const validIssuers =
      process.env.VALID_ISSUERS ||
      '["https://testsachin.topcoder-dev.com/","https://test-sachin-rs256.auth0.com/","https://api.topcoder.com","https://api.topcoder-dev.com","https://topcoder-dev.auth0.com/", "https://auth.topcoder-dev.com/"]';

    this.jwtAuthenticator = tcCore.middleware.jwtAuthenticator({
      AUTH_SECRET: secret,
      VALID_ISSUERS: validIssuers,
    });
  }

  use(req: Request, res: Response, next: NextFunction) {
    // If no Authorization header is present, continue (public endpoints can still work).
    if (!req.headers['authorization']) {
      return next();
    }
    return this.jwtAuthenticator(req, res, next);
  }
}
