import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { sanitizeForLogging } from '../util/log-sanitizer.util';

@Injectable()
export class RequestLoggerMiddleware implements NestMiddleware {
  private readonly logger = new Logger('HTTP'); // Use 'HTTP' context for clarity

  use(req: Request, res: Response, next: NextFunction) {
    const { method, originalUrl, headers } = req;
    const userAgent = headers['user-agent'] || '';
    // Log essential info at the beginning of the request
    this.logger.log(
      `---> ${method} ${originalUrl} - User-Agent: ${userAgent} - IP: ${req.ip}`,
    );
    this.logger.debug(
      `---> Request Headers: ${JSON.stringify(sanitizeForLogging(headers))}`,
    );

    if (this.shouldLogCreateUserBody(method, originalUrl)) {
      this.logger.debug(
        `---> Request Body: ${JSON.stringify(sanitizeForLogging(req.body))}`,
      );
    }

    // Optionally log when the request finishes
    res.on('finish', () => {
      const { statusCode } = res;
      this.logger.log(
        `<--- ${method} ${originalUrl} ${statusCode} - IP: ${req.ip}`,
      );
    });

    next();
  }

  private shouldLogCreateUserBody(
    method: string,
    originalUrl: string,
  ): boolean {
    const normalizedMethod = method.toUpperCase();
    if (normalizedMethod !== 'POST') {
      return false;
    }

    const pathOnly = originalUrl.split('?')[0];
    return /\/v6\/users\/?$/.test(pathOnly);
  }
}
