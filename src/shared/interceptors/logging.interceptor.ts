import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger('LoggingInterceptor');

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const method = request.method;
    const url = request.originalUrl;
    const correlationId = Date.now() + Math.random(); // Simple correlation ID

    this.logger.log(
      `[${correlationId}] INTERCEPTOR ===> BEFORE Route Handler ${method} ${url}`,
    );

    return next.handle().pipe(
      tap({
        next: () => {
          const response = context.switchToHttp().getResponse();
          this.logger.log(
            `[${correlationId}] INTERCEPTOR <=== AFTER Route Handler (Success) ${method} ${url} Status: ${response.statusCode}`,
          );
        },
        error: (error) => {
          const response = context.switchToHttp().getResponse();
          // Log status code from response if available, otherwise log error itself
          const status = response.statusCode || error?.status || 'N/A';
          this.logger.error(
            `[${correlationId}] INTERCEPTOR <=== AFTER Route Handler (Error) ${method} ${url} Status: ${status} Error: ${error?.message || error}`,
          );
        },
      }),
    );
  }
}
