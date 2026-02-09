import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ValidationError } from 'class-validator';
import { sanitizeForLogging } from '../util/log-sanitizer.util';

@Catch(HttpException)
export class ValidationExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(ValidationExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    let message = exception.message;
    let errors: Record<string, string> | null = null;

    // Handle class-validator ValidationPipe errors specifically
    if (
      status === (HttpStatus.BAD_REQUEST as number) &&
      typeof exceptionResponse === 'object' &&
      exceptionResponse !== null &&
      'message' in exceptionResponse
    ) {
      // Type assertion for exceptionResponse.message
      const validationErrors = (exceptionResponse as { message: unknown })
        .message;
      if (
        Array.isArray(validationErrors) &&
        validationErrors[0] instanceof ValidationError
      ) {
        message = 'Validation failed';
        errors = this.formatValidationErrors(validationErrors);
        this.logger.warn(`Validation Error: ${JSON.stringify(errors)}`);
      } else if (typeof validationErrors === 'string') {
        message = validationErrors; // Already a string
      } else {
        // Use type assertion again or a default message
        message =
          (exceptionResponse as { message?: string }).message || message;
      }
    } else if (typeof exceptionResponse === 'string') {
      message = exceptionResponse; // Use the string response as the message
    } else if (
      typeof exceptionResponse === 'object' &&
      exceptionResponse !== null &&
      'message' in exceptionResponse
    ) {
      // Use type assertion
      message = (exceptionResponse as { message?: string }).message || message;
    }

    if (status === HttpStatus.BAD_REQUEST) {
      const reason = this.extractBadRequestReason(
        exceptionResponse,
        message,
        errors,
      );
      this.logger.warn(
        `400 Bad Request: ${request.method} ${request.originalUrl} - Reason: ${reason}`,
      );

      if (this.isCreateUserRequest(request.method, request.originalUrl)) {
        this.logger.warn(
          `400 Request Body: ${JSON.stringify(sanitizeForLogging(request.body))}`,
        );
      }
    }

    response.status(status).json({
      statusCode: status,
      message: message,
      errors: errors, // Include formatted validation errors if present
      timestamp: new Date().toISOString(),
      path: request.url,
    });
  }

  private formatValidationErrors(
    validationErrors: ValidationError[],
  ): Record<string, string> {
    const formattedErrors: Record<string, string> = {};
    validationErrors.forEach((err) => {
      formattedErrors[err.property] = Object.values(err.constraints || {}).join(
        ', ',
      );
      // Recursively format nested errors if needed
      if (err.children && err.children.length > 0) {
        // Basic nested formatting, can be enhanced
        formattedErrors[err.property] +=
          ` (Nested: ${JSON.stringify(this.formatValidationErrors(err.children))})`;
      }
    });
    return formattedErrors;
  }

  private extractBadRequestReason(
    exceptionResponse: unknown,
    fallbackMessage: string,
    errors: Record<string, string> | null,
  ): string {
    if (typeof exceptionResponse === 'string') {
      return exceptionResponse;
    }

    if (
      typeof exceptionResponse === 'object' &&
      exceptionResponse !== null &&
      'message' in exceptionResponse
    ) {
      const responseMessage = (exceptionResponse as { message?: unknown })
        .message;
      if (Array.isArray(responseMessage)) {
        return responseMessage.map((entry) => String(entry)).join('; ');
      }
      if (typeof responseMessage === 'string') {
        return responseMessage;
      }
      return JSON.stringify(sanitizeForLogging(responseMessage));
    }

    if (errors && Object.keys(errors).length > 0) {
      return JSON.stringify(sanitizeForLogging(errors));
    }

    return fallbackMessage;
  }

  private isCreateUserRequest(method: string, originalUrl: string): boolean {
    const pathOnly = originalUrl.split('?')[0];
    return method.toUpperCase() === 'POST' && /\/v6\/users\/?$/.test(pathOnly);
  }
}
