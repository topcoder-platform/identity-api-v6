import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Response } from 'express';
import { ValidationError } from 'class-validator';

@Catch(HttpException)
export class ValidationExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(ValidationExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    let message = exception.message;
    let errors: any = null;

    // Handle class-validator ValidationPipe errors specifically
    if (
      status === HttpStatus.BAD_REQUEST &&
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

    response.status(status).json({
      statusCode: status,
      message: message,
      errors: errors, // Include formatted validation errors if present
      timestamp: new Date().toISOString(),
      path: ctx.getRequest().url,
    });
  }

  private formatValidationErrors(validationErrors: ValidationError[]) {
    const formattedErrors = {};
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
}
