import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { Response } from 'express';

@Catch(BadRequestException)
export class ValidationExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(ValidationExceptionFilter.name);

  catch(exception: BadRequestException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    // Default response structure for ValidationPipe errors
    // is { statusCode: 400, message: [ validation errors ], error: 'Bad Request' }
    let validationErrors: string[] = [];
    if (
      typeof exceptionResponse === 'object' &&
      exceptionResponse !== null &&
      'message' in exceptionResponse
    ) {
      // Check if the message property holds the array of validation errors
      if (Array.isArray(exceptionResponse.message)) {
        validationErrors = exceptionResponse.message;
        this.logger.error('Validation Failed:', validationErrors);
      }
    }

    // Log the raw response as well for debugging
    this.logger.error(
      `Raw BadRequestException response: ${JSON.stringify(exceptionResponse)}`,
    );

    // Send the original BadRequestException response back to the client
    response.status(status).json(exceptionResponse);
  }
}
