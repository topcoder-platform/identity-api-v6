import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';

@Catch() // Catch all exceptions initially, can be refined later
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status: number;
    let message: any; // Can be string or object

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();
      message =
        typeof exceptionResponse === 'string'
          ? { message: exceptionResponse } // Ensure content is always an object
          : exceptionResponse;
    } else {
      // Handle non-HTTP exceptions
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      message = {
        message: 'Internal server error',
        // Include more details in development?
        ...(process.env.NODE_ENV !== 'production' && exception instanceof Error
          ? { detail: exception.message, stack: exception.stack }
          : {}),
      };
      this.logger.error(
        `Unhandled exception: ${exception instanceof Error ? exception.message : JSON.stringify(exception)}`,
        exception instanceof Error ? exception.stack : undefined,
        `${request.method} ${request.url}`,
      );
    }

    const errorResponse = {
      id: uuidv4(), // Generate unique request ID
      version: 'v6', // TODO: Make this configurable or derive from request?
      result: {
        success: false,
        status: status,
        metadata: null, // Metadata is typically null for errors
        content: message, // Use the extracted message (object)
      },
    };

    response.status(status).json(errorResponse);
  }
}
