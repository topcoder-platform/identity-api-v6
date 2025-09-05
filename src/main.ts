import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { Logger, ValidationPipe } from '@nestjs/common'; // Import Logger and ValidationPipe
import { HttpExceptionFilter } from './core/filters/http-exception.filter'; // Import the filter
import { ValidationExceptionFilter } from './core/filters/validation-exception.filter'; // Import the new filter
import { RequestLoggerMiddleware } from './shared/middleware/request-logger.middleware'; // Import the logger middleware
import { LoggingInterceptor } from './shared/interceptors/logging.interceptor'; // <-- Import the interceptor
import { Request, Response, NextFunction } from 'express'; // Import express types
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { cors } from 'cors';

const logger = new Logger('Bootstrap');

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Apply the request logger middleware FIRST (Correctly)
  const requestLogger = new RequestLoggerMiddleware();
  app.use((req: Request, res: Response, next: NextFunction) => {
    requestLogger.use(req, res, next);
  });

  // Apply global interceptor AFTER middleware
  app.useGlobalInterceptors(new LoggingInterceptor()); // <-- Apply interceptor

  // Enable CORS (configure origins as needed)
  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin) {
          // disable cors if service to service request
          callback(null, false);
        } else {
          callback(null, new RegExp(/topcoder(-dev|-qa)?\.com$/));
        }
      },
    }),
  );
  // Set global prefix
  app.setGlobalPrefix('v6');

  // Apply global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Strip properties not defined in DTOs
      transform: true, // Automatically transform payloads to DTO instances
      transformOptions: {
        enableImplicitConversion: true, // Allow implicit type conversion (e.g., string to number for path params)
      },
    }),
  );

  // Apply global filters
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalFilters(new ValidationExceptionFilter()); // Apply the validation filter

  const config = new DocumentBuilder()
    .setTitle('TopCoder Identity Service')
    .setDescription('validate username / password logins, lookup roles, etc')
    .setVersion('v6')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document);

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);
  logger.log(`Application listening on port ${port}`);
  logger.log(`API available at http://localhost:${port}/v6`);
}

bootstrap()
  .then()
  .catch((err) => logger.error(err));
