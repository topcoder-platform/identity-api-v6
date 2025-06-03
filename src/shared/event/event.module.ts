import { Module, Global, Provider } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { EventService } from './event.service';
import busApi from '@topcoder-platform/topcoder-bus-api-wrapper';
import { Logger } from '@nestjs/common';
import { BUS_API_CLIENT } from './event.constants';

// Define the provider for the Bus API Client
const busApiClientProvider: Provider = {
  provide: BUS_API_CLIENT,
  useFactory: (configService: ConfigService) => {
    const logger = new Logger('BusApiClientProvider');
    const options = {
      AUTH0_URL: configService.get<string>('AUTH0_URL'),
      AUTH0_AUDIENCE: configService.get<string>('AUTH0_AUDIENCE'),
      TOKEN_CACHE_TIME: configService.get<string>('TOKEN_CACHE_TIME'),
      AUTH0_CLIENT_ID: configService.get<string>('AUTH0_CLIENT_ID'),
      AUTH0_CLIENT_SECRET: configService.get<string>('AUTH0_CLIENT_SECRET'),
      BUSAPI_URL: configService.get<string>('BUSAPI_URL'),
      KAFKA_ERROR_TOPIC: configService.get<string>('KAFKA_ERROR_TOPIC'),
      AUTH0_PROXY_SERVER_URL: configService.get<string>(
        'AUTH0_PROXY_SERVER_URL',
      ),
    };

    const requiredKeys: (keyof typeof options)[] = [
      'AUTH0_URL',
      'AUTH0_AUDIENCE',
      'AUTH0_CLIENT_ID',
      'AUTH0_CLIENT_SECRET',
      'BUSAPI_URL',
    ];
    let missingConfig = false;
    for (const key of requiredKeys) {
      if (!options[key]) {
        logger.warn(
          `Bus API Client Config Missing/Empty: ${key}. Check environment variables.`,
        );
        missingConfig = true;
      }
    }

    if (missingConfig) {
      logger.error(
        'Essential Bus API configuration is missing. Client initialization might fail or be incomplete.',
      );
    }

    logger.log(
      `Initializing Bus API Client for BUSAPI_URL: ${options.BUSAPI_URL}`,
    );
    try {
      return busApi(options);
    } catch (error) {
      logger.error(
        `Failed to initialize Bus API Client: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  },
  inject: [ConfigService],
};

@Global()
@Module({
  imports: [
    HttpModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        timeout: configService.get<number>('HTTP_TIMEOUT', 5000),
        maxRedirects: configService.get<number>('HTTP_MAX_REDIRECTS', 5),
      }),
      inject: [ConfigService],
    }),
    ConfigModule,
  ],
  providers: [busApiClientProvider, EventService, Logger],
  exports: [EventService],
})
export class EventModule {}
