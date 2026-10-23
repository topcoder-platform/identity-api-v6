import { Module, Global, Provider } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { EventService } from './event.service';
import busApi from '@topcoder-platform/topcoder-bus-api-wrapper';
import { auth } from 'tc-core-library-js';
import { Logger } from '@nestjs/common';
import { BUS_API_CLIENT } from './event.constants';

/**
 * Persistent Bus client for the M2M provider selected by `USE_KEYCLOAK`.
 *
 * The factory takes the Nest `ConfigService` and returns the `tc-bus-api-wrapper`
 * client injected as `BUS_API_CLIENT` into `EventService`. The wrapper's `AUTH0_*`
 * option names come from `auth.wrapperSettings`: with `USE_KEYCLOAK=true` they carry
 * `KEYCLOAK_TOKEN_URL`, `KEYCLOAK_AUDIENCE`, `KEYCLOAK_CLIENT_ID` and
 * `KEYCLOAK_CLIENT_SECRET`; unset or `false` keeps the pre-migration `AUTH0_URL`,
 * `AUTH0_AUDIENCE`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET` and
 * `AUTH0_PROXY_SERVER_URL`. Missing values are logged; the nested shared-core
 * dependency is pinned. Throws at startup for invalid wrapper configuration or a
 * `USE_KEYCLOAK` value other than `true`/`false`.
 */
const busApiClientProvider: Provider = {
  provide: BUS_API_CLIENT,
  useFactory: (configService: ConfigService) => {
    const logger = new Logger('BusApiClientProvider');
    const options = {
      ...auth.wrapperSettings({
        USE_KEYCLOAK: configService.get<string>('USE_KEYCLOAK'),
        KEYCLOAK_TOKEN_URL: configService.get<string>('KEYCLOAK_TOKEN_URL'),
        KEYCLOAK_AUDIENCE: configService.get<string>('KEYCLOAK_AUDIENCE'),
        KEYCLOAK_CLIENT_ID: configService.get<string>('KEYCLOAK_CLIENT_ID'),
        KEYCLOAK_CLIENT_SECRET: configService.get<string>(
          'KEYCLOAK_CLIENT_SECRET',
        ),
        AUTH0_URL: configService.get<string>('AUTH0_URL'),
        AUTH0_AUDIENCE: configService.get<string>('AUTH0_AUDIENCE'),
        AUTH0_CLIENT_ID: configService.get<string>('AUTH0_CLIENT_ID'),
        AUTH0_CLIENT_SECRET: configService.get<string>('AUTH0_CLIENT_SECRET'),
        AUTH0_PROXY_SERVER_URL: configService.get<string>(
          'AUTH0_PROXY_SERVER_URL',
        ),
      }),
      TOKEN_CACHE_TIME: configService.get<string>('TOKEN_CACHE_TIME'),
      BUSAPI_URL: configService.get<string>('BUSAPI_URL'),
      KAFKA_ERROR_TOPIC: configService.get<string>('KAFKA_ERROR_TOPIC'),
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
      useFactory: (configService: ConfigService) => ({
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
