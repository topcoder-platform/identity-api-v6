import { Module, Global, Provider } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { MemberApiService } from './member-api.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager'; // Import CacheModule
import m2mAuth from 'tc-core-library-js/lib/auth/m2m'; // Use default import
import { Logger } from '@nestjs/common';
import { M2M_AUTH_CLIENT } from './member-api.constants'; // Import from constants file

// Define the provider for the M2M Auth client
const m2mAuthProvider: Provider = {
  provide: M2M_AUTH_CLIENT, // Use the imported token
  useFactory: (configService: ConfigService) => {
    const logger = new Logger('M2MAuthProvider');
    const options = {
      AUTH0_URL: configService.get<string>('AUTH0_URL'),
      AUTH0_AUDIENCE: configService.get<string>('AUTH0_AUDIENCE'),
      TOKEN_CACHE_TIME: configService.get<number>('TOKEN_CACHE_TIME'), // Library might expect number
      AUTH0_CLIENT_ID: configService.get<string>('AUTH0_CLIENT_ID'), // Needed for getMachineToken
      AUTH0_CLIENT_SECRET: configService.get<string>('AUTH0_CLIENT_SECRET'), // Needed for getMachineToken
      AUTH0_PROXY_SERVER_URL: configService.get<string>(
        'AUTH0_PROXY_SERVER_URL',
      ),
    };

    // --- Add Debug Logging ---
    logger.debug('--- M2M Auth Options Loaded ---');
    logger.debug(`AUTH0_URL: ${options.AUTH0_URL}`);
    logger.debug(`AUTH0_AUDIENCE: ${options.AUTH0_AUDIENCE}`);
    logger.debug(`AUTH0_CLIENT_ID: ${options.AUTH0_CLIENT_ID}`);
    logger.debug(
      `AUTH0_CLIENT_SECRET: ${options.AUTH0_CLIENT_SECRET ? '<present>' : '<missing or empty>'}`,
    ); // Log presence, not value
    logger.debug(`AUTH0_PROXY_SERVER_URL: ${options.AUTH0_PROXY_SERVER_URL}`);
    logger.debug(`TOKEN_CACHE_TIME: ${options.TOKEN_CACHE_TIME}`);
    logger.debug('-------------------------------');
    // --- End Debug Logging ---

    // Validate essential options for getMachineToken
    const requiredKeys: (keyof typeof options)[] = [
      'AUTH0_URL',
      'AUTH0_AUDIENCE',
      'AUTH0_CLIENT_ID',
      'AUTH0_CLIENT_SECRET',
    ];
    for (const key of requiredKeys) {
      if (!options[key]) {
        logger.warn(
          `M2M Auth Config Missing/Empty: ${key}. Check environment variables.`,
        );
        // Depending on strictness, could throw an error here
      }
    }

    logger.log(`Initializing M2M Auth client.`);
    try {
      // tc-core-library-js's m2m expects options object directly
      // It returns the initialized utility object/function set
      return m2mAuth(options);
    } catch (error) {
      logger.error(
        `Failed to initialize M2M Auth client: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  },
  inject: [ConfigService],
};

@Global() // Make service available globally
@Module({
  imports: [
    // HttpModule is needed by MemberApiService itself
    HttpModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        timeout: configService.get<number>('HTTP_TIMEOUT', 5000),
        maxRedirects: configService.get<number>('HTTP_MAX_REDIRECTS', 5),
      }),
      inject: [ConfigService],
    }),
    ConfigModule, // Ensure ConfigModule is available
    CacheModule.register(), // Ensure CacheModule is available if not global
  ],
  providers: [
    m2mAuthProvider, // Provide the M2M Auth client
    MemberApiService,
    Logger,
  ],
  exports: [
    MemberApiService,
    // Optionally export M2M_AUTH_CLIENT if needed elsewhere directly
    // M2M_AUTH_CLIENT
  ],
})
export class MemberApiModule {}
