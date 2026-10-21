import { Module, Global, Provider } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { MemberApiService } from './member-api.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager'; // Import CacheModule
import { auth } from 'tc-core-library-js';
import { Logger } from '@nestjs/common';
import { M2M_AUTH_CLIENT } from './member-api.constants'; // Import from constants file

/** Construct one shared-core provider from Nest Keycloak configuration; throws on invalid configuration. */
const m2mAuthProvider: Provider = {
  provide: M2M_AUTH_CLIENT, // Use the imported token
  useFactory: (configService: ConfigService) => {
    return auth.m2m({
      M2M_PROVIDER: configService.get<string>('M2M_PROVIDER'),
      KEYCLOAK_ISSUER: configService.get<string>('KEYCLOAK_ISSUER'),
      KEYCLOAK_AUDIENCE: configService.get<string>('KEYCLOAK_AUDIENCE'),
      KEYCLOAK_TOKEN_URL: configService.get<string>('KEYCLOAK_TOKEN_URL'),
      KEYCLOAK_CLIENT_ID: configService.get<string>('KEYCLOAK_CLIENT_ID'),
      KEYCLOAK_CLIENT_SECRET: configService.get<string>('KEYCLOAK_CLIENT_SECRET'),
      KEYCLOAK_SCOPE: configService.get<string>('KEYCLOAK_SCOPE'),
    });
  },
  inject: [ConfigService],
};

@Global() // Make service available globally
@Module({
  imports: [
    // HttpModule is needed by MemberApiService itself
    HttpModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
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
