import { AccessTokenJwksController } from './access-token-jwks.controller';
import { KMSClient } from '@aws-sdk/client-kms';
import { ConfigModule } from '@nestjs/config';
import {
  AccessTokenSigner,
  ACCESS_TOKEN_KMS,
} from './access-token-signer.service';
import { Module } from '@nestjs/common';
import { AuthorizationController } from './authorization.controller';
import { AuthorizationService } from './authorization.service';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { PrismaClient } from '@prisma/client';
import { Auth0Module } from 'src/shared/auth0/auth0.module';
import { UserModule } from '../user/user.module';
import { AuthDataStore } from './auth-data-store.service';
import { ZendeskAuthPlugin } from './zendesk.service';
import { UserProfileHelper } from './user-profile.helper';
import { ConfigurationModule } from 'src/config/configuration.module';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';

@Module({
  imports: [Auth0Module, ConfigurationModule, ConfigModule, UserModule],
  controllers: [AccessTokenJwksController, AuthorizationController],
  providers: [
    AuthorizationService,
    AccessTokenSigner,
    {
      provide: ACCESS_TOKEN_KMS,
      useFactory: () =>
        new KMSClient({
          maxAttempts: 2,
          requestHandler: { connectionTimeout: 2000, requestTimeout: 5000 },
        }),
    },
    {
      provide: PRISMA_CLIENT,
      useClass: PrismaClient,
    },
    AuthDataStore,
    ZendeskAuthPlugin,
    UserProfileHelper,
    AuthRequiredGuard,
  ],
  exports: [AuthorizationService],
})
export class AuthorizationModule {}
