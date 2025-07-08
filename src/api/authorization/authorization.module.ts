import { Module } from '@nestjs/common';
import { AuthorizationController } from './authorization.controller';
import { AuthorizationService } from './authorization.service';
import { PRISMA_CLIENT_AUTHORIZATION } from '../../shared/prisma/prisma.module';
import { PrismaClient as PrismaClientAuthorization } from '@prisma/client-authorization';
import { Auth0Module } from 'src/shared/auth0/auth0.module';
import { UserModule } from '../user/user.module';
import { AuthDataStore } from './auth-data-store.service';
import { ZendeskAuthPlugin } from './zendesk.service';
import { UserProfileHelper } from './user-profile.helper';
import { ConfigurationModule } from 'src/config/configuration.module';

@Module({
  imports: [Auth0Module, ConfigurationModule, UserModule],
  controllers: [AuthorizationController],
  providers: [
    AuthorizationService,
    {
      provide: PRISMA_CLIENT_AUTHORIZATION,
      useClass: PrismaClientAuthorization,
    },
    AuthDataStore,
    ZendeskAuthPlugin,
    UserProfileHelper,
  ],
  exports: [AuthorizationService],
})
export class AuthorizationModule {}
