import { Module, forwardRef } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { UserProfileService } from './user-profile.service';
import { AuthFlowService } from './auth-flow.service';
import { TwoFactorAuthService } from './two-factor-auth.service';
import { ValidationService } from './validation.service';
// Potentially import other necessary modules like RoleModule, EventModule
import { RoleModule } from '../role/role.module';
import { EventModule } from '../../shared/event/event.module';
import { SlackModule } from '../../shared/slack/slack.module';
import { MemberPrismaModule } from '../../shared/member-prisma/member-prisma.module';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { ScopesGuard } from '../../auth/guards/scopes.guard';
import { SelfOrAdminGuard } from '../../auth/guards/self-or-admin.guard';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';
// Assuming NotificationService and CacheService are global or provided elsewhere

@Module({
  imports: [
    PrismaModule, // Provides DB clients via injection tokens
    ConfigModule, // For accessing environment variables
    HttpModule, // For making external HTTP calls
    forwardRef(() => RoleModule), // RoleService needed for roles
    EventModule,
    SlackModule,
    MemberPrismaModule,
    // forwardRef(() => AuthorizationModule) // Might be needed if Auth flows depend on AuthorizationService
  ],
  controllers: [UserController],
  providers: [
    UserService,
    UserProfileService,
    AuthFlowService,
    TwoFactorAuthService,
    ValidationService,
    RolesGuard,
    ScopesGuard,
    SelfOrAdminGuard,
    AuthRequiredGuard,
    // Add NotificationService, SlackService if they belong here
  ],
  // Export services needed by other modules (e.g., AuthorizationService needs UserService?)
  exports: [
    UserService,
    UserProfileService,
    AuthFlowService,
    TwoFactorAuthService,
    ValidationService,
  ],
})
export class UserModule {}
