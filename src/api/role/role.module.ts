import { Module } from '@nestjs/common';
import { RoleController } from './role.controller';
import { RoleService } from './role.service';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { MemberApiModule } from '../../shared/member-api/member-api.module';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { ScopesGuard } from '../../auth/guards/scopes.guard';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';

@Module({
  imports: [PrismaModule, MemberApiModule],
  controllers: [RoleController],
  providers: [RoleService, RolesGuard, ScopesGuard, AuthRequiredGuard],
  exports: [RoleService],
})
export class RoleModule {}
