import { Module } from '@nestjs/common';
import { UserRolesController } from './user-roles.controller';
import { UserRolesService } from './user-roles.service';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { RoleModule } from '../role/role.module';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';

@Module({
  imports: [PrismaModule, RoleModule],
  controllers: [UserRolesController],
  providers: [UserRolesService, AuthRequiredGuard],
  exports: [UserRolesService],
})
export class UserRolesModule {}
