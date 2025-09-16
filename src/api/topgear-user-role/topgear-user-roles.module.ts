import { Module } from '@nestjs/common';
import { TopgearUserRolesController } from './topgear-user-roles.controller';
import { UserRolesModule } from '../user-role/user-roles.module';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';

@Module({
  imports: [UserRolesModule],
  controllers: [TopgearUserRolesController],
  providers: [AuthRequiredGuard],
})
export class TopgearUserRolesModule {}
