import { Module } from '@nestjs/common';
import { RoleController } from './role.controller';
import { RoleService } from './role.service';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { MemberApiModule } from '../../shared/member-api/member-api.module';

@Module({
  imports: [PrismaModule, MemberApiModule],
  controllers: [RoleController],
  providers: [RoleService],
  exports: [RoleService],
})
export class RoleModule {}
