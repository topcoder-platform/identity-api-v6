import { Module } from '@nestjs/common';
import { GroupController } from './group.controller';
import { GroupService } from './group.service';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { MemberApiModule } from '../../shared/member-api/member-api.module';

@Module({
  imports: [MemberApiModule, PrismaModule],
  controllers: [GroupController],
  providers: [GroupService],
  exports: [GroupService],
})
export class GroupModule {}
