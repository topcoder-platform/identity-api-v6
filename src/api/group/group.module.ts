import { Module } from '@nestjs/common';
import { GroupController } from './group.controller';
import { GroupService } from './group.service';
import { PRISMA_CLIENT_AUTHORIZATION } from '../../shared/prisma/prisma.module';
import { PrismaClient as PrismaClientAuthorization } from '@prisma/client-authorization';
import { MemberApiModule } from '../../shared/member-api/member-api.module';

@Module({
  imports: [MemberApiModule],
  controllers: [GroupController],
  providers: [
    GroupService,
    {
      provide: PRISMA_CLIENT_AUTHORIZATION,
      useClass: PrismaClientAuthorization,
    },
  ],
  exports: [GroupService],
})
export class GroupModule {}
