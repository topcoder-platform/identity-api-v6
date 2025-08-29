import { Global, Module } from '@nestjs/common';
import { MemberPrismaService } from './member-prisma.service';

@Global()
@Module({
  providers: [MemberPrismaService],
  exports: [MemberPrismaService],
})
export class MemberPrismaModule {}
