import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient as MemberPrismaClient } from '../../../prisma/member/generated/member';

@Injectable()
export class MemberPrismaService
  extends MemberPrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    super({
      transactionOptions: {
        timeout: process.env.IDENTITY_SERVICE_PRISMA_TIMEOUT || 10000,
      },
    });
  }

  async onModuleInit() {
    await this.$connect();
  }
  async onModuleDestroy() {
    await this.$disconnect();
  }
}
