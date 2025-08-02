import { Module, Global, Provider } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { PrismaClient as PrismaClientGroup } from '@prisma/client-group';

// Define injection tokens for clarity
export const PRISMA_CLIENT = 'PRISMA_CLIENT';
export const PRISMA_CLIENT_GROUP = 'PRISMA_CLIENT_GROUP';

// Create providers for prisma client
const prismaProvider: Provider = {
  provide: PRISMA_CLIENT,
  useFactory: () => {
    const client = new PrismaClient();
    // Connect eagerly or handle connection errors if needed
    client
      .$connect()
      .catch((e) => console.error('Failed to connect to identity DB', e));
    return client;
  },
};

// Create providers for group prisma client
const groupProvider: Provider = {
  provide: PRISMA_CLIENT_GROUP,
  useFactory: () => {
    const client = new PrismaClientGroup();
    // Connect eagerly or handle connection errors if needed
    client
      .$connect()
      .catch((e) => console.error('Failed to connect to identity DB', e));
    return client;
  },
};

@Global()
@Module({
  providers: [prismaProvider, groupProvider],
  exports: [PRISMA_CLIENT, PRISMA_CLIENT_GROUP],
})
export class PrismaModule {}
