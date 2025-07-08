import { Module, Global, Provider } from '@nestjs/common';
import { PrismaClient as PrismaClientCommonOltp } from '@prisma/client-common-oltp';
import { PrismaClient as PrismaClientAuthorization } from '@prisma/client-authorization';

// Define injection tokens for clarity
export const PRISMA_CLIENT_COMMON_OLTP = 'PRISMA_CLIENT_COMMON_OLTP';
export const PRISMA_CLIENT_AUTHORIZATION = 'PRISMA_CLIENT_AUTHORIZATION';

// Create providers for each client
const commonOltpProvider: Provider = {
  provide: PRISMA_CLIENT_COMMON_OLTP,
  useFactory: () => {
    const client = new PrismaClientCommonOltp();
    // Connect eagerly or handle connection errors if needed
    client
      .$connect()
      .catch((e) => console.error('Failed to connect to common_oltp DB', e));
    return client;
  },
};

const authorizationProvider: Provider = {
  provide: PRISMA_CLIENT_AUTHORIZATION,
  useFactory: () => {
    const client = new PrismaClientAuthorization();
    // Connect eagerly or handle connection errors if needed
    client
      .$connect()
      .catch((e) => console.error('Failed to connect to authorization DB', e));
    console.log('Connected to authorization DB');
    return client;
  },
};

@Global()
@Module({
  providers: [commonOltpProvider, authorizationProvider],
  exports: [PRISMA_CLIENT_COMMON_OLTP, PRISMA_CLIENT_AUTHORIZATION],
})
export class PrismaModule {}
