import { Module } from '@nestjs/common';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { IdentityProviderController } from './identity-provider.controller';
import { IdentityProviderService } from './identity-provider.service';

@Module({
  imports: [
    PrismaModule, // Provides DB clients via injection tokens
  ],
  controllers: [IdentityProviderController],
  providers: [IdentityProviderService],
  exports: [IdentityProviderService],
})
export class IdentityProviderModule {}
