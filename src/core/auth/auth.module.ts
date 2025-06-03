import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport'; // <-- Restore import
import { JwtStrategy } from './jwt.strategy';
import { ConfigModule } from '@nestjs/config'; // Import ConfigModule if strategy uses ConfigService
import { PrismaModule } from '../../shared/prisma/prisma.module'; // Import PrismaModule for guard

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }), // <-- Restore registration with defaultStrategy
    ConfigModule, // Needed by JwtStrategy
    // PrismaModule, // No longer needed here directly for guards
  ],
  providers: [JwtStrategy], // Removed RolePermissionGuard
  exports: [PassportModule, JwtStrategy], // <-- Restore PassportModule export
})
export class AuthModule {}
