import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';
import { redisStore } from 'cache-manager-ioredis';
import { EventModule } from './shared/event/event.module';
import { RoleModule } from './api/role/role.module';
import { AuthModule } from './core/auth/auth.module';
import { UserModule } from './api/user/user.module';
import { GroupModule } from './api/group/group.module';
import { MemberPrismaModule } from './shared/member-prisma/member-prisma.module';
import { AuthorizationModule } from './api/authorization/authorization.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    CacheModule.registerAsync({
      isGlobal: true,
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        store: redisStore,
        host: configService.get<string>('REDIS_HOST', '127.0.0.1'),
        port: configService.get<number>('REDIS_PORT', 6379),
        ttl: 30 * 24 * 60 * 60 * 1000, // Default TTL: 30 days in milliseconds
        // password: configService.get<string>('REDIS_PASSWORD'),
        // db: configService.get<number>('REDIS_DB', 0),
      }),
      inject: [ConfigService],
    }),
    EventModule,
    AuthModule,
    // CoreModule,
    // SharedModule,
    // --> Add API modules here <--
    // UserModule,
    MemberPrismaModule,
    RoleModule,
    UserModule,
    GroupModule,
    AuthorizationModule
  ],
  controllers: [], // No root controller
  providers: [], // No root service
})
export class AppModule {}
