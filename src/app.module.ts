import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';
import { createRedisCacheOptions } from './shared/cache/redis-cache.config';
import { EventModule } from './shared/event/event.module';
import { RoleModule } from './api/role/role.module';
import { AuthModule } from './core/auth/auth.module';
import { UserModule } from './api/user/user.module';
import { GroupModule } from './api/group/group.module';
import { MemberPrismaModule } from './shared/member-prisma/member-prisma.module';
import { AuthorizationModule } from './api/authorization/authorization.module';
import { IdentityProviderModule } from './api/identity-provider/identity-provider.module';
import { AuthMiddleware } from './auth/auth.middleware';
import { UserRolesModule } from './api/user-role/user-roles.module';
import { TopgearUserRolesModule } from './api/topgear-user-role/topgear-user-roles.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    CacheModule.registerAsync({
      isGlobal: true,
      imports: [ConfigModule],
      useFactory: createRedisCacheOptions,
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
    UserRolesModule,
    TopgearUserRolesModule,
    UserModule,
    GroupModule,
    AuthorizationModule,
    IdentityProviderModule,
  ],
  controllers: [], // No root controller
  providers: [], // No root service
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(AuthMiddleware).forRoutes('*');
  }
}
