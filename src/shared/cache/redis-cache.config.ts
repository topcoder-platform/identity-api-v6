import { CacheModuleOptions } from '@nestjs/cache-manager';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createKeyv } from '@keyv/redis';

/**
 * Configures the shared Redis cache used by identity API instances.
 *
 * @param configService Application configuration containing REDIS_HOST and REDIS_PORT.
 * @returns Cache-module options with one Redis-backed Keyv store and millisecond TTLs.
 * @remarks Used by AppModule so OTPs, proofs, and pending email changes survive
 * requests reaching another instance. There is no per-instance memory tier.
 * @throws Redis operation errors propagate on writes instead of silently losing state.
 */
export function createRedisCacheOptions(
  configService: ConfigService,
): CacheModuleOptions {
  const logger = new Logger('RedisCache');
  const store = createKeyv(
    {
      socket: {
        host: configService.get<string>('REDIS_HOST', '127.0.0.1'),
        port: Number(configService.get<string>('REDIS_PORT', '6379')),
        connectTimeout: 5000,
      },
    },
    {
      namespace: 'identity-api-v6',
      throwOnErrors: true,
    },
  );
  store.throwOnErrors = true;
  store.on('error', () => logger.error('Redis cache operation failed.'));

  return {
    stores: [store],
    ttl: 30 * 24 * 60 * 60 * 1000,
  };
}
