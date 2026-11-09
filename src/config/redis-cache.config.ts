import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CacheModuleOptions } from '@nestjs/cache-manager';
import KeyvRedis, { RedisClientOptions } from '@keyv/redis';
import Keyv from 'keyv';
import {
  getRedisConnectionConfig,
  getRedisTlsOptions,
  getRedisUrl,
} from './redis.config';

export async function createRedisCacheOptions(
  config: ConfigService,
): Promise<CacheModuleOptions> {
  const url = getRedisUrl(getRedisConnectionConfig(config));
  const tls = getRedisTlsOptions(url);
  const logger = new Logger('RedisCache');
  const socket = { connectTimeout: 5000, reconnectStrategy: false as const };
  const options: RedisClientOptions = {
    url,
    socket: tls ? { ...socket, ...tls, tls: true } : socket,
    // Fail requests promptly; the adapter reconnects on subsequent operations.
    disableOfflineQueue: true,
  };
  const adapter = new KeyvRedis(options, {
    throwOnConnectError: true,
    throwOnErrors: true,
  });
  const store = new Keyv({
    store: adapter,
    namespace: 'identity-api-v6',
    useKeyPrefix: false,
    throwOnErrors: true,
  });
  store.on('error', () =>
    logger.error('Redis cache connection/operation failed'),
  );

  try {
    // A configured but unreachable cache must not silently become process memory.
    const client = await adapter.getClient();
    await client.ping();
  } catch {
    await adapter.disconnect(true).catch(() => undefined);
    throw new Error('Cannot connect to the configured Redis cache');
  }

  return { stores: [store], ttl: 30 * 24 * 60 * 60 * 1000 };
}
