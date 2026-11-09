import { CacheModule, CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { Cache } from 'cache-manager';
import Redis from 'ioredis';
import { randomUUID } from 'crypto';
import { createRedisCacheOptions } from '../src/config/redis-cache.config';
import { getRedisTlsOptions } from '../src/config/redis.config';
import { ConfigurationService } from '../src/config/configuration.service';
import { AuthDataStore } from '../src/api/authorization/auth-data-store.service';

// Use a disposable Redis/Valkey instance. Never point this suite at application data.
const url = process.env.REDIS_TEST_URL;
const describeRedis = url ? describe : describe.skip;
const itTls = url?.startsWith('rediss://') ? it : it.skip;

describeRedis('Redis integration', () => {
  let first: TestingModule;
  let second: TestingModule;
  let observer: Redis;
  const prefix = `pm6691-test-${randomUUID()}`;

  async function createModule() {
    const config = new ConfigService({ REDIS_URL: url });
    return Test.createTestingModule({
      imports: [
        CacheModule.registerAsync({
          imports: [ConfigModule],
          useFactory: () => createRedisCacheOptions(config),
        }),
      ],
      providers: [
        AuthDataStore,
        {
          provide: ConfigurationService,
          useValue: new ConfigurationService(config),
        },
      ],
    }).compile();
  }

  beforeAll(async () => {
    observer = new Redis(url, { tls: getRedisTlsOptions(url) });
    await observer.ping();
    first = await createModule();
    second = await createModule();
  });

  afterAll(async () => {
    await first?.close();
    await second?.close();
    await observer?.quit();
  });

  it('shares cache values across independent Nest containers and deletes them', async () => {
    const key = `${prefix}:shared`;
    const a = first.get<Cache>(CACHE_MANAGER);
    const b = second.get<Cache>(CACHE_MANAGER);
    try {
      await a.set(key, { otp: 'synthetic' }, 5000);
      expect(await b.get(key)).toEqual({ otp: 'synthetic' });
      const ttl = await observer.pttl(`identity-api-v6::${key}`);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(5000);
      await b.del(key);
      expect(await a.get(key)).toBeNull();
    } finally {
      await a.del(key);
    }
  });

  it('expires cache values using millisecond TTLs', async () => {
    const key = `${prefix}:expiry`;
    const cache = first.get<Cache>(CACHE_MANAGER);
    await cache.set(key, 'synthetic', 50);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(await second.get<Cache>(CACHE_MANAGER).get(key)).toBeNull();
  });

  it('preserves authorization key format and its 90-day TTL across instances', async () => {
    const claims = Buffer.from(JSON.stringify({ userId: prefix })).toString(
      'base64url',
    );
    const auth = { token: `e30.${claims}.synthetic`, target: 'test' };
    const a = first.get(AuthDataStore);
    const b = second.get(AuthDataStore);
    try {
      await a.put(auth);
      expect(await b.get(auth.token, auth.target)).toEqual(auth);
      const ttl = await observer.ttl(
        `ap:identity:authorization:${prefix}:test`,
      );
      expect(ttl).toBeGreaterThan(7775990);
      expect(ttl).toBeLessThanOrEqual(7776000);
      await b.delete(auth.token, auth.target);
      expect(await a.get(auth.token, auth.target)).toBeNull();
    } finally {
      await a.delete(auth.token, auth.target);
    }
  });

  it('fails startup when the configured cache cannot be reached', async () => {
    await expect(
      createRedisCacheOptions(
        new ConfigService({ REDIS_URL: 'redis://127.0.0.1:1' }),
      ),
    ).rejects.toThrow('Cannot connect to the configured Redis cache');
  });

  itTls(
    'rejects a TLS certificate for a different hostname in both clients',
    async () => {
      const wrongHostname = new URL(url);
      // The disposable test server certificate is valid only for localhost.
      wrongHostname.hostname = '127.0.0.1';
      const config = new ConfigService({ REDIS_URL: wrongHostname.toString() });
      await expect(createRedisCacheOptions(config)).rejects.toThrow(
        'Cannot connect to the configured Redis cache',
      );
      const auth = new AuthDataStore(new ConfigurationService(config));
      try {
        await expect(auth.get('synthetic', 'test')).rejects.toThrow(
          "authDataStore can't connect to redis",
        );
      } finally {
        await auth.onModuleDestroy();
      }
    },
  );
});
