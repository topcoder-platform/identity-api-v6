import { ConfigService } from '@nestjs/config';
import {
  getRedisConnectionConfig,
  getRedisTlsOptions,
  getRedisUrl,
} from './redis.config';

describe('Redis connection configuration', () => {
  it('prefers the TLS URL over the legacy host and port', () => {
    const config = new ConfigService({
      REDIS_URL: 'rediss://cache.example.com:6379/0',
      REDIS_HOST: 'old.example.com',
      REDIS_PORT: '6380',
    });
    const url = getRedisUrl(getRedisConnectionConfig(config));
    expect(url).toBe('rediss://cache.example.com:6379/0');
    expect(getRedisTlsOptions(url)).toEqual({
      servername: 'cache.example.com',
      minVersion: 'TLSv1.2',
      rejectUnauthorized: true,
    });
  });

  it('preserves legacy host/port and plaintext local development', () => {
    expect(getRedisUrl({ host: 'localhost', port: '6380' })).toBe(
      'redis://localhost:6380',
    );
    expect(getRedisTlsOptions(getRedisUrl({}))).toBeUndefined();
  });

  it('preserves URL credentials and database without logging them', () => {
    const url = 'rediss://default:escaped%40password@cache.example.com:6379/2';
    expect(getRedisUrl({ url })).toBe(url);
  });

  it.each([
    'https://cache.example.com',
    'cache.example.com:6379',
    'rediss://cache.example.com:0',
    'rediss://cache.example.com:invalid',
    'rediss://cache.example.com/invalid-db',
    'rediss://cache.example.com?tls=false',
    'rediss://cache.example.com#fragment',
  ])(
    'rejects malformed URLs without falling back to the old host: %s',
    (url) => {
      expect(() => getRedisUrl({ url, host: 'old.example.com' })).toThrow(
        'Invalid Redis configuration: use redis:// or rediss://',
      );
    },
  );
});
