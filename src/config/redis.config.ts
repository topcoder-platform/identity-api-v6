import { ConfigService } from '@nestjs/config';
import { ConnectionOptions } from 'tls';

export interface RedisConnectionConfig {
  url?: string;
  host?: string;
  port?: string | number;
}

export function getRedisConnectionConfig(
  config: ConfigService,
): RedisConnectionConfig {
  return {
    url: config.get<string>('REDIS_URL'),
    host: config.get<string>('REDIS_HOST', '127.0.0.1'),
    port: config.get<string>('REDIS_PORT', '6379'),
  };
}

/** REDIS_URL takes precedence; legacy host/port remain available for local/prod. */
export function getRedisUrl(config: RedisConnectionConfig): string {
  const value = config.url?.trim();
  try {
    const url = new URL(
      value || `redis://${config.host || '127.0.0.1'}:${config.port || 6379}`,
    );
    if (
      !['redis:', 'rediss:'].includes(url.protocol) ||
      !url.hostname ||
      url.search ||
      url.hash ||
      (url.pathname && !/^\/\d*$/.test(url.pathname)) ||
      url.port === '0'
    ) {
      throw new Error('Invalid connection configuration');
    }
    return url.toString();
  } catch {
    // URL parsing errors can include credentials; never include the supplied URL.
    throw new Error('Invalid Redis configuration: use redis:// or rediss://');
  }
}

export function getRedisTlsOptions(url: string): ConnectionOptions | undefined {
  const parsed = new URL(url);
  return parsed.protocol === 'rediss:'
    ? {
        servername: parsed.hostname,
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true,
      }
    : undefined;
}
