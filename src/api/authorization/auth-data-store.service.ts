import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import Redis, { RedisOptions } from 'ioredis';
import { ConfigurationService } from '../../config/configuration.service';
import { AuthorizationResponse } from '../../dto/authorization/authorization.dto';
import { CommonUtils } from '../../shared/util/common.utils';
import { getRedisTlsOptions, getRedisUrl } from '../../config/redis.config';

@Injectable()
export class AuthDataStore implements OnModuleDestroy {
  private readonly storeConfig;

  private readonly store: DataStoreService;
  constructor(private readonly config: ConfigurationService) {
    this.storeConfig = this.config.getAuthStore();

    if (this.storeConfig.type === 'memory') {
      this.store = new InMemoryDataStore();
    } else if (this.storeConfig.type === 'redis') {
      this.store = new RedisDataStore(this.storeConfig);
    }
  }

  async put(auth: AuthorizationResponse): Promise<void> {
    await this.store.put(auth);
  }

  async get(token: string, target: string): Promise<AuthorizationResponse> {
    return await this.store.get(token, target);
  }

  async delete(token: string, target: string): Promise<void> {
    await this.store.delete(token, target);
  }

  async onModuleDestroy(): Promise<void> {
    if (this.store instanceof RedisDataStore) {
      await this.store.onModuleDestroy();
    }
  }
}

/**
 * Define auth store base class
 */
abstract class DataStoreService {
  protected readonly logger = new Logger(DataStoreService.name);

  public abstract put(auth: AuthorizationResponse): Promise<void>;
  public abstract get(
    token: string,
    target: string,
  ): Promise<AuthorizationResponse | null>;
  public abstract delete(token: string, target: string): Promise<void>;

  protected getAuthKey(auth: AuthorizationResponse) {
    return this.getKey(auth.token, auth.target);
  }

  protected getKey(token: string, target: string | null | undefined): string {
    const userId = this.getUserId(token);
    return `ap:identity:authorization:${userId}:${target == null ? '' : target}`;
  }

  protected getUserId(token: string): string {
    try {
      const decoded = CommonUtils.parseJWTClaims(token);
      return String(decoded['userId']);
    } catch (error) {
      this.logger.warn(
        `Failed to extract user-id from JWT token. token: ${token}`,
        error,
      );
      throw new Error('Failed to extract user-id from JWT token.');
    }
  }
}

const DEFAULT_EXPIRY_SECONDS = 90 * 24 * 60 * 60 * 1000;

/**
 * In memory auth store.
 */
export class InMemoryDataStore extends DataStoreService {
  private readonly store: Record<string, AuthorizationResponse>;

  constructor() {
    super();
    this.store = {};
  }

  async put(auth: AuthorizationResponse | null | undefined): Promise<void> {
    if (auth == null) {
      return;
    }
    const key = this.getAuthKey(auth);
    this.logger.debug(`Put (${key}, ${JSON.stringify(auth)})`);
    this.store[key] = auth;
    // create task to clear cache
    setTimeout(() => {
      delete this.store[key];
    }, DEFAULT_EXPIRY_SECONDS * 1000);
    return Promise.resolve();
  }

  async get(
    token: string,
    target: string,
  ): Promise<AuthorizationResponse | null> {
    if (token == null || token.trim().length === 0) {
      return null;
    }
    const key = this.getKey(token, target);
    const auth = this.store[key];
    this.logger.debug(`Get (${key}, ${JSON.stringify(auth)})`);
    return Promise.resolve(auth);
  }

  async delete(token: string, target: string): Promise<void> {
    if (token == null || token.trim().length === 0) {
      return;
    }
    const key = this.getKey(token, target);
    this.logger.debug(`delete (${key})`);
    delete this.store[key];
    return Promise.resolve();
  }
}

export class RedisDataStore
  extends DataStoreService
  implements OnModuleDestroy
{
  private redisClient: Redis;
  private readonly expirySeconds: number;
  private readonly redisOptions: RedisOptions;

  private readonly redisUrl: string;

  constructor(config) {
    super();
    this.redisUrl = getRedisUrl(config.spec);
    this.redisOptions = {
      tls: getRedisTlsOptions(this.redisUrl),
      connectTimeout: 5000,
      commandTimeout: 5000,
      maxRetriesPerRequest: 1,
    };
    this.expirySeconds = config.spec.expirySeconds;
  }

  private async getRedisClient() {
    if (!this.redisClient) {
      this.redisClient = new Redis(this.redisUrl, this.redisOptions);
      this.redisClient.on('error', () =>
        this.logger.error('Authorization Redis connection failed'),
      );
      // check connection
      try {
        await this.redisClient.ping();
      } catch {
        this.redisClient.disconnect();
        this.redisClient = null;
        this.logger.error('Cannot connect to authorization Redis');
        throw new Error("authDataStore can't connect to redis");
      }
    }
    return this.redisClient;
  }

  async onModuleDestroy() {
    try {
      if (this.redisClient) {
        await this.redisClient.quit();
      }
    } catch (error) {
      this.logger.debug('Error disconnecting redis.', error);
    }
  }

  async put(auth: AuthorizationResponse): Promise<void> {
    if (auth == null) {
      return;
    }
    const redis = await this.getRedisClient();
    const key = this.getAuthKey(auth);
    this.logger.debug(`Redis put (${key}, ${JSON.stringify(auth)})`);
    await redis.setex(key, this.expirySeconds, JSON.stringify(auth));
  }

  async get(
    token: string,
    target: string,
  ): Promise<AuthorizationResponse | null> {
    if (token == null || token.trim().length === 0) {
      return null;
    }
    const redis = await this.getRedisClient();
    const key = this.getKey(token, target);
    this.logger.debug(`Redis get (${key})`);
    const content = await redis.get(key);
    if (content == null) {
      return null;
    }
    return JSON.parse(content) as AuthorizationResponse;
  }

  async delete(token: string, target: string): Promise<void> {
    if (token == null || token.trim().length === 0) {
      return;
    }
    const redis = await this.getRedisClient();
    const key = this.getKey(token, target);
    this.logger.debug(`Redis delete (${key})`);
    await redis.del(key);
  }
}
