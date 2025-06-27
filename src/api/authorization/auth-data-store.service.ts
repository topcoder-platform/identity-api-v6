import { Injectable, Logger, OnModuleDestroy } from "@nestjs/common";
import Redis, { RedisOptions } from 'ioredis';
import { ConfigurationService } from "../../config/configuration.service";
import { AuthorizationResponse } from "../../dto/authorization/authorization.dto";
import { CommonUtils } from "../../shared/util/common.utils";

@Injectable()
export class AuthDataStore {
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
}

/**
 * Define auth store base class
 */
abstract class DataStoreService {
  protected readonly logger = new Logger(DataStoreService.name);

  public abstract put(auth: AuthorizationResponse): Promise<void>;
  public abstract get(token: string, target: string): Promise<AuthorizationResponse | null>;
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
      this.logger.warn(`Failed to extract user-id from JWT token. token: ${token}`, error);
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
    this.logger.debug(`Put (${key}, ${auth})`);
    this.store[key] = auth;
    // create task to clear cache
    setTimeout(() => {
      delete this.store[key];
    }, DEFAULT_EXPIRY_SECONDS * 1000);
  }

  async get(token: string, target: string): Promise<AuthorizationResponse | null> {
    if (token == null || token.trim().length === 0) {
      return null;
    }
    const key = this.getKey(token, target);
    const auth = this.store[key];
    this.logger.debug(`Get (${key}, ${auth})`);
    return auth;
  }

  async delete(token: string, target: string): Promise<void> {
    if (token == null || token.trim().length === 0) {
      return;
    }
    const key = this.getKey(token, target);
    this.logger.debug(`delete (${key})`);
    delete this.store[key];
  }
}


export class RedisDataStore extends DataStoreService implements OnModuleDestroy {

  private redisClient: Redis;
  private readonly expirySeconds: number;
  private readonly redisOptions: RedisOptions;

  constructor(config) {
    super();
    // create redis connection
    this.redisOptions = {
      host: config.spec.host || 'localhost',
      port: parseInt(config.spec.port) || 6379
    };
    this.expirySeconds = config.spec.expirySeconds;
  }

  private async getRedisClient() {
    if (!this.redisClient) {
      this.redisClient = new Redis(this.redisOptions);
      // check connection
      try {
        await this.redisClient.ping();
      } catch (error) {
        this.redisClient = null;
        this.logger.error('Cannot connect to redis.', error);
        throw new Error('authDataStore can\'t connect to redis');
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

  async get(token: string, target: string): Promise<AuthorizationResponse | null> {
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
