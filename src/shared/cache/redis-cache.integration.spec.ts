import { CACHE_MANAGER, CacheModule } from '@nestjs/cache-manager';
import { ForbiddenException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import KeyvRedis from '@keyv/redis';
import { Cache } from 'cache-manager';
import { randomInt, randomUUID } from 'crypto';
import Redis from 'ioredis';
import { decode } from 'jsonwebtoken';
import { setTimeout as delay } from 'timers/promises';

import { EmailChangeService } from '../../api/user/email-change.service';
import { UserService } from '../../api/user/user.service';
import { ValidationService } from '../../api/user/validation.service';
import { MemberStatus } from '../../dto/member';
import { EventService } from '../event/event.service';
import { PRISMA_CLIENT } from '../prisma/prisma.module';
import { createRedisCacheOptions } from './redis-cache.config';

// Run explicitly against an isolated local Redis; ordinary unit runs skip this suite.
const describeWithRedis = process.env.REDIS_CACHE_TEST_PORT
  ? describe
  : describe.skip;

describeWithRedis('Shared Redis cache for email changes', () => {
  let modules: TestingModule[];
  let caches: Cache[];
  let services: EmailChangeService[];
  let redis: Redis;
  let userId: string;
  let keys: Set<string>;
  const eventService = {
    postDirectBusMessage: jest.fn().mockResolvedValue(undefined),
  };
  const userService = {
    updatePrimaryEmail: jest.fn().mockResolvedValue({}),
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    modules = [];
    caches = [];
    services = [];
    keys = new Set();
    userId = String(randomInt(80_000_000, 90_000_000));
    const configService = new ConfigService({
      REDIS_HOST: '127.0.0.1',
      REDIS_PORT: process.env.REDIS_CACHE_TEST_PORT,
      APP_DOMAIN: 'topcoder-dev.com',
      JWT_SECRET: 'isolated-cache-integration-test-secret',
    });
    redis = new Redis({
      host: '127.0.0.1',
      port: Number(process.env.REDIS_CACHE_TEST_PORT),
      maxRetriesPerRequest: 1,
    });
    await redis.ping();

    for (let instance = 0; instance < 2; instance++) {
      const module = await Test.createTestingModule({
        imports: [
          CacheModule.registerAsync({
            useFactory: () => createRedisCacheOptions(configService),
          }),
        ],
        providers: [
          EmailChangeService,
          { provide: ConfigService, useValue: configService },
          { provide: EventService, useValue: eventService },
          { provide: UserService, useValue: userService },
          {
            provide: ValidationService,
            useValue: { validateEmail: jest.fn().mockResolvedValue(undefined) },
          },
          {
            provide: PRISMA_CLIENT,
            useValue: {
              user: {
                findUnique: jest.fn().mockResolvedValue({
                  handle: 'cacheTestMember',
                  status: MemberStatus.ACTIVE,
                }),
              },
              email: {
                findFirst: jest.fn().mockResolvedValue({
                  address: 'old@example.com',
                }),
              },
            },
          },
        ],
      }).compile();
      modules.push(module);
      caches.push(module.get<Cache>(CACHE_MANAGER));
      services.push(module.get(EmailChangeService));
    }
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    // Remove only this test's keys, including any unfinished email-change state.
    if (caches[1]) {
      await Promise.all([...keys].map((key) => caches[1].del(key)));
    }
    await Promise.all(modules.map((module) => module.close()));
    await redis?.quit();
  });

  it('shares every phase across instances and survives the issuing instance stopping', async () => {
    keys.add(`EMAIL_CHANGE_OTP:${userId}`);
    await services[0].sendCurrentEmailOtp(userId);
    const otp = eventService.postDirectBusMessage.mock.calls[0][1].data.otp;
    const proof = await services[1].verifyCurrentEmailOtp(userId, otp);
    const proofClaims = decode(proof.verificationToken) as { jti: string };
    keys.add(`EMAIL_CHANGE_PROOF:${proofClaims.jti}`);

    await services[0].initiateEmailChange(
      userId,
      'new@example.com',
      proof.verificationToken,
    );
    await expect(
      services[1].initiateEmailChange(
        userId,
        'new@example.com',
        proof.verificationToken,
      ),
    ).rejects.toThrow('Current email verification has expired or was already used.');

    const payload = eventService.postDirectBusMessage.mock.calls[1][1];
    const code = new URL(payload.data.verificationAgreeUrl).searchParams.get('code');
    expect(code).toEqual(expect.any(String));
    const claims = decode(code as string) as { jti: string };
    keys.add(`EMAIL_CHANGE_PENDING:${claims.jti}`);

    await modules.shift()?.close();
    await expect(services[1].completeEmailChange(code as string)).resolves.toEqual({
      email: 'new@example.com',
    });
    expect(userService.updatePrimaryEmail).toHaveBeenCalledWith(
      userId,
      'new@example.com',
      expect.objectContaining({ userId }),
    );
    await expect(services[1].completeEmailChange(code as string)).rejects.toThrow(
      ForbiddenException,
    );
    expect(userService.updatePrimaryEmail).toHaveBeenCalledTimes(1);
  });

  it('expires shared entries using milliseconds and invalidates them on every instance', async () => {
    const key = `cache-integration:${randomUUID()}`;
    keys.add(key);
    await caches[0].set(key, { pending: true }, 500);
    await expect(caches[1].get(key)).resolves.toEqual({ pending: true });
    const ttl = await redis.pttl(`identity-api-v6::${key}`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(500);
    await delay(550);
    expect(await caches[1].get(key)).toBeNull();

    await caches[0].set(key, { pending: true }, 60_000);
    await caches[1].del(key);
    expect(await caches[0].get(key)).toBeNull();
  });

  it('rejects failed Redis writes instead of acknowledging lost verification state', async () => {
    const key = `cache-integration:${randomUUID()}`;
    keys.add(key);
    const adapter = caches[0].stores[0].store as KeyvRedis<unknown>;
    const log = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    jest.spyOn(adapter.client, 'set').mockRejectedValueOnce(new Error('write failed'));

    await expect(caches[0].set(key, { pending: true }, 60_000)).rejects.toThrow(
      'write failed',
    );
    expect(log).toHaveBeenCalledWith('Redis cache operation failed.');
    expect(await caches[1].get(key)).toBeNull();
  });
});
