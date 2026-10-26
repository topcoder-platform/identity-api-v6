import { UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import * as jwt from 'jsonwebtoken';
import { JwtStrategy } from './jwt.strategy';

const secret = 'a-test-only-secret-with-at-least-32-bytes';

describe('shared JWT strategy', () => {
  /** Creates the actual shared-verifier strategy with isolated service dependencies; no network is used. */
  function strategy() {
    const values: Record<string, string> = {
      JWT_VALIDATION_MODE: 'HS256', JWT_ISSUER_URL: 'https://issuer.test/',
      JWT_AUDIENCE: 'api', AUTH_SECRET: secret,
    };
    const cache = { get: jest.fn().mockResolvedValue({ scopes: ['admin'], isAdmin: true }), set: jest.fn() };
    return { service: new JwtStrategy({ get: (key: string, fallback?: string) => values[key] ?? fallback } as never, {} as never, cache as never), cache };
  }

  it('never replaces a machine token scope with cached scopes', async () => {
    const { service, cache } = strategy();
    const token = jwt.sign({ sub: 'client@clients', gty: 'client-credentials', scope: 'read:users' }, secret, { issuer: 'https://issuer.test/', audience: 'api', expiresIn: 300 });
    const user = await service.validate({ headers: { authorization: `Bearer ${token}` } } as Request);
    expect(user.scopes).toEqual(['read:users']);
    expect(user.isMachine).toBe(true);
    expect(user.isAdmin).toBe(false);
    expect(cache.get).not.toHaveBeenCalled();
  });

  it('rejects forged signatures before reading authorization data', async () => {
    const { service, cache } = strategy();
    const token = jwt.sign({ sub: '42', userId: '42' }, 'a-different-signing-secret', { issuer: 'https://issuer.test/', audience: 'api', expiresIn: 300 });
    await expect(service.validate({ headers: { authorization: `Bearer ${token}` } } as Request)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(cache.get).not.toHaveBeenCalled();
  });
});
