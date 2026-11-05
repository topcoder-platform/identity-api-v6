import { UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { generateKeyPairSync } from 'node:crypto';
import { createRequire } from 'node:module';
import * as jwt from 'jsonwebtoken';
import { JwtStrategy } from './jwt.strategy';

const secret = 'a-test-only-secret-with-at-least-32-bytes';
const browserIssuer = 'https://browser.example.test/';
const machineIssuer = 'https://machine.example.test/';
const legacyIssuer = 'https://legacy.example.test';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const sharedRequire = createRequire(require.resolve('tc-core-library-js'));
const { JwksClient } = sharedRequire('jwks-rsa') as {
  JwksClient: { prototype: { getSigningKey(kid: string): Promise<{ getPublicKey(): string }> } };
};

describe('shared JWT strategy', () => {
  beforeEach(() => {
    // Only key retrieval is stubbed; the released core verifies real signatures and claims.
    jest.spyOn(JwksClient.prototype, 'getSigningKey').mockResolvedValue({
      getPublicKey: () => publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    });
  });
  afterEach(() => jest.restoreAllMocks());

  /** Builds the strategy from common environment settings with isolated role storage.
   * @returns The real strategy and cache spy; invalid JWT configuration throws.
   */
  function strategy() {
    const values: Record<string, string> = {
      VALID_ISSUERS: JSON.stringify([browserIssuer, machineIssuer, legacyIssuer]),
      JWT_AUDIENCE: 'browser-client', AUTH0_AUDIENCE: 'machine-api', AUTH_SECRET: secret,
      // Old service settings must not override the shared issuer and audience policies.
      JWT_VALIDATION_MODE: 'HS256', JWT_ISSUER_URL: 'obsolete,issuer,list',
    };
    const cache = { get: jest.fn().mockResolvedValue({ roles: ['User'], scopes: ['admin'], isAdmin: false }), set: jest.fn() };
    return { service: new JwtStrategy({ get: (key: string, fallback?: string) => values[key] ?? fallback } as never, {} as never, cache as never), cache };
  }

  /** Validates a compact JWT through the real Passport adapter.
   * @param token Signed test token. @returns Verified user or a rejected authentication promise.
   */
  function validate(token: string) {
    return strategy().service.validate({ headers: { authorization: `Bearer ${token}` } } as Request);
  }

  it('accepts browser RS256 tokens using the browser audience', async () => {
    const token = jwt.sign({ sub: 'user', userId: '42', roles: ['User'] }, privateKey, { algorithm: 'RS256', keyid: 'test-key', issuer: browserIssuer, audience: 'browser-client', expiresIn: 300 });
    await expect(validate(token)).resolves.toMatchObject({ userId: '42', isMachine: false });
  });

  it('accepts audience-free legacy HS256 human tokens', async () => {
    const token = jwt.sign({ userId: '42' }, secret, { issuer: legacyIssuer, expiresIn: 300 });
    await expect(validate(token)).resolves.toMatchObject({ userId: '42', isMachine: false });
  });

  it('never replaces a machine token scope with cached scopes', async () => {
    const { service, cache } = strategy();
    const token = jwt.sign({ sub: 'client@clients', gty: 'client-credentials', scope: 'read:users' }, privateKey, { algorithm: 'RS256', keyid: 'test-key', issuer: machineIssuer, audience: 'machine-api', expiresIn: 300 });
    const user = await service.validate({ headers: { authorization: `Bearer ${token}` } } as Request);
    expect(user.scopes).toEqual(['read:users']);
    expect(user.isMachine).toBe(true);
    expect(user.isAdmin).toBe(false);
    expect(cache.get).not.toHaveBeenCalled();
  });

  it.each([
    { issuer: browserIssuer, audience: 'untrusted-audience', expiresIn: 300 },
    { issuer: 'https://untrusted.example.test/', audience: 'browser-client', expiresIn: 300 },
    { issuer: browserIssuer, audience: 'browser-client', expiresIn: -60 },
  ])('rejects invalid RSA claims: %j', async (claims) => {
    const token = jwt.sign({ userId: '42' }, privateKey, { ...claims, algorithm: 'RS256', keyid: 'test-key' });
    await expect(validate(token)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects a machine token addressed to the browser audience', async () => {
    const token = jwt.sign({ sub: 'client@clients', gty: 'client-credentials' }, privateKey, { algorithm: 'RS256', keyid: 'test-key', issuer: machineIssuer, audience: 'browser-client', expiresIn: 300 });
    await expect(validate(token)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects forged signatures before reading authorization data', async () => {
    const { service, cache } = strategy();
    const token = jwt.sign({ sub: '42', userId: '42' }, 'a-different-signing-secret', { issuer: legacyIssuer, expiresIn: 300 });
    await expect(service.validate({ headers: { authorization: `Bearer ${token}` } } as Request)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(cache.get).not.toHaveBeenCalled();
  });
});
