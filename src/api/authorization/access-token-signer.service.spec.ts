import { ConfigService } from '@nestjs/config';
import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import {
  constants,
  createPublicKey,
  generateKeyPairSync,
  privateEncrypt,
} from 'node:crypto';
import * as jwt from 'jsonwebtoken';
import { AccessTokenSigner } from './access-token-signer.service';
import { ConfigurationService } from '../../config/configuration.service';

const keyArn =
  'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicDer = pair.publicKey.export({ type: 'spki', format: 'der' });
const publicResult = {
  KeyId: keyArn,
  KeyUsage: 'SIGN_VERIFY',
  SigningAlgorithms: ['RSASSA_PKCS1_V1_5_SHA_256'],
  PublicKey: publicDer,
};
const common = {
  getCommon: () => ({
    authDomain: 'example.com',
    authSecret: 'legacy-test-only-secret-at-least-32-bytes',
  }),
} as ConfigurationService;
const settings = {
  ACCESS_TOKEN_SIGNING_ALGORITHM: 'RS256',
  ACCESS_TOKEN_KMS_KEY_ARN: keyArn,
  ACCESS_TOKEN_AUDIENCE: 'https://api.example.com/v6',
  ACCESS_TOKEN_TTL_SECONDS: '900',
};
function setup(values: Record<string, string> = settings) {
  const send = jest.fn((command: GetPublicKeyCommand | SignCommand) => {
    if (command instanceof GetPublicKeyCommand)
      return Promise.resolve(publicResult);
    const input = command.input;
    expect(input.MessageType).toBe('DIGEST');
    expect(input.KeyId).toBe(keyArn);
    expect(input.SigningAlgorithm).toBe('RSASSA_PKCS1_V1_5_SHA_256');
    expect(input.Message?.length).toBe(32);
    // Reproduce KMS RSA PKCS#1 v1.5 signing of an already-hashed SHA256 digest.
    const digestInfo = Buffer.concat([
      Buffer.from('3031300d060960864801650304020105000420', 'hex'),
      Buffer.from(input.Message),
    ]);
    return Promise.resolve({
      KeyId: keyArn,
      SigningAlgorithm: input.SigningAlgorithm,
      Signature: privateEncrypt(
        { key: pair.privateKey, padding: constants.RSA_PKCS1_PADDING },
        digestInfo,
      ),
    });
  });
  const config = { get: (name: string) => values[name] } as ConfigService;
  const signer = new AccessTokenSigner(common, config, {
    send,
  } as unknown as KMSClient);
  return { signer, send };
}

describe('isolated access-token signing', () => {
  it('signs server-bound claims with RS256 and publishes only the matching public key', async () => {
    const { signer, send } = setup();
    await signer.onModuleInit();
    const token = await signer.sign({
      userId: '42',
      roles: ['member'],
      iss: 'attacker',
      aud: 'wrong',
      exp: 1,
      sub: 'manual',
    });
    const key = signer.getJwks().keys[0];
    expect(Object.keys(key).sort()).toEqual([
      'alg',
      'e',
      'kid',
      'kty',
      'n',
      'use',
    ]);
    const verified = jwt.verify(
      token,
      createPublicKey({ key, format: 'jwk' }),
      {
        algorithms: ['RS256'],
        issuer: 'https://api.example.com',
        audience: settings.ACCESS_TOKEN_AUDIENCE,
      },
    ) as jwt.JwtPayload;
    expect(verified.sub).toBe('topcoder|42');
    expect(verified.userId).toBe('42');
    expect(verified.roles).toEqual(['member']);
    expect(verified.exp! - verified.iat!).toBe(900);
    expect(verified.jti).toBeTruthy();
    expect(jwt.decode(token, { complete: true })?.header.kid).toBe(keyArn);
    expect(send).toHaveBeenCalledTimes(2);
    signer.getJwks().keys[0].kid = 'tampered';
    expect(signer.getJwks().keys[0].kid).toBe(keyArn);
  });

  it('never falls back to the shared secret after signing fails', async () => {
    const { signer, send } = setup();
    await signer.onModuleInit();
    send.mockRejectedValueOnce(new Error('KMS unavailable'));
    await expect(signer.sign({ userId: '42' })).rejects.toThrow(
      'KMS unavailable',
    );
  });

  it('rejects unexpected key metadata before serving traffic', async () => {
    const { signer, send } = setup();
    send.mockResolvedValueOnce({
      ...publicResult,
      KeyUsage: 'ENCRYPT_DECRYPT',
    });
    await expect(signer.onModuleInit()).rejects.toThrow(
      'Invalid access-token KMS key',
    );
  });

  it('requires immutable key identity, audience and bounded lifetime', () => {
    for (const patch of [
      { ACCESS_TOKEN_KMS_KEY_ARN: '' },
      { ACCESS_TOKEN_KMS_KEY_ARN: 'alias/current' },
      { ACCESS_TOKEN_AUDIENCE: '' },
      { ACCESS_TOKEN_TTL_SECONDS: '86401' },
      { ACCESS_TOKEN_SIGNING_ALGORITHM: 'none' },
    ]) {
      expect(() => setup({ ...settings, ...patch })).toThrow();
    }
  });

  it('can publish public keys before switching the legacy issuer', async () => {
    const { signer, send } = setup({
      ...settings,
      ACCESS_TOKEN_SIGNING_ALGORITHM: 'HS256',
    });
    await signer.onModuleInit();
    expect(signer.getJwks().keys).toHaveLength(1);
    const token = await signer.sign({
      userId: '42',
      iss: 'https://api.example.com',
      exp: Math.floor(Date.now() / 1000) + 300,
    });
    expect(
      jwt.verify(token, common.getCommon().authSecret, {
        algorithms: ['HS256'],
      }),
    ).toMatchObject({ userId: '42' });
    expect(send).toHaveBeenCalledTimes(1);
  });
});
