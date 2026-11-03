import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import { createHash, createPublicKey, randomUUID } from 'node:crypto';
import { ConfigurationService } from '../../config/configuration.service';
import { CommonUtils } from '../../shared/util/common.utils';

export const ACCESS_TOKEN_KMS = 'ACCESS_TOKEN_KMS';
const algorithm = 'RSASSA_PKCS1_V1_5_SHA_256';
type PublicKey = {
  kty: 'RSA';
  n: string;
  e: string;
  kid: string;
  alg: 'RS256';
  use: 'sig';
};

/** Signs server-created login claims. The asymmetric private key stays in KMS. */
@Injectable()
export class AccessTokenSigner implements OnModuleInit {
  private readonly mode: string;
  private readonly keyArn?: string;
  private readonly verificationKeyArns: string[];
  private readonly audience?: string;
  private readonly ttl: number;
  private keys: PublicKey[] = [];
  private ready = false;

  constructor(
    private readonly common: ConfigurationService,
    private readonly config: ConfigService,
    @Inject(ACCESS_TOKEN_KMS) private readonly kms: KMSClient,
  ) {
    // Retained until the coordinated verifier migration is complete. Never fallback after a KMS failure.
    this.mode = config.get<string>('ACCESS_TOKEN_SIGNING_ALGORITHM') || 'HS256';
    this.keyArn = config.get<string>('ACCESS_TOKEN_KMS_KEY_ARN');
    this.audience = config.get<string>('ACCESS_TOKEN_AUDIENCE');
    this.ttl = Number(config.get<string>('ACCESS_TOKEN_TTL_SECONDS') || '900');
    this.verificationKeyArns = [
      ...new Set([
        ...(this.keyArn ? [this.keyArn] : []),
        ...(config.get<string>('ACCESS_TOKEN_VERIFICATION_KEY_ARNS') || '')
          .split(',')
          .map((v) => v.trim())
          .filter(Boolean),
      ]),
    ];
    if (!['HS256', 'RS256'].includes(this.mode))
      throw new Error('Unsupported access-token signing algorithm');
    if (!Number.isSafeInteger(this.ttl) || this.ttl < 60 || this.ttl > 86400)
      throw new Error('Access-token TTL must be between 60 and 86400 seconds');
    if (
      this.verificationKeyArns.length > 5 ||
      this.verificationKeyArns.some(
        (arn) =>
          !/^arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:key\/[a-zA-Z0-9-]+$/.test(
            arn,
          ),
      )
    )
      throw new Error('Use immutable KMS key ARNs for access-token signing');
    if (
      this.mode === 'RS256' &&
      (!this.keyArn ||
        !this.audience?.trim() ||
        !this.common.getCommon().authDomain)
    )
      throw new Error(
        'RS256 requires a KMS key, API audience and issuer domain',
      );
  }

  /** Loads only public keys before the service accepts requests. */
  async onModuleInit(): Promise<void> {
    this.keys = await Promise.all(
      this.verificationKeyArns.map(async (keyArn) => {
        const result = await this.kms.send(
          new GetPublicKeyCommand({ KeyId: keyArn }),
        );
        if (
          result.KeyId !== keyArn ||
          result.KeyUsage !== 'SIGN_VERIFY' ||
          !result.SigningAlgorithms?.includes(algorithm) ||
          !result.PublicKey
        )
          throw new Error('Invalid access-token KMS key configuration');
        const key = createPublicKey({
          key: Buffer.from(result.PublicKey),
          format: 'der',
          type: 'spki',
        });
        const jwk = key.export({ format: 'jwk' });
        if (
          key.asymmetricKeyType !== 'rsa' ||
          (key.asymmetricKeyDetails?.modulusLength || 0) < 2048 ||
          !jwk.n ||
          !jwk.e
        )
          throw new Error(
            'Access-token key must be RSA with at least 2048 bits',
          );
        return {
          kty: 'RSA' as const,
          n: jwk.n,
          e: jwk.e,
          kid: keyArn,
          alg: 'RS256' as const,
          use: 'sig' as const,
        };
      }),
    );
    this.ready = true;
  }

  /** Public verification material only; this endpoint never signs caller input. */
  getJwks(): { keys: PublicKey[] } {
    if (!this.ready) throw new Error('Access-token signer is not initialized');
    return { keys: this.keys.map((key) => ({ ...key })) };
  }

  /** Claims originate from successful login/service-account authorization and server-side role lookup. */
  async sign(claims: Record<string, unknown>): Promise<string> {
    if (this.mode === 'HS256') {
      const secret = this.common.getCommon().authSecret;
      if (!secret)
        throw new Error('Legacy access-token secret is not configured');
      return CommonUtils.generateJwt(claims, secret, { algorithm: 'HS256' });
    }
    if (!this.ready || !this.keyArn)
      throw new Error('Access-token signer is not initialized');
    if (typeof claims.userId !== 'string' && typeof claims.userId !== 'number')
      throw new Error('Access-token user ID is required');
    const id = String(claims.userId);
    if (!/^[1-9]\d{0,18}$/.test(id))
      throw new Error('Access-token user ID is required');
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      ...claims,
      sub: `topcoder|${id}`,
      iss: CommonUtils.createIssuerFor(this.common.getCommon().authDomain),
      aud: this.audience,
      iat: now,
      exp: now + this.ttl,
      jti: randomUUID(),
    };
    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value)).toString('base64url');
    const input = `${encode({ alg: 'RS256', typ: 'JWT', kid: this.keyArn })}.${encode(payload)}`;
    const result = await this.kms.send(
      new SignCommand({
        KeyId: this.keyArn,
        SigningAlgorithm: algorithm,
        MessageType: 'DIGEST',
        Message: createHash('sha256').update(input).digest(),
      }),
    );
    if (
      result.KeyId !== this.keyArn ||
      result.SigningAlgorithm !== algorithm ||
      !result.Signature?.length
    )
      throw new Error('Access-token signing failed');
    return `${input}.${Buffer.from(result.Signature).toString('base64url')}`;
  }
}
