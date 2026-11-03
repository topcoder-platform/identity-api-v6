import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AccessTokenJwksController } from './access-token-jwks.controller';
import { AccessTokenSigner } from './access-token-signer.service';

describe('public access-token keys', () => {
  it('serves public JWKS without bearer authentication and without a signing route', async () => {
    const publicKeys = {
      keys: [
        {
          kty: 'RSA',
          n: 'public-modulus',
          e: 'AQAB',
          kid: 'key',
          alg: 'RS256',
          use: 'sig',
        },
      ],
    };
    const module = await Test.createTestingModule({
      controllers: [AccessTokenJwksController],
      providers: [
        { provide: AccessTokenSigner, useValue: { getJwks: () => publicKeys } },
      ],
    }).compile();
    const app = module.createNestApplication();
    app.setGlobalPrefix('v6');
    await app.init();
    try {
      const response = await request(app.getHttpServer())
        .get('/v6/authorizations/.well-known/jwks.json')
        .expect(200);
      expect(response.body).toEqual(publicKeys);
      expect(response.headers['cache-control']).toBe('public, max-age=300');
      await request(app.getHttpServer())
        .post('/v6/authorizations/.well-known/jwks.json')
        .send({ roles: ['administrator'] })
        .expect(404);
    } finally {
      await app.close();
    }
  });
});
