import { createServer, IncomingMessage, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { Logger } from '@nestjs/common';
import { MemberApiModule } from './member-api.module';
import { MemberApiService } from './member-api.service';
import { M2M_AUTH_CLIENT } from './member-api.constants';

/** Synthetic Keycloak settings (the real Keycloak HTTP path is covered by test/keycloak.test.cjs). */
const keycloakConfig = {
  KEYCLOAK_ISSUER: 'https://keycloak.example.test/realms/m2m',
  KEYCLOAK_AUDIENCE: 'https://api.example.test',
  KEYCLOAK_TOKEN_URL: 'https://keycloak.example.test/m2m/token',
  KEYCLOAK_CLIENT_ID: 'm2m-identity',
  KEYCLOAK_CLIENT_SECRET: 'keycloak-secret',
  ALLOW_LEGACY_USER_AUDIENCE: 'true',
};

/** Build a ConfigService stand-in that reads the given map, honouring fallbacks. */
function configOf(values: Record<string, string | undefined>) {
  return {
    get: jest.fn(
      (key: string, fallback?: unknown) => values[key] ?? fallback,
    ),
  };
}

/** Return the M2M provider factory registered by MemberApiModule. */
function m2mFactory(): (config: unknown) => {
  getMachineToken(): Promise<string>;
} {
  const providers = Reflect.getMetadata('providers', MemberApiModule) as {
    provide?: unknown;
    useFactory?: (config: unknown) => { getMachineToken(): Promise<string> };
  }[];
  return providers.find((provider) => provider.provide === M2M_AUTH_CLIENT)!
    .useFactory!;
}

describe('MemberApiModule M2M provider (USE_KEYCLOAK)', () => {
  let server: Server | undefined;

  afterEach(async () => {
    jest.restoreAllMocks();
    if (server) await new Promise((resolve) => server!.close(resolve));
    server = undefined;
  });

  it('requests Auth0 tokens with the AUTH0_* settings when USE_KEYCLOAK=false', async () => {
    const requests: { url?: string; body: Record<string, string> }[] = [];
    server = createServer((req: IncomingMessage, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        requests.push({ url: req.url, body: JSON.parse(body) });
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ access_token: 'auth0-token' }));
      });
    });
    await new Promise<void>((resolve) =>
      server!.listen(0, '127.0.0.1', resolve),
    );
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const client = m2mFactory()(
      configOf({
        ...keycloakConfig,
        USE_KEYCLOAK: 'false',
        AUTH0_URL: `${base}/oauth/token`,
        AUTH0_AUDIENCE: 'https://m2m.example/',
        AUTH0_PROXY_SERVER_URL: `${base}/proxy`,
        AUTH0_CLIENT_ID: 'auth0-identity',
        AUTH0_CLIENT_SECRET: 'auth0-secret',
      }),
    );

    await expect(client.getMachineToken()).resolves.toBe('auth0-token');
    expect(requests).toEqual([
      {
        url: '/proxy',
        body: {
          grant_type: 'client_credentials',
          client_id: 'auth0-identity',
          client_secret: 'auth0-secret',
          auth0_url: `${base}/oauth/token`,
          audience: 'https://m2m.example/',
        },
      },
    ]);
  });

  it('defaults to Auth0 credentials when USE_KEYCLOAK is unset', async () => {
    const client = m2mFactory()(
      configOf({ ...keycloakConfig, AUTH0_URL: 'https://tenant.example' }),
    );
    await expect(client.getMachineToken()).rejects.toThrow(
      'AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET are required',
    );
  });

  it('uses only the Keycloak credentials when USE_KEYCLOAK=true', async () => {
    const client = m2mFactory()(
      configOf({
        ...keycloakConfig,
        USE_KEYCLOAK: 'true',
        KEYCLOAK_CLIENT_ID: undefined,
        AUTH0_CLIENT_ID: 'auth0-identity',
        AUTH0_CLIENT_SECRET: 'auth0-secret',
      }),
    );
    await expect(client.getMachineToken()).rejects.toThrow(
      'KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET are required',
    );
  });

  it('names the active provider when a token cannot be obtained', async () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    const failing = { getMachineToken: jest.fn().mockRejectedValue(new Error('x')) };
    for (const [useKeycloak, name] of [
      ['true', 'Keycloak'],
      ['false', 'Auth0'],
    ]) {
      const service = new MemberApiService(
        configOf({ MEMBER_API_URL: 'https://members.example', USE_KEYCLOAK: useKeycloak }) as never,
        {} as never,
        failing,
      );
      await expect(
        (service as unknown as { getM2mToken(): Promise<string | null> }).getM2mToken(),
      ).resolves.toBeNull();
      expect(error).toHaveBeenLastCalledWith(`${name} service authentication failed`);
    }
  });
});
