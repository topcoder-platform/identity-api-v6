import { BadRequestException, ValidationPipe } from '@nestjs/common';
import { CreateUserBodyDto } from './user.dto';

describe('Auth0 social registration payloads', () => {
  const pipe = new ValidationPipe({
    whitelist: true,
    transform: true,
    transformOptions: { enableImplicitConversion: true },
  });

  /**
   * Validates an Auth0 registration body using the application's HTTP pipe.
   * @param profile External profile fields submitted by the Auth0 action.
   * @returns The registration DTO passed to the user controller.
   * @throws BadRequestException when the request fails DTO validation.
   */
  async function transformRegistration(
    profile: Record<string, unknown>,
  ): Promise<CreateUserBodyDto> {
    return pipe.transform(
      {
        param: {
          handle: 'socialuser',
          firstName: 'Social',
          lastName: 'User',
          email: 'socialuser@example.com',
          status: 'A',
          country: {
            code: 'United States',
            isoAlpha2Code: 'US',
            isoAlpha3Code: 'USA',
          },
          regSource: 'gigs',
          profile: {
            userId: '123456',
            name: 'Social User',
            email: 'socialuser@example.com',
            context: { handle: 'socialuser', auth0UserId: 'github|123456' },
            ...profile,
          },
        },
        options: { afterActivationURL: 'https://www.topcoder.com' },
      },
      { type: 'body', metatype: CreateUserBodyDto },
    );
  }

  describe.each(['github', 'google-oauth2'])('%s', (providerType) => {
    it.each([true, false, undefined])(
      'accepts the legacy profile with emailVerified=%s',
      async (emailVerified) => {
        const result = await transformRegistration({
          providerType,
          emailVerified,
        });

        expect(result.param.profile).toMatchObject({
          provider: providerType,
          userId: '123456',
          isEmailVerified: emailVerified ?? false,
        });
        expect(result.param.profile).not.toHaveProperty('emailVerified');
        expect(result).not.toHaveProperty('options');
      },
    );
  });

  it('preserves canonical fields when legacy fields are also supplied', async () => {
    const result = await transformRegistration({
      provider: 'github',
      providerType: 'google-oauth2',
      isEmailVerified: false,
      emailVerified: true,
    });

    expect(result.param.profile).toMatchObject({
      provider: 'github',
      isEmailVerified: false,
    });
  });

  it.each([true, false])(
    'preserves canonical profiles with isEmailVerified=%s',
    async (isEmailVerified) => {
      const result = await transformRegistration({
        provider: 'github',
        providerType: 'social',
        isEmailVerified,
      });

      expect(result.param.profile).toMatchObject({
        provider: 'github',
        isEmailVerified,
      });
    },
  );

  it('keeps enterprise provider names distinct from provider types', async () => {
    const result = await transformRegistration({
      provider: 'wipro-adfs',
      providerType: 'samlp',
    });

    expect(result.param.profile.provider).toBe('wipro-adfs');
  });

  it('still rejects profiles without a provider', async () => {
    await expect(transformRegistration({})).rejects.toThrow(
      BadRequestException,
    );
  });

  it.each(['userId', 'name'])(
    'still rejects legacy profiles without %s',
    async (field) => {
      await expect(
        transformRegistration({ providerType: 'github', [field]: '' }),
      ).rejects.toThrow(BadRequestException);
    },
  );

  it('still rejects a non-boolean legacy email verification flag', async () => {
    await expect(
      transformRegistration({
        providerType: 'github',
        emailVerified: 'false',
      }),
    ).rejects.toThrow(BadRequestException);
  });
});
