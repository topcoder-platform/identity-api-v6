import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  BadRequestException,
  ForbiddenException,
  HttpStatus,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';

import { MemberStatus } from '../../dto/member';
import { EventService } from '../../shared/event/event.service';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { EmailChangeService } from './email-change.service';
import { UserService } from './user.service';
import { ValidationService } from './validation.service';

describe('EmailChangeService', () => {
  let service: EmailChangeService;
  const cache = new Map<string, unknown>();
  const cacheManager = {
    del: jest.fn(async (key: string) => {
      cache.delete(key);
    }),
    get: jest.fn(async (key: string) => cache.get(key)),
    set: jest.fn(async (key: string, value: unknown) => {
      cache.set(key, value);
    }),
  };
  const eventService = {
    postDirectBusMessage: jest.fn().mockResolvedValue(undefined),
  };
  const prismaClient = {
    email: {
      findFirst: jest.fn().mockResolvedValue({
        address: 'old@example.com',
      }),
    },
    user: {
      findUnique: jest.fn().mockImplementation(({ select }) =>
        Promise.resolve({
          first_name: 'Justin',
          handle: 'memberHandle',
          last_name: 'Gasper',
          ...(select?.status && { status: MemberStatus.ACTIVE }),
        }),
      ),
    },
  };
  const userService = {
    updatePrimaryEmail: jest.fn().mockResolvedValue({}),
  };
  const validationService = {
    validateEmail: jest.fn().mockResolvedValue(undefined),
  };
  const configService = {
    get: jest.fn((key: string) => {
      const values: Record<string, string> = {
        APP_DOMAIN: 'topcoder-dev.com',
        EMAIL_CHANGE_OTP_EXPIRY_SECONDS: '600',
        EMAIL_CHANGE_OTP_RESEND_SECONDS: '60',
        EMAIL_CHANGE_PROOF_EXPIRY_SECONDS: '600',
        EMAIL_CHANGE_VALIDATION_EXPIRY_SECONDS: '3600',
        JWT_SECRET: 'email-change-test-secret',
      };
      return values[key];
    }),
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    cache.clear();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EmailChangeService,
        { provide: CACHE_MANAGER, useValue: cacheManager },
        { provide: ConfigService, useValue: configService },
        { provide: EventService, useValue: eventService },
        { provide: PRISMA_CLIENT, useValue: prismaClient },
        { provide: UserService, useValue: userService },
        { provide: ValidationService, useValue: validationService },
      ],
    }).compile();

    service = module.get(EmailChangeService);
  });

  it('verifies the old address before validating and applying the new one', async () => {
    await expect(service.sendCurrentEmailOtp('2')).resolves.toEqual({
      expiresIn: 600,
    });

    const otpEmailPayload = eventService.postDirectBusMessage.mock.calls[0][1];
    const otp = otpEmailPayload.data.otp;
    expect(otp).toMatch(/^\d{6}$/);
    expect(otpEmailPayload).toEqual({
      data: {
        name: 'Justin Gasper',
        otp,
      },
      from: {
        email: 'noreply@topcoder-dev.com',
        name: 'Topcoder',
      },
      recipients: ['old@example.com'],
      sendgrid_template_id: 'd-2d0ab9f6c9cc4efba50080668a9c35c1',
      version: 'v3',
    });

    const proof = await service.verifyCurrentEmailOtp('2', otp);
    expect(proof.verificationToken).toEqual(expect.any(String));

    await expect(
      service.initiateEmailChange(
        '2',
        ' New@Example.com ',
        proof.verificationToken,
      ),
    ).resolves.toEqual({ email: 'new@example.com' });

    const validationCall = eventService.postDirectBusMessage.mock.calls[1];
    expect(validationCall[0]).toBe(
      'member.action.email.profile.emailchange.verification',
    );
    expect(validationCall[1].recipients).toEqual(['new@example.com']);
    const validationUrl = new URL(
      validationCall[1].data.verificationAgreeUrl,
    );
    const validationCode = validationUrl.searchParams.get('code');
    expect(validationUrl.pathname).toBe(
      '/account-settings/email-change/verify',
    );
    expect(validationCode).toEqual(expect.any(String));
    expect(validationUrl.searchParams.has('token')).toBe(false);

    await expect(
      service.completeEmailChange(validationCode as string),
    ).resolves.toEqual({ email: 'new@example.com' });
    expect(userService.updatePrimaryEmail).toHaveBeenCalledWith(
      '2',
      'new@example.com',
      expect.objectContaining({ userId: '2' }),
    );
  });

  it('rejects an incorrect current-email OTP', async () => {
    await service.sendCurrentEmailOtp('2');

    await expect(service.verifyCurrentEmailOtp('2', '999999')).rejects.toThrow(
      BadRequestException,
    );
    expect(userService.updatePrimaryEmail).not.toHaveBeenCalled();
  });

  it('rate limits repeated ownership-code requests', async () => {
    await service.sendCurrentEmailOtp('2');

    await expect(service.sendCurrentEmailOtp('2')).rejects.toMatchObject({
      status: HttpStatus.TOO_MANY_REQUESTS,
    });
    expect(eventService.postDirectBusMessage).toHaveBeenCalledTimes(1);
  });

  it('rejects validation if the primary email changed while pending', async () => {
    await service.sendCurrentEmailOtp('2');
    const otp = eventService.postDirectBusMessage.mock.calls[0][1].data.otp;
    const proof = await service.verifyCurrentEmailOtp('2', otp);
    await service.initiateEmailChange(
      '2',
      'new@example.com',
      proof.verificationToken,
    );
    const validationUrl = new URL(
      eventService.postDirectBusMessage.mock.calls[1][1].data
        .verificationAgreeUrl,
    );
    prismaClient.email.findFirst.mockResolvedValueOnce({
      address: 'changed@example.com',
    });

    await expect(
      service.completeEmailChange(
        validationUrl.searchParams.get('code') as string,
      ),
    ).rejects.toThrow(ForbiddenException);
    expect(userService.updatePrimaryEmail).not.toHaveBeenCalled();
  });
});
