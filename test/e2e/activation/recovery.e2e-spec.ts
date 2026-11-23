import { randomUUID } from 'node:crypto';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';
import * as jwt from 'jsonwebtoken';
import { UserService } from '../../../src/api/user/user.service';
import { AuthFlowService } from '../../../src/api/user/auth-flow.service';
import { ActivationEmailWorker } from '../../../src/api/user/activation-email.worker';
import { ACTIVATION_LIFETIME_MS } from '../../../src/api/user/activation-code';

// Run on a freshly migrated identity_test2 database. Authentication proofs and
// Identity writes are real. Member, role and mail-bus calls are test doubles.
describe('Activation recovery', () => {
  const prisma = new PrismaClient();
  const config = new ConfigService({
    JWT_SECRET: randomUUID(),
    LEGACY_BLOWFISH_KEY: 'fixture',
    SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID: 'fixture-template',
  });
  const events = {
    postDirectBusMessage: jest.fn(),
    postEnvelopedNotification: jest.fn(),
  };
  const userService = new UserService(
    prisma,
    { $queryRaw: jest.fn().mockResolvedValue([]) } as any,
    {
      validateUser: jest.fn(),
      validateHandle: jest.fn().mockResolvedValue({ valid: true }),
      validateEmailViaDB: jest.fn(),
    } as any,
    { assignRoleByName: jest.fn() } as any,
    null,
    events as any,
    config,
    { member: { create: jest.fn() } } as any,
  );
  // Welcome mail and membership roles are downstream of activation.
  jest.spyOn(userService, 'notifyWelcome').mockResolvedValue(undefined);
  jest.spyOn(userService, 'assignDefaultUserRole').mockResolvedValue(undefined);
  const serviceFor = (client: PrismaClient) =>
    new AuthFlowService(
      client,
      null,
      config,
      userService as any,
      events as any,
      { findAll: jest.fn().mockResolvedValue([]) } as any,
      null,
      { member: { update: jest.fn() } } as any,
    );
  const service = serviceFor(prisma);
  const worker = () => new ActivationEmailWorker(prisma, config, events as any);
  let userId: number, email: string, handle: string;
  const where = () => ({ user_id_mode: { user_id: userId, mode: 1 } });
  const row = () => prisma.user_otp_email.findUnique({ where: where() });
  const proof = async () =>
    (await service.getUserProfileForAuth0(handle)).credential.resendToken;
  const resend = (resendToken: string) =>
    service.requestResendActivation({ userId, resendToken });
  const activate = (resendToken: string, otp: string) =>
    service.activateUser({ param: { userId, resendToken, otp } });
  const oldTime = () => new Date(Date.now() - ACTIVATION_LIFETIME_MS - 1000);

  beforeAll(async () => {
    for (const status_id of [1, 2]) {
      await prisma.email_status_lu.upsert({
        where: { status_id },
        create: { status_id },
        update: {},
      });
    }
    await prisma.email_type_lu.upsert({
      where: { email_type_id: 1 },
      create: { email_type_id: 1 },
      update: {},
    });
  });
  beforeEach(async () => {
    userId = undefined;
    events.postDirectBusMessage.mockReset().mockResolvedValue(undefined);
    handle = 'rec' + randomUUID().slice(0, 10);
    email = handle + '@example.invalid';
    const user = await userService.registerUser({
      param: {
        handle,
        email,
        credential: { password: 'SignupFixture123!' },
      },
    });
    userId = user.user_id.toNumber();
  });
  afterEach(async () => {
    if (userId === undefined) return;
    await prisma.security_user.deleteMany({ where: { user_id: handle } });
    await prisma.user_otp_email.deleteMany({ where: { user_id: userId } });
    await prisma.email.deleteMany({ where: { user_id: userId } });
    await prisma.user.delete({ where: { user_id: userId } });
  });
  afterAll(() => prisma.$disconnect());

  it('queues the registration code, preserves it on later login and rejects invalid passwords', async () => {
    const first = await row();
    expect(first.activation_sends).toHaveLength(1);
    await worker().dispatch();
    expect(events.postDirectBusMessage).toHaveBeenCalledWith(
      'external.action.email',
      expect.objectContaining({
        recipients: [email],
        data: { handle, code: first.otp },
      }),
    );
    await expect(
      service.authenticateForAuth0(handle, 'incorrect'),
    ).rejects.toMatchObject({ status: 401 });
    await expect(
      service.authenticateForAuth0(email, 'SignupFixture123!'),
    ).rejects.toMatchObject({ status: 403 });
    const profile = await service.getUserProfileForAuth0(handle);
    expect(profile.credential.activationCodeState).toBe('valid');
    expect((await row()).otp).toBe(first.otp);
    await expect(resend(profile.credential.resendToken)).rejects.toMatchObject({
      status: 429,
    });
  });

  it('recovers an expired, previously resent code and retries the same email after a bus failure', async () => {
    await prisma.user_otp_email.update({
      where: where(),
      data: {
        activation_sends: [],
        delivery_due_at: null,
        delivery_recipient: null,
        otp: '123456',
        expire_at: oldTime(),
        resend: true,
      },
    });
    const profile = await service.getUserProfileForAuth0(email);
    expect(profile.active).toBe(false);
    expect(profile.credential).toMatchObject({
      activationCodeState: 'expired',
      canResend: true,
    });
    const token = profile.credential.resendToken;
    await expect(activate(token, '123456')).rejects.toThrow('expired');
    const clicks = await Promise.allSettled([resend(token), resend(token)]);
    expect(clicks.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(clicks.find((r) => r.status === 'rejected')).toMatchObject({
      reason: { status: 429 },
    });
    const code = await row();
    expect(code.otp).not.toBe('123456');
    expect(code.activation_sends).toHaveLength(1);
    expect(code.delivery_due_at).toBeInstanceOf(Date);
    expect(
      (await service.getUserProfileForAuth0(handle)).credential
        .activationCodeState,
    ).toBe('valid');
    expect((await row()).otp).toBe(code.otp);

    events.postDirectBusMessage.mockRejectedValueOnce(
      new Error('temporary failure'),
    );
    await worker().dispatch();
    expect((await row()).delivery_due_at.getTime()).toBeGreaterThan(Date.now());
    await prisma.user_otp_email.update({
      where: where(),
      data: { delivery_due_at: new Date() },
    });
    await Promise.all([worker().dispatch(), worker().dispatch()]);
    expect(events.postDirectBusMessage).toHaveBeenCalledTimes(2);
    expect(events.postDirectBusMessage.mock.calls[0]).toEqual(
      events.postDirectBusMessage.mock.calls[1],
    );
    expect(events.postDirectBusMessage.mock.calls[1]).toEqual([
      'external.action.email',
      expect.objectContaining({
        recipients: [email],
        data: { handle, code: code.otp },
      }),
    ]);
    expect((await row()).delivery_due_at).toBeNull();
    await expect(activate(token, '123456')).rejects.toThrow(
      'Wrong activation code',
    );
    expect((await activate(token, code.otp)).status).toBe('A');
    expect(await row()).toBeNull();
    await expect(resend(token)).rejects.toThrow('activated');
    await expect(activate(token, code.otp)).rejects.toThrow('activated');
  });

  it('recovers a missing record and enforces proof scope, expiry and account status', async () => {
    await prisma.user_otp_email.delete({ where: where() });
    const profile = await service.getUserProfileForAuth0(handle);
    expect(profile.credential.activationCodeState).toBe('replacement_required');
    expect(await row()).toBeNull();
    const signed = (id: number, aud: string, expiresIn: number) =>
      jwt.sign({ sub: String(id), aud }, config.get('JWT_SECRET'), {
        expiresIn,
      });
    await expect(
      resend(signed(userId, 'emailactivation', -60)),
    ).rejects.toMatchObject({ status: 410 });
    await expect(
      resend(signed(userId + 1, 'emailactivation', 100)),
    ).rejects.toMatchObject({ status: 403 });
    await expect(resend(signed(userId, 'other', 100))).rejects.toMatchObject({
      status: 403,
    });
    expect(await row()).toBeNull();
    await resend(profile.credential.resendToken);
    await prisma.user.update({
      where: { user_id: userId },
      data: { status: 'I' },
    });
    await expect(resend(profile.credential.resendToken)).rejects.toMatchObject({
      status: 403,
    });
    await worker().dispatch();
    expect(events.postDirectBusMessage).not.toHaveBeenCalled();
  });

  it('retains failures across rotation and lets the rolling limits expire', async () => {
    const token = await proof();
    const wrong = (await row()).otp === '000000' ? '000001' : '000000';
    await Promise.allSettled([
      activate(token, wrong),
      activate(token, wrong),
      activate(token, wrong),
    ]);
    expect((await row()).fail_count).toBe(3);
    await expect(activate(token, (await row()).otp)).rejects.toThrow(
      'Too many attempts',
    );
    await prisma.user_otp_email.update({
      where: where(),
      data: { activation_sends: [oldTime()] },
    });
    await resend(token);
    expect((await row()).activation_failures).toHaveLength(3);
    expect((await row()).fail_count).toBe(0);
    const hourAgo = new Date(Date.now() - 3600000);
    await prisma.user_otp_email.update({
      where: where(),
      data: { activation_sends: Array(5).fill(hourAgo) },
    });
    await expect(resend(token)).rejects.toMatchObject({
      status: 429,
      response: {
        retryAt: new Date(+hourAgo + ACTIVATION_LIFETIME_MS).toISOString(),
      },
    });
    await prisma.user_otp_email.update({
      where: where(),
      data: {
        activation_sends: [oldTime()],
        activation_failures: Array(10).fill(hourAgo),
      },
    });
    await expect(resend(token)).rejects.toMatchObject({ status: 429 });
    await expect(activate(token, (await row()).otp)).rejects.toMatchObject({
      status: 429,
    });
    await prisma.user_otp_email.update({
      where: where(),
      data: { activation_failures: [oldTime()] },
    });
    await expect(resend(token)).resolves.toMatchObject({ message: 'SUCCESS' });
  });

  it('rolls back a replacement when persisting the email job fails', async () => {
    await prisma.user_otp_email.update({
      where: where(),
      data: {
        activation_sends: [],
        delivery_due_at: null,
        otp: '555555',
        expire_at: oldTime(),
      },
    });
    const failing = prisma.$extends({
      query: {
        user_otp_email: {
          async upsert({ args, query }) {
            await query(args);
            throw new Error('queue write failed');
          },
        },
      },
    });
    await expect(
      serviceFor(failing as unknown as PrismaClient).requestResendActivation({
        userId,
        resendToken: await proof(),
      }),
    ).rejects.toThrow('queue write failed');
    expect(await row()).toMatchObject({
      otp: '555555',
      delivery_due_at: null,
      activation_sends: [],
    });
  });
});
