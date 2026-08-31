import { BadRequestException } from '@nestjs/common';

import { UserController } from './user.controller';

describe('UserController email-change validation', () => {
  const emailChangeService = {
    completeEmailChange: jest.fn(),
  };
  let controller: UserController;

  beforeEach(() => {
    jest.clearAllMocks();
    controller = Object.create(UserController.prototype) as UserController;
    Object.assign(controller, { emailChangeService });
  });

  it('passes the email-link code to the email change service', async () => {
    emailChangeService.completeEmailChange.mockResolvedValue({
      email: 'new@example.com',
    });

    await expect(
      controller.completeEmailChange('validation-code'),
    ).resolves.toEqual({ email: 'new@example.com' });
    expect(emailChangeService.completeEmailChange).toHaveBeenCalledWith(
      'validation-code',
    );
  });

  it('accepts the legacy token query parameter', async () => {
    emailChangeService.completeEmailChange.mockResolvedValue({
      email: 'new@example.com',
    });

    await expect(
      controller.completeEmailChange(undefined, 'legacy-token'),
    ).resolves.toEqual({ email: 'new@example.com' });
    expect(emailChangeService.completeEmailChange).toHaveBeenCalledWith(
      'legacy-token',
    );
  });

  it('rejects a validation request without a code', async () => {
    await expect(controller.completeEmailChange()).rejects.toThrow(
      BadRequestException,
    );
    expect(emailChangeService.completeEmailChange).not.toHaveBeenCalled();
  });
});
