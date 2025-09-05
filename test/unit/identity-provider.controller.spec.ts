import { Test, TestingModule } from '@nestjs/testing';
import { Logger } from '@nestjs/common';
import { IdentityProviderController } from '../../src/api/identity-provider/identity-provider.controller';
import { IdentityProviderService } from '../../src/api/identity-provider/identity-provider.service';
import {
  IdentityProviderDto,
  IdentityProviderQueryDto,
} from '../../src/api/identity-provider/identity-provider.dto';
import { createBaseResponse } from '../../src/shared/util/responseBuilder';

describe('IdentityProviderController', () => {
  let controller: IdentityProviderController;
  let service: IdentityProviderService;

  beforeEach(async () => {
    const mockService = {
      fetchProviderInfo: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IdentityProviderController],
      providers: [
        {
          provide: IdentityProviderService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<IdentityProviderController>(
      IdentityProviderController,
    );
    service = module.get<IdentityProviderService>(IdentityProviderService);

    // Mock logger to avoid console output during tests
    jest.spyOn(Logger.prototype, 'log').mockImplementation();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('fetchProviderInfo', () => {
    it('should call service with handle parameter and return result', async () => {
      const query: IdentityProviderQueryDto = { handle: 'testuser' };
      const expectedResult: IdentityProviderDto = {
        name: 'okta',
        type: 'OIDC',
      };

      jest
        .spyOn(service, 'fetchProviderInfo')
        .mockResolvedValue(expectedResult);

      const result = await controller.fetchProviderInfo(query);

      expect(service.fetchProviderInfo).toHaveBeenCalledWith(
        'testuser',
        undefined,
      );
      expect(result).toEqual(createBaseResponse(expectedResult));
      expect(Logger.prototype.log).toHaveBeenCalledWith(
        'fetchProviderInfo called',
      );
    });

    it('should call service with email parameter and return result', async () => {
      const query: IdentityProviderQueryDto = { email: 'user@example.com' };
      const expectedResult: IdentityProviderDto = {
        name: 'azure-ad',
        type: 'SAML',
      };

      jest
        .spyOn(service, 'fetchProviderInfo')
        .mockResolvedValue(expectedResult);

      const result = await controller.fetchProviderInfo(query);

      expect(service.fetchProviderInfo).toHaveBeenCalledWith(
        undefined,
        'user@example.com',
      );
      expect(result).toEqual(createBaseResponse(expectedResult));
      expect(Logger.prototype.log).toHaveBeenCalledWith(
        'fetchProviderInfo called',
      );
    });

    it('should call service with both handle and email parameters', async () => {
      const query: IdentityProviderQueryDto = {
        handle: 'testuser',
        email: 'user@example.com',
      };
      const expectedResult: IdentityProviderDto = {
        name: 'ldap',
        type: 'default',
      };

      jest
        .spyOn(service, 'fetchProviderInfo')
        .mockResolvedValue(expectedResult);

      const result = await controller.fetchProviderInfo(query);

      expect(service.fetchProviderInfo).toHaveBeenCalledWith(
        'testuser',
        'user@example.com',
      );
      expect(result).toEqual(createBaseResponse(expectedResult));
    });

    it('should call service with empty query parameters', async () => {
      const query: IdentityProviderQueryDto = {};
      const expectedResult: IdentityProviderDto = {
        name: 'ldap',
        type: 'default',
      };

      jest
        .spyOn(service, 'fetchProviderInfo')
        .mockResolvedValue(expectedResult);

      const result = await controller.fetchProviderInfo(query);

      expect(service.fetchProviderInfo).toHaveBeenCalledWith(
        undefined,
        undefined,
      );
      expect(result).toEqual(createBaseResponse(expectedResult));
    });

    it('should propagate service errors', async () => {
      const query: IdentityProviderQueryDto = { handle: 'testuser' };
      const error = new Error('Service error');

      jest.spyOn(service, 'fetchProviderInfo').mockRejectedValue(error);

      await expect(controller.fetchProviderInfo(query)).rejects.toThrow(
        'Service error',
      );
      expect(service.fetchProviderInfo).toHaveBeenCalledWith(
        'testuser',
        undefined,
      );
    });
  });
});
