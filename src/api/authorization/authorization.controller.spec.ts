import { Test, TestingModule } from '@nestjs/testing';
import { AuthorizationController } from './authorization.controller';
import { AuthorizationService } from './authorization.service';
import { Request, Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { AuthorizationCreateRequest, AuthorizationForm, AuthorizationResponse, GetTokenQueryDto, ValidateClientQueryDto } from '../../dto/authorization/authorization.dto';

describe('AuthorizationController', () => {
  let controller: AuthorizationController;
  let mockService: jest.Mocked<Partial<AuthorizationService>>;

  const mockRequest = {
    headers: {},
  } as Request;

  const mockResponse = {
    redirect: jest.fn().mockReturnThis(),
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
  } as unknown as Response;

  beforeEach(async () => {
    mockService = {
      loginRedirect: jest.fn(),
      getTokenByAuthorizationCode: jest.fn(),
      createObject: jest.fn(),
      createObjectForm: jest.fn(),
      deleteObject: jest.fn(),
      getObject: jest.fn(),
      validateClient: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthorizationController],
      providers: [
        {
          provide: AuthorizationService,
          useValue: mockService,
        },
      ],
    })
      .overrideGuard(AuthGuard('jwt'))
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AuthorizationController>(AuthorizationController);
  });

  describe('loginRedirect', () => {
    it('should call service.loginRedirect with correct parameters', async () => {
      const nextParam = 'http://test.com';
      await controller.loginRedirect(mockRequest, mockResponse, nextParam);
      expect(mockService.loginRedirect).toHaveBeenCalledWith(mockRequest, mockResponse, nextParam);
    });

    it('should call service.loginRedirect without nextParam when not provided', async () => {
      await controller.loginRedirect(mockRequest, mockResponse);
      expect(mockService.loginRedirect).toHaveBeenCalledWith(mockRequest, mockResponse, undefined);
    });
  });

  describe('getTokenByAuthorizationCode', () => {
    it('should call service.getTokenByAuthorizationCode with correct parameters', async () => {
      const dto = new GetTokenQueryDto();
      await controller.getTokenByAuthorizationCode(mockRequest, mockResponse, dto);
      expect(mockService.getTokenByAuthorizationCode).toHaveBeenCalledWith(mockRequest, mockResponse, dto);
    });
  });

  describe('createObject', () => {
    it('should call handleCreateForm for form-urlencoded content type', async () => {
      const formData: AuthorizationForm = {
        clientId: 'xyz',
        secret: 'xyz'
      };
      mockRequest.headers['content-type'] = 'application/x-www-form-urlencoded';
      mockService.createObjectForm.mockResolvedValue({} as AuthorizationResponse);

      await controller.createObject(mockRequest, mockResponse, formData);
      expect(mockService.createObjectForm).toHaveBeenCalledWith(formData);
    });

    it('should call handleCreateRequest for json content type', async () => {
      const requestData: AuthorizationCreateRequest = {
        param: {
          id: '123',
          token: 'test-token',
          refreshToken: 'refresh-token',
          target: '1',
          externalToken: 'external-token'
        },
      };
      mockRequest.headers['content-type'] = 'application/json';
      mockService.createObject.mockResolvedValue({} as AuthorizationResponse);

      await controller.createObject(mockRequest, mockResponse, requestData);
      expect(mockService.createObject).toHaveBeenCalledWith(mockRequest, mockResponse, requestData.param);
    });

    it('should default to handleCreateRequest when content-type is not specified', async () => {
      const requestData: AuthorizationCreateRequest = {
        param: {
          id: '123',
          token: 'test-token',
          refreshToken: 'refresh-token',
          target: '1',
          externalToken: 'external-token'
        },
      };
      mockRequest.headers['content-type'] = undefined;
      mockService.createObject.mockResolvedValue({} as AuthorizationResponse);

      await controller.createObject(mockRequest, mockResponse, requestData);
      expect(mockService.createObject).toHaveBeenCalledWith(mockRequest, mockResponse, requestData.param);
    });
  });

  describe('deleteObject', () => {
    it('should call service.deleteObject with targetId', async () => {
      const targetId = '123';
      await controller.deleteObject(targetId, mockRequest, mockResponse);
      expect(mockService.deleteObject).toHaveBeenCalledWith(targetId, mockRequest, mockResponse);
    });
  });

  describe('deleteToken', () => {
    it('should call service.deleteObject with default targetId', async () => {
      await controller.deleteToken(mockRequest, mockResponse);
      expect(mockService.deleteObject).toHaveBeenCalledWith('1', mockRequest, mockResponse);
    });
  });

  describe('getObject', () => {
    it('should call service.getObject with correct parameters', async () => {
      const targetId = '123';
      const fields = 'id,name';
      mockService.getObject.mockResolvedValue({} as AuthorizationResponse);

      await controller.getObject(mockRequest, mockResponse, targetId, fields);
      expect(mockService.getObject).toHaveBeenCalledWith(targetId, mockRequest, mockResponse, fields);
    });

    it('should call service.getObject without fields when not provided', async () => {
      const targetId = '123';
      mockService.getObject.mockResolvedValue({} as AuthorizationResponse);

      await controller.getObject(mockRequest, mockResponse, targetId);
      expect(mockService.getObject).toHaveBeenCalledWith(targetId, mockRequest, mockResponse, undefined);
    });
  });

  describe('validateClient', () => {
    it('should call service.validateClient with correct parameters', async () => {
      const dto = new ValidateClientQueryDto();
      mockService.validateClient.mockResolvedValue('Valid client');

      const result = await controller.validateClient(dto);
      expect(mockService.validateClient).toHaveBeenCalledWith(dto);
      expect(result).toBe('Valid client');
    });
  });
});
