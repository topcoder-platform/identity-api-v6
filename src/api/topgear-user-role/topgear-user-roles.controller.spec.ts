import { Test, TestingModule } from '@nestjs/testing';
import { TopgearUserRolesController } from './topgear-user-roles.controller';
import { UserRolesService } from '../user-role/user-roles.service';
import { RoleResponseDto } from '../../dto/role/role.dto';
import { ForbiddenException } from '@nestjs/common';

const mockUserRolesService = () => ({
  getUserRoles: jest.fn(),
  getRoleForUser: jest.fn(),
  assignRoleToUser: jest.fn(),
  removeRoleFromUser: jest.fn(),
});

describe('TopgearUserRolesController', () => {
  let controller: TopgearUserRolesController;
  const serviceMock = mockUserRolesService();

  beforeEach(async () => {
    jest.clearAllMocks();
    Object.values(serviceMock).forEach((fn) => fn.mockReset());

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TopgearUserRolesController],
      providers: [{ provide: UserRolesService, useValue: serviceMock }],
    }).compile();

    controller = module.get<TopgearUserRolesController>(
      TopgearUserRolesController,
    );
  });

  const createRequest = (userOverrides: Partial<any> = {}) => ({
    authUser: { isAdmin: false, scope: '', userId: 999, ...userOverrides },
  });

  describe('listTopgearUserRoles', () => {
    it('delegates to service with topgear requirement for admins', async () => {
      const dto = new RoleResponseDto();
      dto.id = 1;
      dto.roleName = 'Admin';
      dto.createdAt = new Date().toISOString();
      dto.createdBy = 1;
      dto.updatedAt = new Date().toISOString();
      dto.updatedBy = 1;

      serviceMock.getUserRoles.mockResolvedValue([dto]);
      const req = createRequest({ isAdmin: true });

      const result = await controller.listTopgearUserRoles(
        'topgear',
        req as any,
      );

      expect(serviceMock.getUserRoles).toHaveBeenCalledWith('topgear', {
        requireTopgear: true,
      });
      expect(result).toEqual([dto]);
    });

    it('allows call when token has read scope', async () => {
      serviceMock.getUserRoles.mockResolvedValue([]);
      const req = createRequest({ scope: 'read:topgear-user-roles' });

      await controller.listTopgearUserRoles('topgear', req as any);

      expect(serviceMock.getUserRoles).toHaveBeenCalledWith('topgear', {
        requireTopgear: true,
      });
    });

    it('throws when missing admin role or scope', async () => {
      const req = createRequest();

      await expect(
        controller.listTopgearUserRoles('topgear', req as any),
      ).rejects.toThrow(ForbiddenException);
      expect(serviceMock.getUserRoles).not.toHaveBeenCalled();
    });
  });

  describe('assignTopgearRole', () => {
    it('passes operator id and topgear requirement', async () => {
      const dto = new RoleResponseDto();
      dto.id = 2;
      dto.roleName = 'Member';
      dto.createdAt = new Date().toISOString();
      dto.createdBy = 1;
      dto.updatedAt = new Date().toISOString();
      dto.updatedBy = 1;
      serviceMock.assignRoleToUser.mockResolvedValue(dto);

      const req = createRequest({
        scope: 'write:topgear-user-roles',
        userId: 1234,
      });

      const result = await controller.assignTopgearRole(
        'topgear',
        { roleId: 42 },
        req as any,
      );

      expect(serviceMock.assignRoleToUser).toHaveBeenCalledWith(
        'topgear',
        42,
        1234,
        { requireTopgear: true },
      );
      expect(result).toBe(dto);
    });
  });

  describe('removeTopgearRole', () => {
    it('requires write scope for deletion', async () => {
      const req = createRequest({ scope: 'write:topgear-user-roles' });

      await controller.removeTopgearRole('topgear', 12, req as any);

      expect(serviceMock.removeRoleFromUser).toHaveBeenCalledWith(
        'topgear',
        12,
        { requireTopgear: true },
      );
    });
  });
});
