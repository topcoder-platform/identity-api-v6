import { Test, TestingModule } from '@nestjs/testing';
import { UserRolesService } from './user-roles.service';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { RoleService } from '../role/role.service';
import { RoleResponseDto } from '../../dto/role/role.dto';
import { NotFoundException } from '@nestjs/common';

const createMockPrisma = () => ({
  user: {
    findFirst: jest.fn(),
    findUnique: jest.fn(),
  },
  roleAssignment: {
    findMany: jest.fn(),
  },
});

const createMockRoleService = () => ({
  checkSubjectHasRole: jest.fn(),
  assignRoleToSubject: jest.fn(),
  deassignRoleFromSubject: jest.fn(),
});

describe('UserRolesService', () => {
  let service: UserRolesService;
  const mockPrisma = createMockPrisma();
  const mockRoleService = createMockRoleService();

  beforeEach(async () => {
    jest.clearAllMocks();
    Object.values(mockPrisma.user).forEach((fn) => fn.mockReset());
    Object.values(mockPrisma.roleAssignment).forEach((fn) => fn.mockReset());
    Object.values(mockRoleService).forEach((fn) => fn.mockReset?.());
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserRolesService,
        { provide: PRISMA_CLIENT, useValue: mockPrisma },
        { provide: RoleService, useValue: mockRoleService },
      ],
    }).compile();

    service = module.get<UserRolesService>(UserRolesService);
  });

  describe('getUserRoles', () => {
    it('returns mapped roles for resolved handle', async () => {
      mockPrisma.user.findFirst.mockResolvedValue({
        user_id: 123,
        handle: 'Handle',
      });
      mockPrisma.roleAssignment.findMany.mockResolvedValue([
        {
          role: {
            id: 1,
            name: 'Admin',
            createdAt: new Date('2024-01-01T00:00:00.000Z'),
            createdBy: 1,
            modifiedAt: new Date('2024-01-02T00:00:00.000Z'),
            modifiedBy: 2,
          },
        },
      ]);

      const roles = await service.getUserRoles('Handle');

      expect(mockPrisma.user.findFirst).toHaveBeenCalled();
      expect(mockPrisma.roleAssignment.findMany).toHaveBeenCalledWith({
        where: { subjectId: 123, subjectType: 1 },
        include: { role: true },
        orderBy: { role: { name: 'asc' } },
      });
      expect(roles).toHaveLength(1);
      expect(roles[0].roleName).toBe('Admin');
    });

    it('falls back to lookup by numeric id when handle lookup fails', async () => {
      mockPrisma.user.findFirst.mockResolvedValue(null);
      mockPrisma.user.findUnique.mockResolvedValue({
        user_id: 456,
        handle: 'numericUser',
      });
      mockPrisma.roleAssignment.findMany.mockResolvedValue([]);

      const roles = await service.getUserRoles('456');

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { user_id: 456 },
        select: { user_id: true, handle: true },
      });
      expect(roles).toEqual([]);
    });
  });

  describe('getRoleForUser', () => {
    it('returns role when assigned', async () => {
      const dto = new RoleResponseDto();
      dto.id = 2;
      dto.roleName = 'Member';
      dto.createdAt = new Date().toISOString();
      dto.createdBy = 1;
      dto.updatedAt = new Date().toISOString();
      dto.updatedBy = 1;

      mockPrisma.user.findFirst.mockResolvedValue({
        user_id: 789,
        handle: 'foo',
      });
      mockRoleService.checkSubjectHasRole.mockResolvedValue(dto);

      const result = await service.getRoleForUser('foo', 2);

      expect(mockRoleService.checkSubjectHasRole).toHaveBeenCalledWith(2, 789);
      expect(result).toBe(dto);
    });

    it('throws when role is not assigned', async () => {
      mockPrisma.user.findFirst.mockResolvedValue({
        user_id: 789,
        handle: 'foo',
      });
      mockRoleService.checkSubjectHasRole.mockResolvedValue(null);

      await expect(service.getRoleForUser('foo', 1)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('assignRoleToUser', () => {
    it('assigns role and returns updated dto', async () => {
      const dto = new RoleResponseDto();
      dto.id = 3;
      dto.roleName = 'Manager';
      dto.createdAt = new Date().toISOString();
      dto.createdBy = 1;
      dto.updatedAt = new Date().toISOString();
      dto.updatedBy = 1;

      mockPrisma.user.findFirst.mockResolvedValue({
        user_id: 1001,
        handle: 'userA',
      });
      mockRoleService.checkSubjectHasRole.mockResolvedValue(dto);

      const result = await service.assignRoleToUser('userA', 3, 999);

      expect(mockRoleService.assignRoleToSubject).toHaveBeenCalledWith(
        3,
        1001,
        999,
      );
      expect(result).toBe(dto);
    });

    it('falls back to user id when operator is not provided', async () => {
      const dto = new RoleResponseDto();
      dto.id = 4;
      dto.roleName = 'Observer';
      dto.createdAt = new Date().toISOString();
      dto.createdBy = 1;
      dto.updatedAt = new Date().toISOString();
      dto.updatedBy = 1;

      mockPrisma.user.findFirst.mockResolvedValue({
        user_id: 1010,
        handle: 'userD',
      });
      mockRoleService.checkSubjectHasRole.mockResolvedValue(dto);

      await service.assignRoleToUser('userD', 4);

      expect(mockRoleService.assignRoleToSubject).toHaveBeenCalledWith(
        4,
        1010,
        1010,
      );
    });
  });

  describe('removeRoleFromUser', () => {
    it('throws when user does not have the role', async () => {
      mockPrisma.user.findFirst.mockResolvedValue({
        user_id: 2002,
        handle: 'userB',
      });
      mockRoleService.checkSubjectHasRole.mockResolvedValue(null);

      await expect(service.removeRoleFromUser('userB', 5)).rejects.toThrow(
        NotFoundException,
      );
      expect(mockRoleService.deassignRoleFromSubject).not.toHaveBeenCalled();
    });

    it('removes role when assignment exists', async () => {
      const dto = new RoleResponseDto();
      dto.id = 6;
      dto.roleName = 'Reviewer';
      dto.createdAt = new Date().toISOString();
      dto.createdBy = 1;
      dto.updatedAt = new Date().toISOString();
      dto.updatedBy = 1;

      mockPrisma.user.findFirst.mockResolvedValue({
        user_id: 3003,
        handle: 'userC',
      });
      mockRoleService.checkSubjectHasRole.mockResolvedValue(dto);

      await service.removeRoleFromUser('userC', 6);

      expect(mockRoleService.deassignRoleFromSubject).toHaveBeenCalledWith(
        6,
        3003,
      );
    });
  });
});
