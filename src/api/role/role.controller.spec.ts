import { Test, TestingModule } from '@nestjs/testing';
import { RoleController } from './role.controller';
import { RoleService } from './role.service';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';
import {
  ForbiddenException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import {
  RoleResponseDto,
  CreateRoleBodyDto,
  UpdateRoleBodyDto,
} from '../../dto/role/role.dto';

// Mock RoleService
const mockRoleService: jest.Mocked<Partial<RoleService>> = {
  findAll: jest.fn(),
  findOne: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  remove: jest.fn(),
  assignRoleToSubject: jest.fn(),
  deassignRoleFromSubject: jest.fn(),
  checkSubjectHasRole: jest.fn(),
};

// Mock Authenticated Users
const mockAdminUser: AuthenticatedUser = {
  userId: '1',
  roles: ['Administrator'],
  scopes: [],
  isAdmin: true,
  isMachine: false,
  payload: {},
  handle: 'admin',
  email: 'admin@test.com',
};

const mockRegularUser: AuthenticatedUser = {
  userId: '123',
  roles: ['User'],
  scopes: [],
  isAdmin: false,
  isMachine: false,
  payload: {},
  handle: 'user123',
  email: 'user123@test.com',
};

describe('RoleController', () => {
  let controller: RoleController;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [RoleController],
      providers: [
        {
          provide: RoleService,
          useValue: mockRoleService,
        },
      ],
    })
      .overrideGuard(AuthGuard('jwt'))
      .useValue({ canActivate: () => true })
      .overrideGuard(RolesGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(AuthRequiredGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<RoleController>(RoleController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  // --- Helper to create mock request ---
  const createMockRequest = (user: AuthenticatedUser): any => ({
    user: user,
  });

  // --- Test Cases ---

  describe('findAll', () => {
    it('should allow admin to find all roles', async () => {
      const req = createMockRequest(mockAdminUser);
      const mockResult: RoleResponseDto[] = [
        { id: 1, roleName: 'Admin' } as RoleResponseDto,
      ];
      const mockFind = mockRoleService.findAll.mockResolvedValue(mockResult);

      await controller.findAll({}, req);
      expect(mockFind).toHaveBeenCalledWith(undefined);
    });

    it('should allow admin to find roles by subjectId', async () => {
      const req = createMockRequest(mockAdminUser);
      const mockResult: RoleResponseDto[] = [
        { id: 1, roleName: 'Admin' } as RoleResponseDto,
      ];
      const mockFind = mockRoleService.findAll.mockResolvedValue(mockResult);

      await controller.findAll({ filter: 'subjectId=456' }, req);
      expect(mockFind).toHaveBeenCalledWith(456);
    });

    it('should allow non-admin to find their own roles with filter', async () => {
      const req = createMockRequest(mockRegularUser);
      const mockResult: RoleResponseDto[] = [
        { id: 2, roleName: 'User' } as RoleResponseDto,
      ];
      const mockFind = mockRoleService.findAll.mockResolvedValue(mockResult);

      await controller.findAll(
        { filter: `subjectId=${mockRegularUser.userId}` },
        req,
      );
      expect(mockFind).toHaveBeenCalledWith(Number(mockRegularUser.userId));
    });

    it('should forbid non-admin from finding all roles (no filter)', async () => {
      const req = createMockRequest(mockRegularUser);
      expect.assertions(1); // Expect one assertion to be called (the catch block)
      try {
        await controller.findAll({}, req);
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
      }
    });

    it('should forbid non-admin from finding roles for another subjectId', async () => {
      const req = createMockRequest(mockRegularUser);
      expect.assertions(1); // Expect one assertion to be called (the catch block)
      try {
        await controller.findAll({ filter: 'subjectId=999' }, req);
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
      }
    });

    it('should throw BadRequestException for invalid subjectId filter', async () => {
      const req = createMockRequest(mockAdminUser); // User type doesn't matter here
      expect.assertions(1); // Expect one assertion to be called (the catch block)
      try {
        await controller.findAll({ filter: 'subjectId=abc' }, req);
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
      }
    });
  });

  describe('findOne', () => {
    it('should find a role by ID', async () => {
      const roleId = 1;
      const mockResult = { id: roleId, roleName: 'Admin' } as RoleResponseDto;
      const mockFind = mockRoleService.findOne.mockResolvedValue(mockResult);

      const result = await controller.findOne(roleId);
      expect(result).toEqual(mockResult);
      expect(mockFind).toHaveBeenCalledWith(roleId, undefined);
    });

    it('should throw NotFoundException if role not found', async () => {
      const roleId = 99;
      mockRoleService.findOne.mockResolvedValue(null);
      await expect(controller.findOne(roleId)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should pass fields query to service', async () => {
      const roleId = 1;
      const mockFind = mockRoleService.findOne.mockResolvedValue({
        id: roleId,
        roleName: 'Admin',
      } as RoleResponseDto);
      await controller.findOne(roleId, 'subjects');
      expect(mockFind).toHaveBeenCalledWith(roleId, 'subjects');
    });
  });

  describe('create', () => {
    it('should allow admin to create a role', async () => {
      const req = createMockRequest(mockAdminUser);
      const body: CreateRoleBodyDto = { param: { roleName: 'NewRole' } };
      const mockResult = { id: 3, roleName: 'NewRole' } as RoleResponseDto;
      const mockCreate = mockRoleService.create.mockResolvedValue(mockResult);

      const result = await controller.create(req, body);
      expect(result).toEqual(mockResult);
      expect(mockCreate).toHaveBeenCalledWith(
        { roleName: 'NewRole' },
        Number(mockAdminUser.userId),
      );
    });

    it('should forbid non-admin from creating a role', async () => {
      const req = createMockRequest(mockRegularUser);
      const body: CreateRoleBodyDto = { param: { roleName: 'NewRole' } };
      await expect(controller.create(req, body)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('update', () => {
    it('should allow admin to update a role', async () => {
      const req = createMockRequest(mockAdminUser);
      const roleId = 1;
      const body: UpdateRoleBodyDto = { param: { roleName: 'UpdatedRole' } };
      const mockResult = {
        id: roleId,
        roleName: 'UpdatedRole',
      } as RoleResponseDto;
      const mockUpdate = mockRoleService.update.mockResolvedValue(mockResult);

      const result = await controller.update(req, roleId, body);
      expect(result).toEqual(mockResult);
      expect(mockUpdate).toHaveBeenCalledWith(
        roleId,
        { roleName: 'UpdatedRole' },
        Number(mockAdminUser.userId),
      );
    });

    it('should forbid non-admin from updating a role', async () => {
      const req = createMockRequest(mockRegularUser);
      const roleId = 1;
      const body: UpdateRoleBodyDto = { param: { roleName: 'UpdatedRole' } };
      await expect(controller.update(req, roleId, body)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('remove', () => {
    it('should allow admin to delete a role', async () => {
      const req = createMockRequest(mockAdminUser);
      const roleId = 1;
      const mockRemove = mockRoleService.remove.mockResolvedValue(undefined);

      const result = await controller.remove(req, roleId);
      expect(result).toBeUndefined();
      expect(mockRemove).toHaveBeenCalledWith(roleId);
    });

    it('should forbid non-admin from deleting a role', async () => {
      const req = createMockRequest(mockRegularUser);
      const roleId = 1;
      await expect(controller.remove(req, roleId)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  // --- Role Assignment Tests ---

  describe('assignRoleToSubject', () => {
    it('should allow admin to assign a role', async () => {
      const req = createMockRequest(mockAdminUser);
      const roleId = 1;
      const subjectId = 456;
      const mockFunc =
        mockRoleService.assignRoleToSubject.mockResolvedValue(undefined);

      const result = await controller.assignRoleToSubject(
        req,
        roleId,
        `subjectId=${subjectId}`,
      );
      expect(result).toEqual({
        message: `Role ${roleId} assigned to subject ${subjectId}.`,
      });
      expect(mockFunc).toHaveBeenCalledWith(
        roleId,
        subjectId,
        Number(mockAdminUser.userId),
      );
    });

    it('should forbid non-admin from assigning a role', async () => {
      const req = createMockRequest(mockRegularUser);
      await expect(
        controller.assignRoleToSubject(req, 1, 'subjectId=456'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw BadRequestException if subjectId filter is missing or invalid', async () => {
      const req = createMockRequest(mockAdminUser);
      await expect(controller.assignRoleToSubject(req, 1, '')).rejects.toThrow(
        BadRequestException,
      );
      await expect(
        controller.assignRoleToSubject(req, 1, 'subjectId=abc'),
      ).rejects.toThrow(BadRequestException); // Still invalid as parsedId is NaN
      await expect(
        controller.assignRoleToSubject(req, 1, 'otherFilter=123'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('deassignRoleFromSubject', () => {
    it('should allow admin to deassign a role', async () => {
      const req = createMockRequest(mockAdminUser);
      const roleId = 1;
      const subjectId = 456;
      const mockFunc =
        mockRoleService.deassignRoleFromSubject.mockResolvedValue(undefined);

      const result = await controller.deassignRoleFromSubject(
        req,
        roleId,
        `subjectId=${subjectId}`,
      );
      expect(result).toEqual({
        message: `Role ${roleId} unassigned from subject ${subjectId}.`,
      });
      expect(mockFunc).toHaveBeenCalledWith(roleId, subjectId);
    });

    it('should forbid non-admin from deassigning a role', async () => {
      const req = createMockRequest(mockRegularUser);
      await expect(
        controller.deassignRoleFromSubject(req, 1, 'subjectId=456'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw BadRequestException if subjectId filter is missing or invalid', async () => {
      const req = createMockRequest(mockAdminUser);
      await expect(
        controller.deassignRoleFromSubject(req, 1, ''),
      ).rejects.toThrow(BadRequestException);
      await expect(
        controller.deassignRoleFromSubject(req, 1, 'subjectId=abc'),
      ).rejects.toThrow(BadRequestException); // Still invalid
      await expect(
        controller.deassignRoleFromSubject(req, 1, 'otherFilter=123'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('checkSubjectHasRole', () => {
    it('should allow admin to check any subject role', async () => {
      const req = createMockRequest(mockAdminUser);
      const roleId = 1;
      const subjectId = 456;
      const mockResult = { id: roleId, roleName: 'Admin' } as RoleResponseDto;
      const mockCheck =
        mockRoleService.checkSubjectHasRole.mockResolvedValue(mockResult);

      const result = await controller.checkSubjectHasRole(
        req,
        roleId,
        `subjectId=${subjectId}`,
      );
      expect(result).toEqual(mockResult);
      expect(mockCheck).toHaveBeenCalledWith(roleId, subjectId);
    });

    it('should allow non-admin to check their own role', async () => {
      const req = createMockRequest(mockRegularUser);
      const roleId = 2;
      const subjectId = Number(mockRegularUser.userId);
      const mockResult = { id: roleId, roleName: 'User' } as RoleResponseDto;
      const mockCheck =
        mockRoleService.checkSubjectHasRole.mockResolvedValue(mockResult);

      const result = await controller.checkSubjectHasRole(
        req,
        roleId,
        `subjectId=${subjectId}`,
      );
      expect(result).toEqual(mockResult);
      expect(mockCheck).toHaveBeenCalledWith(roleId, subjectId);
    });

    it('should forbid non-admin from checking another subject role', async () => {
      const req = createMockRequest(mockRegularUser);
      await expect(
        controller.checkSubjectHasRole(req, 1, 'subjectId=999'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw NotFoundException if subject does not have the role', async () => {
      const req = createMockRequest(mockAdminUser); // Use admin to bypass permission check
      const roleId = 1;
      const subjectId = 456;
      mockRoleService.checkSubjectHasRole.mockResolvedValue(null);

      await expect(
        controller.checkSubjectHasRole(req, roleId, `subjectId=${subjectId}`),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException if subjectId filter is missing or invalid', async () => {
      const req = createMockRequest(mockAdminUser);
      await expect(controller.checkSubjectHasRole(req, 1, '')).rejects.toThrow(
        BadRequestException,
      );
      await expect(
        controller.checkSubjectHasRole(req, 1, 'subjectId=abc'),
      ).rejects.toThrow(BadRequestException); // Still invalid
      await expect(
        controller.checkSubjectHasRole(req, 1, 'otherFilter=123'),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
