import { Test, TestingModule } from '@nestjs/testing';
import { RoleService } from './role.service';
import { PRISMA_CLIENT_AUTHORIZATION } from '../../shared/prisma/prisma.module';
import { MemberApiService } from '../../shared/member-api/member-api.service';
import { NotFoundException, ConflictException } from '@nestjs/common';
import { Prisma } from '@prisma/client-authorization';
import { MemberInfoResponseDto } from '../../dto/member/member.dto';

// Mock Prisma Client
const mockPrismaAuth = {
  role: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  roleAssignment: {
    findUnique: jest.fn(),
    create: jest.fn(),
    deleteMany: jest.fn(),
    count: jest.fn(), // Added count for testing remove conflict
  },
  // Add the $transaction mock
  $transaction: jest.fn().mockImplementation(async (callback) => {
    // Execute the callback with the mock Prisma client itself
    // This simulates the transaction, allowing operations within the callback
    // to use the mocked methods (findUnique, update, etc.)
    return callback(mockPrismaAuth);
  }),
};

// Mock Member API Service (even if not used directly in current methods)
const mockMemberApiService = {
  getUserInfoList: jest.fn(),
};

describe('RoleService', () => {
  let service: RoleService;
  let memberApiService: MemberApiService;

  beforeEach(async () => {
    // Reset mocks before each test
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RoleService,
        {
          provide: PRISMA_CLIENT_AUTHORIZATION,
          useValue: mockPrismaAuth,
        },
        {
          provide: MemberApiService,
          useValue: mockMemberApiService,
        },
        // Provide a mock logger to suppress actual logging during tests if desired
        // {
        //   provide: Logger,
        //   useValue: {
        //     log: jest.fn(),
        //     debug: jest.fn(),
        //     error: jest.fn(),
        //     warn: jest.fn(),
        //   },
        // },
      ],
    }).compile();

    service = module.get<RoleService>(RoleService);
    memberApiService = module.get<MemberApiService>(MemberApiService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // --- Test Cases for each method ---

  describe('findAll', () => {
    it('should return all roles without filter', async () => {
      const mockRoles = [
        {
          id: 1,
          name: 'Admin',
          createdAt: new Date(),
          createdBy: 1,
          modifiedAt: new Date(),
          modifiedBy: 1,
        },
      ];
      mockPrismaAuth.role.findMany.mockResolvedValue(mockRoles);

      const result = await service.findAll();
      expect(result).toHaveLength(1);
      expect(result[0].roleName).toEqual('Admin');
      expect(mockPrismaAuth.role.findMany).toHaveBeenCalledWith({
        where: {},
      });
    });

    it('should return roles for a specific subjectId', async () => {
      const mockRoles = [
        {
          id: 2,
          name: 'User',
          createdAt: new Date(),
          createdBy: 1,
          modifiedAt: new Date(),
          modifiedBy: 1,
        },
      ];
      mockPrismaAuth.role.findMany.mockResolvedValue(mockRoles);

      const result = await service.findAll(123);
      expect(result).toHaveLength(1);
      expect(result[0].roleName).toEqual('User');
      expect(mockPrismaAuth.role.findMany).toHaveBeenCalledWith({
        where: {
          roleAssignments: { some: { subjectId: 123, subjectType: 1 } },
        },
      });
    });

    it('should NOT include enriched subjects even when fields=subjects', async () => {
      const mockRoles = [
        {
          id: 1,
          name: 'Admin',
          createdAt: new Date(),
          createdBy: 1,
          modifiedAt: new Date(),
          modifiedBy: 1,
        },
      ];
      mockPrismaAuth.role.findMany.mockResolvedValue(mockRoles);

      const result = await service.findAll(undefined, 'subjects');
      expect(result[0].subjects).toBeUndefined();
      expect(mockPrismaAuth.role.findMany).toHaveBeenCalledWith({
        where: {},
      });
      expect(memberApiService.getUserInfoList).not.toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    it('should return a role if found (no enrichment)', async () => {
      const mockRole = {
        id: 1,
        name: 'Admin',
        createdAt: new Date(),
        createdBy: 1,
        modifiedAt: new Date(),
        modifiedBy: 1,
      };
      mockPrismaAuth.role.findUnique.mockResolvedValue(mockRole);

      const result = await service.findOne(1);
      expect(result).toBeDefined();
      expect(result?.roleName).toEqual('Admin');
      expect(result?.subjects).toBeUndefined();
      expect(mockPrismaAuth.role.findUnique).toHaveBeenCalledWith({
        where: { id: 1 },
        include: { roleAssignments: false },
      });
      expect(memberApiService.getUserInfoList).not.toHaveBeenCalled();
    });

    it('should return null if role not found', async () => {
      mockPrismaAuth.role.findUnique.mockResolvedValue(null);
      const result = await service.findOne(99);
      expect(result).toBeNull();
    });

    it('should include enriched subjects when fields=subjects', async () => {
      const roleId = 1;
      const subjectId = 123;
      const mockRoleWithAssignments = {
        id: roleId,
        name: 'Admin',
        createdAt: new Date(),
        createdBy: 1,
        modifiedAt: new Date(),
        modifiedBy: 1,
        roleAssignments: [{ subjectId: subjectId }],
      };
      const mockMemberInfo: MemberInfoResponseDto[] = [
        { userId: subjectId, handle: 'user123', email: 'user123@test.com' },
      ];

      mockPrismaAuth.role.findUnique.mockResolvedValue(mockRoleWithAssignments);
      (memberApiService.getUserInfoList as jest.Mock).mockResolvedValue(
        mockMemberInfo,
      );

      const result = await service.findOne(roleId, 'subjects');

      expect(mockPrismaAuth.role.findUnique).toHaveBeenCalledWith({
        where: { id: roleId },
        include: {
          roleAssignments: {
            where: { subjectType: 1 },
            select: { subjectId: true },
          },
        },
      });
      expect(memberApiService.getUserInfoList).toHaveBeenCalledWith([
        subjectId,
      ]);
      expect(result).toBeDefined();
      expect(result?.roleName).toEqual('Admin');
      expect(result?.subjects).toEqual(mockMemberInfo);
    });
  });

  describe('create', () => {
    it('should create a new role', async () => {
      const createDto = { roleName: 'Tester' };
      const creatorId = 1;
      const newRole = {
        id: 3,
        name: 'Tester',
        createdBy: creatorId,
        modifiedBy: creatorId,
        createdAt: new Date(),
        modifiedAt: new Date(),
      };

      mockPrismaAuth.role.findUnique.mockResolvedValue(null); // No existing role
      mockPrismaAuth.role.create.mockResolvedValue(newRole);

      const result = await service.create(createDto, creatorId);
      expect(result.roleName).toEqual('Tester');
      expect(result.id).toEqual(3);
      expect(result.subjects).toBeUndefined();
      expect(mockPrismaAuth.role.findUnique).toHaveBeenCalledWith({
        where: { name: 'Tester' },
      });
      expect(mockPrismaAuth.role.create).toHaveBeenCalledWith({
        data: { name: 'Tester', createdBy: creatorId, modifiedBy: creatorId },
      });
    });

    it('should throw ConflictException if role name already exists', async () => {
      const createDto = { roleName: 'Admin' };
      const existingRole = { id: 1, name: 'Admin' };
      mockPrismaAuth.role.findUnique.mockResolvedValue(existingRole);

      await expect(service.create(createDto, 1)).rejects.toThrow(
        ConflictException,
      );
      expect(mockPrismaAuth.role.create).not.toHaveBeenCalled();
    });
  });

  describe('update', () => {
    it('should update an existing role', async () => {
      const updateDto = { roleName: 'SuperAdmin' };
      const modifierId = 2;
      const roleId = 1;
      const existingRole = {
        id: roleId,
        name: 'Admin',
        createdAt: new Date(),
        createdBy: 1,
        modifiedAt: new Date(),
        modifiedBy: 1,
      };
      const updatedRoleData = {
        ...existingRole,
        name: 'SuperAdmin',
        modifiedBy: modifierId,
        modifiedAt: new Date(),
      };

      // Mock for fetching the role by ID (first call to findUnique)
      mockPrismaAuth.role.findUnique.mockResolvedValueOnce(existingRole);
      // Mock for checking if the new name conflicts with another role (second call to findUnique)
      // Should return null for this test case to indicate no conflict.
      mockPrismaAuth.role.findUnique.mockResolvedValueOnce(null);
      // Mock for the actual update operation
      mockPrismaAuth.role.update.mockResolvedValue(updatedRoleData);

      const result = await service.update(roleId, updateDto, modifierId);
      expect(result.roleName).toEqual('SuperAdmin');
      expect(result.updatedBy).toEqual(modifierId);
      expect(result.subjects).toBeUndefined();
      expect(mockPrismaAuth.role.findUnique).toHaveBeenCalledWith({
        where: { id: roleId },
      });
      expect(mockPrismaAuth.role.update).toHaveBeenCalledWith({
        where: { id: roleId },
        data: { name: 'SuperAdmin', modifiedBy: modifierId },
      });
    });

    it('should throw NotFoundException if role to update does not exist', async () => {
      mockPrismaAuth.role.findUnique.mockResolvedValue(null); // Role not found
      await expect(
        service.update(99, { roleName: 'Ghost' }, 1),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ConflictException if updated role name already exists', async () => {
      const roleId = 1;
      const updateDto = {
        roleName: 'ExistingRole',
        description: 'Updated Description',
      };
      const existingRole = {
        id: roleId,
        name: 'SomeOtherRole',
        description: 'Original Description',
        createdBy: 1,
        updatedBy: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPrismaAuth.role.findUnique.mockResolvedValueOnce(existingRole); // For fetching the role by ID

      // Mock the update call to throw a P2002 error with meta information
      mockPrismaAuth.role.update.mockRejectedValueOnce(
        new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
          code: 'P2002',
          clientVersion: 'test',
          meta: { target: ['name'] }, // Added meta target for the service to correctly identify the constraint
        }),
      );

      await expect(service.update(roleId, updateDto, 1)).rejects.toThrow(
        ConflictException,
      );
      expect(mockPrismaAuth.role.update).toHaveBeenCalledWith({
        where: { id: roleId },
        data: { name: updateDto.roleName, modifiedBy: 1 },
      });
    });
  });

  describe('remove', () => {
    it('should remove a role and its assignments', async () => {
      const roleId = 1;
      const existingRole = { id: roleId, name: 'ToDelete' };
      mockPrismaAuth.role.findUnique.mockResolvedValue(existingRole);
      mockPrismaAuth.roleAssignment.deleteMany.mockResolvedValue({ count: 2 }); // Assume 2 assignments deleted
      mockPrismaAuth.role.delete.mockResolvedValue(existingRole); // Role deleted

      await expect(service.remove(roleId)).resolves.toBeUndefined();
      expect(mockPrismaAuth.role.findUnique).toHaveBeenCalledWith({
        where: { id: roleId },
      });
      expect(mockPrismaAuth.roleAssignment.deleteMany).toHaveBeenCalledWith({
        where: { roleId: roleId },
      });
      expect(mockPrismaAuth.role.delete).toHaveBeenCalledWith({
        where: { id: roleId },
      });
    });

    it('should throw NotFoundException if role to remove does not exist', async () => {
      mockPrismaAuth.role.findUnique.mockResolvedValue(null);
      await expect(service.remove(99)).rejects.toThrow(NotFoundException);
      expect(mockPrismaAuth.roleAssignment.deleteMany).not.toHaveBeenCalled();
      expect(mockPrismaAuth.role.delete).not.toHaveBeenCalled();
    });

    it('should throw ConflictException if assignments remain (simulated P2003)', async () => {
      const roleId = 1;
      const existingRole = { id: roleId, name: 'ToDelete' };
      mockPrismaAuth.role.findUnique.mockResolvedValue(existingRole);
      mockPrismaAuth.roleAssignment.deleteMany.mockResolvedValue({ count: 0 }); // Simulate deleteMany didn't catch all?
      // Simulate Prisma throwing P2003 on role delete
      mockPrismaAuth.role.delete.mockRejectedValue({ code: 'P2003' });
      // Simulate count finding assignments
      mockPrismaAuth.roleAssignment.count.mockResolvedValue(1);

      await expect(service.remove(roleId)).rejects.toThrow(ConflictException);
      expect(mockPrismaAuth.role.delete).toHaveBeenCalledTimes(1);
      expect(mockPrismaAuth.roleAssignment.count).toHaveBeenCalledWith({
        where: { roleId },
      });
    });
  });

  describe('assignRoleToSubject', () => {
    it('should assign a role to a subject', async () => {
      const roleId = 1;
      const subjectId = 123;
      const operatorId = 1;
      mockPrismaAuth.role.count.mockResolvedValue(1); // Role exists
      mockPrismaAuth.roleAssignment.create.mockResolvedValue({}); // Assignment created

      await expect(
        service.assignRoleToSubject(roleId, subjectId, operatorId),
      ).resolves.toBeUndefined();
      expect(mockPrismaAuth.role.count).toHaveBeenCalledWith({
        where: { id: roleId },
      });
      expect(mockPrismaAuth.roleAssignment.create).toHaveBeenCalledWith({
        data: {
          roleId,
          subjectId,
          subjectType: 1,
          createdBy: operatorId,
          modifiedBy: operatorId,
        },
      });
    });

    it('should throw NotFoundException if role does not exist', async () => {
      mockPrismaAuth.role.count.mockResolvedValue(0); // Role does not exist
      await expect(service.assignRoleToSubject(99, 123, 1)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should ignore assignment if it already exists (P2002)', async () => {
      mockPrismaAuth.role.count.mockResolvedValue(1);
      mockPrismaAuth.roleAssignment.create.mockRejectedValue({ code: 'P2002' }); // Simulate unique constraint violation

      // Should now throw ConflictException, not resolve
      await expect(service.assignRoleToSubject(1, 123, 1)).rejects.toThrow(
        ConflictException,
      );
      expect(mockPrismaAuth.roleAssignment.create).toHaveBeenCalled();
    });
  });

  describe('deassignRoleFromSubject', () => {
    it('should deassign a role from a subject', async () => {
      const roleId = 1;
      const subjectId = 123;
      mockPrismaAuth.roleAssignment.deleteMany.mockResolvedValue({ count: 1 }); // Assignment deleted

      await expect(
        service.deassignRoleFromSubject(roleId, subjectId),
      ).resolves.toBeUndefined();
      expect(mockPrismaAuth.roleAssignment.deleteMany).toHaveBeenCalledWith({
        where: { roleId, subjectId, subjectType: 1 },
      });
    });

    it('should do nothing if assignment does not exist', async () => {
      mockPrismaAuth.roleAssignment.deleteMany.mockResolvedValue({ count: 0 }); // No assignment found

      await expect(
        service.deassignRoleFromSubject(1, 123),
      ).resolves.toBeUndefined();
      expect(mockPrismaAuth.roleAssignment.deleteMany).toHaveBeenCalled();
    });
  });

  describe('checkSubjectHasRole', () => {
    it('should return role details if subject has the role', async () => {
      const roleId = 1;
      const subjectId = 123;
      const mockRole = {
        id: roleId,
        name: 'Admin',
        createdAt: new Date(),
        createdBy: 1,
        modifiedAt: new Date(),
        modifiedBy: 1,
      };
      const mockAssignment = {
        roleId,
        subjectId,
        subjectType: 1,
        role: mockRole,
      };
      mockPrismaAuth.roleAssignment.findUnique.mockResolvedValue(
        mockAssignment,
      );

      const result = await service.checkSubjectHasRole(roleId, subjectId);
      expect(result).toBeDefined();
      expect(result?.roleName).toEqual('Admin');
      expect(mockPrismaAuth.roleAssignment.findUnique).toHaveBeenCalledWith({
        where: {
          roleId_subjectId_subjectType: { roleId, subjectId, subjectType: 1 },
        },
        include: { role: true },
      });
    });

    it('should return null if subject does not have the role', async () => {
      mockPrismaAuth.roleAssignment.findUnique.mockResolvedValue(null);
      const result = await service.checkSubjectHasRole(1, 123);
      expect(result).toBeNull();
    });
  });
});
