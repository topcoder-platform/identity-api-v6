import { Test, TestingModule } from '@nestjs/testing';
import { RoleService } from './role.service';
import { PRISMA_CLIENT_AUTHORIZATION } from '../../shared/prisma/prisma.module';
import { MemberApiService } from '../../shared/member-api/member-api.service';
import { NotFoundException, ConflictException, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client-authorization';
import { MemberInfoResponseDto } from '../../dto/member/member.dto';

// Test data factory functions
const createMockRole = (overrides: Partial<any> = {}) => ({
  id: 1,
  name: 'Admin',
  createdAt: new Date('2024-01-01'),
  createdBy: 1,
  modifiedAt: new Date('2024-01-01'),
  modifiedBy: 1,
  ...overrides,
});

const createMockMemberInfo = (
  overrides: Partial<MemberInfoResponseDto> = {},
): MemberInfoResponseDto => ({
  userId: 123,
  handle: 'user123',
  email: 'user123@test.com',
  ...overrides,
});

const createMockRoleAssignment = (overrides: Partial<any> = {}) => ({
  roleId: 1,
  subjectId: 123,
  subjectType: 1,
  ...overrides,
});

// Mock factory functions
const createMockPrismaAuth = () => ({
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
    count: jest.fn(),
  },
  $transaction: jest.fn().mockImplementation(<T>(callback): Promise<T> => {
    const result = callback(mockPrismaAuth);
    return result instanceof Promise ? result : Promise.resolve(result);
  }),
});

const createMockMemberApiService = () => ({
  getUserInfoList: jest.fn(),
});

const createMockLogger = () => ({
  log: jest.fn(),
  debug: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
});

// Global mocks
const mockPrismaAuth = createMockPrismaAuth();
const mockMemberApiService = createMockMemberApiService();
const mockLogger = createMockLogger();

describe('RoleService', () => {
  let service: RoleService;

  beforeEach(async () => {
    // Reset all mocks
    jest.clearAllMocks();
    Object.values(mockPrismaAuth.role).forEach((mock) => mock.mockReset());
    Object.values(mockPrismaAuth.roleAssignment).forEach((mock) =>
      mock.mockReset(),
    );
    mockPrismaAuth.$transaction.mockImplementation(
      <T>(callback): Promise<T> => {
        const result = callback(mockPrismaAuth);
        return result instanceof Promise ? result : Promise.resolve(result);
      },
    );

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RoleService,
        { provide: PRISMA_CLIENT_AUTHORIZATION, useValue: mockPrismaAuth },
        { provide: MemberApiService, useValue: mockMemberApiService },
        { provide: Logger, useValue: mockLogger },
      ],
    }).compile();

    service = module.get<RoleService>(RoleService);

    // Replace logger instance to ensure consistent mocking
    (service as any).logger = mockLogger;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('findAll', () => {
    const mockRoles = [
      createMockRole(),
      createMockRole({ id: 2, name: 'User' }),
    ];

    it('should return all roles without filter', async () => {
      mockPrismaAuth.role.findMany.mockResolvedValue(mockRoles);

      const result = await service.findAll();

      expect(result).toHaveLength(2);
      expect(result[0].roleName).toBe('Admin');
      expect(result[1].roleName).toBe('User');
      expect(mockPrismaAuth.role.findMany).toHaveBeenCalledWith({ where: {} });
    });

    it('should return roles for a specific subjectId', async () => {
      const subjectId = 123;
      mockPrismaAuth.role.findMany.mockResolvedValue([mockRoles[1]]);

      const result = await service.findAll(subjectId);

      expect(result).toHaveLength(1);
      expect(result[0].roleName).toBe('User');
      expect(mockPrismaAuth.role.findMany).toHaveBeenCalledWith({
        where: { roleAssignments: { some: { subjectId, subjectType: 1 } } },
      });
    });

    it('should not include enriched subjects even when fields=subjects', async () => {
      mockPrismaAuth.role.findMany.mockResolvedValue(mockRoles);

      const result = await service.findAll(undefined);

      expect(result[0].subjects).toBeUndefined();
      expect(mockMemberApiService.getUserInfoList).not.toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    const mockRole = createMockRole();
    const roleId = 1;

    describe('without enrichment', () => {
      it('should return a role if found', async () => {
        mockPrismaAuth.role.findUnique.mockResolvedValue(mockRole);

        const result = await service.findOne(roleId);

        expect(result?.roleName).toBe('Admin');
        expect(result?.subjects).toBeUndefined();
        expect(mockPrismaAuth.role.findUnique).toHaveBeenCalledWith({
          where: { id: roleId },
          include: { roleAssignments: false },
        });
      });

      it('should return null if role not found', async () => {
        mockPrismaAuth.role.findUnique.mockResolvedValue(null);

        const result = await service.findOne(99);

        expect(result).toBeNull();
      });
    });

    describe('with enrichment (fields=subjects)', () => {
      const subjectId = 123;
      const mockRoleWithAssignments = {
        ...mockRole,
        roleAssignments: [{ subjectId }],
      };
      const mockMemberInfo = [createMockMemberInfo({ userId: subjectId })];

      it('should include enriched subjects', async () => {
        mockPrismaAuth.role.findUnique.mockResolvedValue(
          mockRoleWithAssignments,
        );
        const mockFunc =
          mockMemberApiService.getUserInfoList.mockResolvedValue(
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
        expect(mockFunc).toHaveBeenCalledWith([subjectId]);
        expect(result?.subjects).toEqual(mockMemberInfo);
      });

      it('should handle getUserInfoList failure gracefully', async () => {
        const error = new Error('API service unavailable');
        mockPrismaAuth.role.findUnique.mockResolvedValue(
          mockRoleWithAssignments,
        );
        mockMemberApiService.getUserInfoList.mockRejectedValue(error);

        const result = await service.findOne(roleId, 'subjects');

        expect(mockLogger.error).toHaveBeenCalledWith(
          `Failed to fetch member info for role ${roleId}: ${error.message}`,
          error.stack,
        );
        expect(result?.subjects).toBeUndefined();
      });
    });
  });

  describe('create', () => {
    const createDto = { roleName: 'Tester' };
    const creatorId = 1;
    const newRole = createMockRole({
      id: 3,
      name: 'Tester',
      createdBy: creatorId,
      modifiedBy: creatorId,
    });

    it('should create a new role successfully', async () => {
      mockPrismaAuth.role.findUnique.mockResolvedValue(null); // No existing role
      mockPrismaAuth.role.create.mockResolvedValue(newRole);

      const result = await service.create(createDto, creatorId);

      expect(result.roleName).toBe('Tester');
      expect(result.id).toBe(3);
      expect(mockPrismaAuth.role.findUnique).toHaveBeenCalledWith({
        where: { name: 'Tester' },
      });
      expect(mockPrismaAuth.role.create).toHaveBeenCalledWith({
        data: { name: 'Tester', createdBy: creatorId, modifiedBy: creatorId },
      });
    });

    it('should throw ConflictException if role name already exists', async () => {
      const existingRole = createMockRole({ name: 'Tester' });
      mockPrismaAuth.role.findUnique.mockResolvedValue(existingRole);

      await expect(service.create(createDto, creatorId)).rejects.toThrow(
        ConflictException,
      );
      expect(mockPrismaAuth.role.create).not.toHaveBeenCalled();
    });
  });

  describe('update', () => {
    const roleId = 1;
    const updateDto = { roleName: 'SuperAdmin' };
    const modifierId = 2;
    const existingRole = createMockRole();
    const updatedRole = createMockRole({
      name: 'SuperAdmin',
      modifiedBy: modifierId,
    });

    it('should update an existing role successfully', async () => {
      mockPrismaAuth.role.findUnique
        .mockResolvedValueOnce(existingRole) // First call: check if role exists
        .mockResolvedValueOnce(null); // Second call: check name conflict
      mockPrismaAuth.role.update.mockResolvedValue(updatedRole);

      const result = await service.update(roleId, updateDto, modifierId);

      expect(result.roleName).toBe('SuperAdmin');
      expect(result.updatedBy).toBe(modifierId);
      expect(mockPrismaAuth.role.update).toHaveBeenCalledWith({
        where: { id: roleId },
        data: { name: 'SuperAdmin', modifiedBy: modifierId },
      });
    });

    it('should throw NotFoundException if role does not exist', async () => {
      mockPrismaAuth.role.findUnique.mockResolvedValue(null);

      await expect(service.update(99, updateDto, modifierId)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw ConflictException if updated name already exists', async () => {
      const conflictingRole = createMockRole({ id: 2, name: 'SuperAdmin' });
      mockPrismaAuth.role.findUnique
        .mockResolvedValueOnce(existingRole)
        .mockResolvedValueOnce(conflictingRole);

      await expect(
        service.update(roleId, updateDto, modifierId),
      ).rejects.toThrow(
        new ConflictException(
          `Role with name '${updateDto.roleName}' already exists.`,
        ),
      );
      expect(mockPrismaAuth.role.update).not.toHaveBeenCalled();
    });

    it('should handle Prisma P2002 error during update', async () => {
      mockPrismaAuth.role.findUnique.mockResolvedValueOnce(existingRole);
      mockPrismaAuth.role.update.mockRejectedValue(
        new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
          code: 'P2002',
          clientVersion: 'test',
          meta: { target: ['name'] },
        }),
      );

      await expect(
        service.update(roleId, updateDto, modifierId),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe('remove', () => {
    const roleId = 1;
    const existingRole = createMockRole({ id: roleId, name: 'ToDelete' });

    it('should remove a role and its assignments successfully', async () => {
      mockPrismaAuth.role.findUnique.mockResolvedValue(existingRole);
      mockPrismaAuth.roleAssignment.deleteMany.mockResolvedValue({ count: 2 });
      mockPrismaAuth.role.delete.mockResolvedValue(existingRole);

      await expect(service.remove(roleId)).resolves.toBeUndefined();
      expect(mockPrismaAuth.roleAssignment.deleteMany).toHaveBeenCalledWith({
        where: { roleId },
      });
      expect(mockPrismaAuth.role.delete).toHaveBeenCalledWith({
        where: { id: roleId },
      });
    });

    it('should throw NotFoundException if role does not exist', async () => {
      mockPrismaAuth.role.findUnique.mockResolvedValue(null);

      await expect(service.remove(99)).rejects.toThrow(NotFoundException);
      expect(mockPrismaAuth.roleAssignment.deleteMany).not.toHaveBeenCalled();
    });

    it('should throw ConflictException if assignments remain', async () => {
      mockPrismaAuth.role.findUnique.mockResolvedValue(existingRole);
      mockPrismaAuth.roleAssignment.deleteMany.mockResolvedValue({ count: 0 });
      mockPrismaAuth.role.delete.mockRejectedValue({ code: 'P2003' });
      mockPrismaAuth.roleAssignment.count.mockResolvedValue(1);

      await expect(service.remove(roleId)).rejects.toThrow(ConflictException);
    });
  });

  describe('assignRoleToSubject', () => {
    const roleId = 1;
    const subjectId = 123;
    const operatorId = 1;

    it('should assign a role to a subject successfully', async () => {
      mockPrismaAuth.role.count.mockResolvedValue(1);
      mockPrismaAuth.roleAssignment.create.mockResolvedValue({});

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
      mockPrismaAuth.role.count.mockResolvedValue(0);

      await expect(
        service.assignRoleToSubject(99, subjectId, operatorId),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ConflictException if assignment already exists', async () => {
      mockPrismaAuth.role.count.mockResolvedValue(1);
      mockPrismaAuth.roleAssignment.create.mockRejectedValue({ code: 'P2002' });

      await expect(
        service.assignRoleToSubject(roleId, subjectId, operatorId),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe('deassignRoleFromSubject', () => {
    const roleId = 1;
    const subjectId = 123;

    it('should deassign a role from a subject successfully', async () => {
      mockPrismaAuth.roleAssignment.deleteMany.mockResolvedValue({ count: 1 });

      await expect(
        service.deassignRoleFromSubject(roleId, subjectId),
      ).resolves.toBeUndefined();
      expect(mockPrismaAuth.roleAssignment.deleteMany).toHaveBeenCalledWith({
        where: { roleId, subjectId, subjectType: 1 },
      });
    });

    it('should handle non-existent assignment gracefully', async () => {
      mockPrismaAuth.roleAssignment.deleteMany.mockResolvedValue({ count: 0 });

      await expect(
        service.deassignRoleFromSubject(roleId, subjectId),
      ).resolves.toBeUndefined();
    });
  });

  describe('checkSubjectHasRole', () => {
    const roleId = 1;
    const subjectId = 123;

    it('should return role details if subject has the role', async () => {
      const mockRole = createMockRole();
      const mockAssignment = createMockRoleAssignment({ role: mockRole });
      mockPrismaAuth.roleAssignment.findUnique.mockResolvedValue(
        mockAssignment,
      );

      const result = await service.checkSubjectHasRole(roleId, subjectId);

      expect(result?.roleName).toBe('Admin');
      expect(mockPrismaAuth.roleAssignment.findUnique).toHaveBeenCalledWith({
        where: {
          roleId_subjectId_subjectType: { roleId, subjectId, subjectType: 1 },
        },
        include: { role: true },
      });
    });

    it('should return null if subject does not have the role', async () => {
      mockPrismaAuth.roleAssignment.findUnique.mockResolvedValue(null);

      const result = await service.checkSubjectHasRole(roleId, subjectId);

      expect(result).toBeNull();
    });
  });

  describe('Role operations by name', () => {
    const roleName = 'Admin';
    const subjectId = 123;
    const operatorId = 456;
    const mockRole = createMockRole();

    beforeEach(() => {
      // Setup common spy for findRoleByName
      jest.spyOn(service, 'findRoleByName');
    });

    describe('assignRoleByName', () => {
      it('should assign role successfully when role exists', async () => {
        (service.findRoleByName as jest.Mock).mockResolvedValue(mockRole);
        const mockFunc = jest
          .spyOn(service, 'assignRoleToSubject')
          .mockResolvedValue(undefined);

        await service.assignRoleByName(roleName, subjectId, operatorId);

        expect(mockLogger.debug).toHaveBeenCalledWith(
          `Assigning role '${roleName}' to subject ${subjectId} by operator ${operatorId}`,
        );
        expect(mockFunc).toHaveBeenCalledWith(
          mockRole.id,
          subjectId,
          operatorId,
        );
      });

      it('should throw NotFoundException when role does not exist', async () => {
        (service.findRoleByName as jest.Mock).mockResolvedValue(null);
        jest.spyOn(service, 'assignRoleToSubject').mockResolvedValue(undefined);

        await expect(
          service.assignRoleByName(roleName, subjectId, operatorId),
        ).rejects.toThrow(
          new NotFoundException(`Role with name '${roleName}' not found.`),
        );
      });
    });

    describe('deassignRoleByName', () => {
      it('should deassign role successfully when role exists', async () => {
        (service.findRoleByName as jest.Mock).mockResolvedValue(mockRole);
        const mockFunc = jest
          .spyOn(service, 'deassignRoleFromSubject')
          .mockResolvedValue(undefined);

        await service.deassignRoleByName(roleName, subjectId);

        expect(mockLogger.debug).toHaveBeenCalledWith(
          `Deassigning role by name '${roleName}' from subject ${subjectId}`,
        );
        expect(mockFunc).toHaveBeenCalledWith(mockRole.id, subjectId);
      });

      it('should throw NotFoundException when role does not exist', async () => {
        (service.findRoleByName as jest.Mock).mockResolvedValue(null);

        await expect(
          service.deassignRoleByName(roleName, subjectId),
        ).rejects.toThrow(
          new NotFoundException(`Role with name '${roleName}' not found.`),
        );
      });
    });
  });

  describe('findRoleByName', () => {
    const testCases = [
      {
        name: 'Admin',
        expected: createMockRole(),
        description: 'existing role',
      },
      { name: 'NonExistent', expected: null, description: 'non-existent role' },
      { name: '', expected: null, description: 'empty role name' },
      {
        name: 'Super-Admin_2024!',
        expected: createMockRole({ name: 'Super-Admin_2024!' }),
        description: 'role with special characters',
      },
    ];

    testCases.forEach(({ name, expected, description }) => {
      it(`should handle ${description}`, async () => {
        mockPrismaAuth.role.findUnique.mockResolvedValue(expected);

        const result = await service.findRoleByName(name);

        expect(mockLogger.debug).toHaveBeenCalledWith(
          `Finding role by name: ${name}`,
        );
        expect(mockPrismaAuth.role.findUnique).toHaveBeenCalledWith({
          where: { name },
        });
        expect(result).toEqual(expected);
      });
    });

    it('should propagate database errors', async () => {
      const error = new Error('Database connection failed');
      mockPrismaAuth.role.findUnique.mockRejectedValue(error);

      await expect(service.findRoleByName('Admin')).rejects.toThrow(error);
    });
  });
});
