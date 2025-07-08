import { Test, TestingModule } from '@nestjs/testing';
import { GroupService } from './group.service';
import {
  PRISMA_CLIENT_AUTHORIZATION,
  PRISMA_CLIENT_COMMON_OLTP,
} from '../../shared/prisma/prisma.module';
import {
  NotFoundException,
  ConflictException,
  InternalServerErrorException,
  ForbiddenException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { GroupMembership } from '@prisma/client-authorization';
import {
  GroupResponseDto,
  GroupDto,
  SecurityGroups,
} from 'src/dto/group/group.dto';
import {
  GroupMemberDto,
  GroupMembershipResponseDto,
} from 'src/dto/group/group-membership.dto';
import { AuthenticatedUser } from 'src/core/auth/jwt.strategy';
import { MembershipType, MembershipTypeHelper } from './membership-type.enum';
import { Constants } from '../../core/constant/constants';

// Mock Prisma Clients
const mockPrismaAuth = {
  group: {
    findUnique: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  groupMembership: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    delete: jest.fn(),
    deleteMany: jest.fn(),
    count: jest.fn(),
  },
  $transaction: jest
    .fn()
    .mockImplementation(async (callback) =>
      Promise.resolve(callback(mockPrismaAuth)),
    ),
};

const mockPrismaCommonClient = {
  security_groups: {
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
  },
};

// Mock Authenticated Users
const mockAdminUser: AuthenticatedUser = {
  userId: '1',
  roles: ['administrator'],
  scopes: ['read:groups', 'write:groups', 'all:groups'],
  isMachine: false,
  isAdmin: true, // assuming admin user
  payload: {}, // or use the appropriate structure expected by your app
};

const mockRegularUser: AuthenticatedUser = {
  userId: '2',
  roles: ['user'],
  scopes: [],
  isMachine: false,
  isAdmin: false, // assuming admin user
  payload: {}, // or use the appropriate structure expected by your app
};

const mockMachineUserWithWriteScope: AuthenticatedUser = {
  userId: 'machine-1',
  scopes: ['write:groups'],
  isMachine: true,
  roles: [],
  isAdmin: false, // assuming admin user
  payload: {}, // or use the appropriate structure expected by your app
};

const mockMachineUserWithReadScope: AuthenticatedUser = {
  userId: 'machine-2',
  scopes: ['read:groups'],
  isMachine: true,
  roles: [],
  isAdmin: false, // assuming admin user
  payload: {}, // or use the appropriate structure expected by your app
};

const mockMachineUserWithoutScope: AuthenticatedUser = {
  userId: 'machine-3',
  scopes: ['other:scope'],
  isMachine: true,
  roles: [],
  isAdmin: false, // assuming admin user
  payload: {}, // or use the appropriate structure expected by your app
};

// Mock MembershipTypeHelper
jest.mock('./membership-type.enum', () => ({
  MembershipType: {
    User: 1,
    Group: 2,
  },
  MembershipTypeHelper: {
    getByKey: jest.fn((key: string) => {
      if (key === 'User') return 1;
      if (key === 'Group') return 2;
      return 0;
    }),
    lowerName: jest.fn((type: number) => {
      if (type === 1) return 'user';
      if (type === 2) return 'group';
      return 'unknown';
    }),
  },
}));

describe('GroupService', () => {
  let service: GroupService;

  beforeEach(async () => {
    // Mock the Logger constructor
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    jest.spyOn(Logger.prototype, 'debug').mockImplementation(() => {});
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});

    jest.clearAllMocks();
    (MembershipTypeHelper.getByKey as jest.Mock).mockImplementation(
      (key: string) => {
        if (key === 'User') return 1;
        if (key === 'Group') return 2;
        return 0;
      },
    );

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GroupService,
        {
          provide: PRISMA_CLIENT_AUTHORIZATION,
          useValue: mockPrismaAuth,
        },
        {
          provide: PRISMA_CLIENT_COMMON_OLTP,
          useValue: mockPrismaCommonClient,
        },
      ],
    }).compile();

    service = module.get<GroupService>(GroupService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  const sampleGroupDb = {
    id: 1,
    name: 'Test Group',
    description: 'A test group',
    privateGroup: true,
    selfRegister: false,
    createdBy: 1,
    createdAt: new Date(),
    modifiedBy: 1,
    modifiedAt: new Date(),
  };

  const sampleGroupResponseDto: GroupResponseDto = {
    id: 1,
    name: 'Test Group',
    description: 'A test group',
    privateGroup: true,
    selfRegister: false,
    createdBy: 1,
    createdAt: sampleGroupDb.createdAt,
    modifiedBy: 1,
    modifiedAt: sampleGroupDb.modifiedAt,
  };

  const sampleGroupMembershipDb: GroupMembership & {
    group?: { name: string };
  } = {
    id: 1,
    groupId: 1,
    memberId: 2,
    membershipType: MembershipType.User, // User
    createdBy: 1,
    createdAt: new Date(),
    modifiedBy: 1,
    modifiedAt: new Date(),
  };
  const sampleGroupMembershipWithGroupDb: GroupMembership & {
    group: { name: string };
  } = {
    ...sampleGroupMembershipDb,
    group: { name: 'Test Group' },
  };

  const sampleGroupMembershipResponseDto: GroupMembershipResponseDto = {
    id: 1,
    groupId: 1,
    memberId: 2,
    membershipType: 'user', // Assuming 'User' is the string representation of membershipType 1
    createdBy: 1,
    createdAt: sampleGroupMembershipDb.createdAt,
    modifiedBy: 1,
    modifiedAt: sampleGroupMembershipDb.modifiedAt,
  };

  describe('create', () => {
    const groupData: GroupDto = {
      name: 'New Group',
      description: 'A new group',
    };

    it('should throw BadRequestException when user is null', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null); // groupExists check

      // Test should expect an exception to be thrown
      await expect(service.create(groupData, null)).rejects.toThrow(
        new BadRequestException('Authentication user is mandatory.'),
      );

      // Verify that create method was NOT called since authentication failed
      expect(mockPrismaAuth.group.create).not.toHaveBeenCalled();
    });

    it('should allow admin to create a group', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null); // groupExists check
      mockPrismaAuth.group.create.mockResolvedValue({
        ...sampleGroupDb,
        ...groupData,
        id: 2,
        createdBy: Number(mockAdminUser.userId),
      });

      const result = await service.create(groupData, mockAdminUser);
      expect(mockPrismaAuth.group.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            name: groupData.name,
            createdBy: Number(mockAdminUser.userId),
          }),
        }),
      );
      expect(result.name).toEqual(groupData.name);
    });

    it('should allow machine user with write scopes to create a group', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      mockPrismaAuth.group.create.mockResolvedValue({
        ...sampleGroupDb,
        ...groupData,
        id: 2,
        createdBy: null,
      }); // Machine user sets createdBy to null

      const result = await service.create(
        groupData,
        mockMachineUserWithWriteScope,
      );
      expect(mockPrismaAuth.group.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            name: groupData.name,
            createdBy: null,
          }),
        }),
      );
      expect(result.name).toEqual(groupData.name);
    });

    it('should throw ConflictException if group name already exists', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb); // groupExists returns true
      await expect(service.create(groupData, mockAdminUser)).rejects.toThrow(
        ConflictException,
      );
    });

    it('should throw ConflictException if group ID already exists when provided', async () => {
      const groupDataWithId: GroupDto = {
        id: 1,
        name: 'New Group Conflict ID',
        description: 'A new group',
      };
      mockPrismaAuth.group.findUnique.mockResolvedValueOnce(null); // for name check
      mockPrismaAuth.group.findUnique.mockResolvedValueOnce(sampleGroupDb); // for ID check
      await expect(
        service.create(groupDataWithId, mockAdminUser),
      ).rejects.toThrow(ConflictException);
    });

    it('should throw ForbiddenException if non-admin user tries to create a group', async () => {
      await expect(service.create(groupData, mockRegularUser)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('should throw ForbiddenException if machine user without write scopes tries to create a group', async () => {
      await expect(
        service.create(groupData, mockMachineUserWithoutScope),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw InternalServerErrorException on prisma create error', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      mockPrismaAuth.group.create.mockRejectedValue(new Error('DB error'));
      await expect(service.create(groupData, mockAdminUser)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('createSecurityGroup', () => {
    const securityData: SecurityGroups = {
      id: 100,
      name: 'SG_Test',
      createuserId: 1,
    };
    const authUser = mockAdminUser;

    it('should create a security group for admin user', async () => {
      mockPrismaCommonClient.security_groups.findFirst.mockResolvedValue(null); // name check
      mockPrismaCommonClient.security_groups.findUnique.mockResolvedValue(null); // id check
      mockPrismaCommonClient.security_groups.create.mockResolvedValue({
        group_id: securityData.id,
        description: securityData.name,
        create_user_id: Number(authUser.userId),
      });

      const result = await service.createSecurityGroup(securityData, authUser);
      expect(result.securityGroups.name).toEqual(securityData.name);
      expect(
        mockPrismaCommonClient.security_groups.create,
      ).toHaveBeenCalledWith({
        data: {
          group_id: securityData.id,
          description: securityData.name,
          create_user_id: Number(authUser.userId),
        },
      });
    });

    it('should throw ConflictException if security group name already exists', async () => {
      mockPrismaCommonClient.security_groups.findFirst.mockResolvedValue({
        group_id: 99,
        description: securityData.name,
      });
      await expect(
        service.createSecurityGroup(securityData, authUser),
      ).rejects.toThrow(ConflictException);
    });

    it('should throw ConflictException if security group ID already exists', async () => {
      mockPrismaCommonClient.security_groups.findFirst.mockResolvedValue(null);
      mockPrismaCommonClient.security_groups.findUnique.mockResolvedValue({
        group_id: securityData.id,
        description: 'Other SG',
      });
      await expect(
        service.createSecurityGroup(securityData, authUser),
      ).rejects.toThrow(ConflictException);
    });

    it('should throw ForbiddenException for non-admin user', async () => {
      await expect(
        service.createSecurityGroup(securityData, mockRegularUser),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw InternalServerErrorException on prisma create error', async () => {
      mockPrismaCommonClient.security_groups.findFirst.mockResolvedValue(null);
      mockPrismaCommonClient.security_groups.findUnique.mockResolvedValue(null);
      mockPrismaCommonClient.security_groups.create.mockRejectedValue(
        new Error('DB error'),
      );
      await expect(
        service.createSecurityGroup(securityData, authUser),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('findGroupById', () => {
    it('should return a group if found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      const group = await service.findGroupById(1);
      expect(group).toEqual(sampleGroupDb);
      expect(mockPrismaAuth.group.findUnique).toHaveBeenCalledWith({
        where: { id: 1 },
      });
    });

    it('should return null if group not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      const group = await service.findGroupById(99);
      expect(group).toBeNull();
    });

    it('should throw InternalServerErrorException on prisma error', async () => {
      mockPrismaAuth.group.findUnique.mockRejectedValue(new Error('DB error'));
      await expect(service.findGroupById(1)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('update', () => {
    const groupId = 1;
    const updateData: Partial<GroupDto> = { name: 'Updated Group Name' };

    it('should allow admin to update a group', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValueOnce(sampleGroupDb); // existing group
      mockPrismaAuth.group.findUnique.mockResolvedValueOnce(null); // name conflict check
      mockPrismaAuth.group.update.mockResolvedValue({
        ...sampleGroupDb,
        ...updateData,
        modifiedBy: Number(mockAdminUser.userId),
      });

      const result = await service.update(groupId, updateData, mockAdminUser);
      expect(result.name).toEqual(updateData.name);
      expect(mockPrismaAuth.group.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: groupId },
          data: expect.objectContaining({
            name: updateData.name,
            modifiedBy: Number(mockAdminUser.userId),
          }),
        }),
      );
    });

    it('should throw BadRequestException if no update data provided', async () => {
      await expect(service.update(groupId, {}, mockAdminUser)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw NotFoundException if group to update does not exist', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(
        service.update(groupId, updateData, mockAdminUser),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ConflictException if updated group name already exists', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValueOnce(sampleGroupDb); // existing group
      mockPrismaAuth.group.findUnique.mockResolvedValueOnce({
        ...sampleGroupDb,
        id: 2,
        name: updateData.name,
      }); // name conflict
      await expect(
        service.update(groupId, updateData, mockAdminUser),
      ).rejects.toThrow(ConflictException);
    });

    it('should throw ForbiddenException for non-admin user', async () => {
      await expect(
        service.update(groupId, updateData, mockRegularUser),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw InternalServerErrorException on prisma update error', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValueOnce(sampleGroupDb);
      mockPrismaAuth.group.findUnique.mockResolvedValueOnce(null);
      mockPrismaAuth.group.update.mockRejectedValue(new Error('DB Error'));
      await expect(
        service.update(groupId, updateData, mockAdminUser),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('deleteGroupAndMemberships', () => {
    const groupId = 1;

    it('should allow admin to delete a group and its memberships', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.deleteMany.mockResolvedValue({ count: 5 });
      mockPrismaAuth.group.delete.mockResolvedValue(sampleGroupDb);

      const result = await service.deleteGroupAndMemberships(
        groupId,
        mockAdminUser,
      );
      expect(result).toEqual(sampleGroupDb);
      expect(mockPrismaAuth.$transaction).toHaveBeenCalled();
      expect(mockPrismaAuth.groupMembership.deleteMany).toHaveBeenCalledWith({
        where: { groupId },
      });
      expect(mockPrismaAuth.group.delete).toHaveBeenCalledWith({
        where: { id: groupId },
      });
    });

    it('should throw NotFoundException if group to delete is not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(
        service.deleteGroupAndMemberships(groupId, mockAdminUser),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException for non-admin user', async () => {
      await expect(
        service.deleteGroupAndMemberships(groupId, mockRegularUser),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw InternalServerErrorException on transaction error', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.$transaction.mockRejectedValueOnce(
        new Error('Transaction failed'),
      );
      await expect(
        service.deleteGroupAndMemberships(groupId, mockAdminUser),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('findMembershipByGroupAndMember', () => {
    const groupId = 1;
    const memberId = 2;

    it('should return membership if found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb); // Group exists
      mockPrismaAuth.groupMembership.findFirst.mockResolvedValue(
        sampleGroupMembershipWithGroupDb,
      );

      const result = await service.findMembershipByGroupAndMember(
        groupId,
        memberId,
      );
      expect(result).toEqual(
        expect.objectContaining({
          id: sampleGroupMembershipDb.id,
          groupId,
          memberId,
        }),
      );
      expect(mockPrismaAuth.groupMembership.findFirst).toHaveBeenCalledWith({
        where: { groupId, memberId },
        include: { group: { select: { name: true } } },
      });
    });

    it('should return null if membership not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.findFirst.mockResolvedValue(null);
      const result = await service.findMembershipByGroupAndMember(
        groupId,
        memberId,
      );
      expect(result).toBeNull();
    });

    it('should throw NotFoundException if group not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(
        service.findMembershipByGroupAndMember(groupId, memberId),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw InternalServerErrorException on prisma error', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.findFirst.mockRejectedValue(
        new Error('DB error'),
      );
      await expect(
        service.findMembershipByGroupAndMember(groupId, memberId),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('getMemberCount', () => {
    const groupId = 1;

    it('should return member count for a group', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.count.mockResolvedValue(5);

      const count = await service.getMemberCount(groupId, false);
      expect(count).toEqual(5);
      expect(mockPrismaAuth.groupMembership.count).toHaveBeenCalledWith({
        where: { groupId: { in: [groupId] }, membershipType: 1 },
      });
    });

    it('should return member count including subgroups', async () => {
      const groupId = 1;
      const subGroupId = 2;
      const groupWithSubgroups = {
        ...sampleGroupDb,
        id: groupId,
        subGroups: [{ ...sampleGroupDb, id: subGroupId }],
      };

      mockPrismaAuth.group.findUnique.mockResolvedValueOnce(groupWithSubgroups); // Initial group fetch
      mockPrismaAuth.groupMembership.findMany.mockResolvedValueOnce([
        { memberId: subGroupId },
      ]); // group -> subGroup
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([
        { ...sampleGroupDb, id: subGroupId },
      ]); // fetch subGroup
      mockPrismaAuth.groupMembership.findMany.mockResolvedValueOnce([]); // subGroup has no further subgroups

      mockPrismaAuth.groupMembership.count.mockResolvedValue(10);

      const count = await service.getMemberCount(groupId, true, 1);
      expect(count).toEqual(10);
    });

    it('should throw NotFoundException if group not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(service.getMemberCount(groupId, false)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw InternalServerErrorException on prisma count error', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.count.mockRejectedValue(
        new Error('DB error'),
      );
      await expect(service.getMemberCount(groupId, false)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('isMemberOfGroup', () => {
    const memberId = 1;
    const groupId = 1;
    const membershipType = 1;

    it('should return true if member is part of the group', async () => {
      mockPrismaAuth.groupMembership.count.mockResolvedValue(1);
      const result = await service.isMemberOfGroup(
        memberId,
        groupId,
        membershipType,
      );
      expect(result).toBe(true);
      expect(mockPrismaAuth.groupMembership.count).toHaveBeenCalledWith({
        where: { groupId, memberId, membershipType },
      });
    });

    it('should return false if member is not part of the group', async () => {
      mockPrismaAuth.groupMembership.count.mockResolvedValue(0);
      const result = await service.isMemberOfGroup(
        memberId,
        groupId,
        membershipType,
      );
      expect(result).toBe(false);
    });

    it('should throw InternalServerErrorException on prisma error', async () => {
      mockPrismaAuth.groupMembership.count.mockRejectedValue(
        new Error('DB error'),
      );
      await expect(
        service.isMemberOfGroup(memberId, groupId, membershipType),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('addMemberToGroup', () => {
    const groupId = 1;
    const memberData: GroupMemberDto = {
      memberId: 2,
      membershipType: Constants.memberGroupMembershipName,
      createdAt: new Date(),
      createdBy: '1',
      groupId: groupId,
    }; // User type

    it('should allow admin to add a member', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.count.mockResolvedValue(0); // Membership does not exist
      mockPrismaAuth.groupMembership.create.mockResolvedValue(
        sampleGroupMembershipWithGroupDb,
      );
      (MembershipTypeHelper.getByKey as jest.Mock).mockReturnValue(1);

      const result = await service.addMemberToGroup(
        mockAdminUser,
        groupId,
        memberData,
      );
      expect(result).toEqual(
        expect.objectContaining(sampleGroupMembershipResponseDto),
      );
      expect(mockPrismaAuth.groupMembership.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          groupId,
          memberId: memberData.memberId,
          membershipType: 1,
          createdBy: Number(mockAdminUser.userId),
        }),
        include: { group: { select: { name: true } } },
      });
    });

    it('should throw NotFoundException if group not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(
        service.addMemberToGroup(mockAdminUser, groupId, memberData),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ConflictException if member already exists in group', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.count.mockResolvedValue(1); // Membership exists
      await expect(
        service.addMemberToGroup(mockAdminUser, groupId, memberData),
      ).rejects.toThrow(ConflictException);
    });

    it('should throw ForbiddenException if non-admin tries to add another member to non-selfRegister group', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue({
        ...sampleGroupDb,
        selfRegister: false,
      });
      mockPrismaAuth.groupMembership.count.mockResolvedValue(0);
      await expect(
        service.addMemberToGroup(mockRegularUser, groupId, {
          memberId: 3,
          groupId: groupId,
          createdBy: mockRegularUser.userId,
          createdAt: new Date(),
        }),
      ).rejects.toThrow(Error);
    });

    it('should throw ForbiddenException if machine user has no write scope', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.count.mockResolvedValue(0);
      await expect(
        service.addMemberToGroup(
          mockMachineUserWithoutScope,
          groupId,
          memberData,
        ),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw InternalServerErrorException on prisma create error', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.count.mockResolvedValue(0);
      mockPrismaAuth.groupMembership.create.mockRejectedValue(
        new Error('DB error'),
      );
      await expect(
        service.addMemberToGroup(mockAdminUser, groupId, memberData),
      ).rejects.toThrow(InternalServerErrorException);
    });

    it('should throw Error when memberId is null', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);

      const memberDataWithNullId: GroupMemberDto = {
        memberId: null,
        membershipType: MembershipType.User,
        createdAt: new Date(),
        createdBy: '1',
        groupId: groupId,
      };

      await expect(
        service.addMemberToGroup(mockAdminUser, groupId, memberDataWithNullId),
      ).rejects.toThrow('Mandatory field missing: memberId');
    });
  });

  describe('removeMembershipById', () => {
    const groupId = 1;
    const membershipId = 1;

    it('should allow admin to remove a membership', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.findUnique.mockResolvedValue(
        sampleGroupMembershipDb,
      );
      mockPrismaAuth.groupMembership.delete.mockResolvedValue(
        sampleGroupMembershipDb,
      );

      const result = await service.removeMembershipById(
        mockAdminUser,
        groupId,
        membershipId,
      );
      expect(result).toEqual(
        expect.objectContaining(sampleGroupMembershipResponseDto),
      );
      expect(mockPrismaAuth.groupMembership.delete).toHaveBeenCalledWith({
        where: { id: membershipId },
      });
    });

    it('should allow user to remove their own membership if group has selfRegister true', async () => {
      const selfRegisterGroup = { ...sampleGroupDb, selfRegister: true };
      const selfUser = {
        ...mockRegularUser,
        userId: String(sampleGroupMembershipDb.memberId),
      }; // User is the member
      mockPrismaAuth.group.findUnique.mockResolvedValue(selfRegisterGroup);
      mockPrismaAuth.groupMembership.findUnique.mockResolvedValue(
        sampleGroupMembershipDb,
      );
      mockPrismaAuth.groupMembership.delete.mockResolvedValue(
        sampleGroupMembershipDb,
      );

      const result = await service.removeMembershipById(
        selfUser,
        groupId,
        membershipId,
      );
      expect(result.id).toBe(membershipId);
    });

    it('should throw NotFoundException if group not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(
        service.removeMembershipById(mockAdminUser, groupId, membershipId),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException if membership not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.findUnique.mockResolvedValue(null);
      await expect(
        service.removeMembershipById(mockAdminUser, groupId, membershipId),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException if membership does not belong to group', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.findUnique.mockResolvedValue({
        ...sampleGroupMembershipDb,
        groupId: 2,
      });
      await expect(
        service.removeMembershipById(mockAdminUser, groupId, membershipId),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw ForbiddenException if non-admin tries to remove another member from non-selfRegister group', async () => {
      const nonSelfRegisterGroup = { ...sampleGroupDb, selfRegister: false };
      const otherUser = { ...mockRegularUser, userId: '99' }; // Not the member, not admin
      mockPrismaAuth.group.findUnique.mockResolvedValue(nonSelfRegisterGroup);
      mockPrismaAuth.groupMembership.findUnique.mockResolvedValue(
        sampleGroupMembershipDb,
      ); // memberId is 2
      await expect(
        service.removeMembershipById(otherUser, groupId, membershipId),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw InternalServerErrorException on prisma delete error', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.findUnique.mockResolvedValue(
        sampleGroupMembershipDb,
      );
      mockPrismaAuth.groupMembership.delete.mockRejectedValue(
        new Error('DB error'),
      );
      await expect(
        service.removeMembershipById(mockAdminUser, groupId, membershipId),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('getGroupByGroupId', () => {
    const groupId = 1;

    it('should return group for admin user', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      const result = await service.getGroupByGroupId(groupId, mockAdminUser);
      expect(result).toEqual(sampleGroupResponseDto);
    });

    it('should return public group for any authenticated user', async () => {
      const publicGroup = { ...sampleGroupDb, privateGroup: false };
      mockPrismaAuth.group.findUnique.mockResolvedValue(publicGroup);
      const result = await service.getGroupByGroupId(groupId, mockRegularUser);
      expect(result.id).toEqual(groupId);
    });

    it('should return private group if user is a member', async () => {
      const privateGroup = { ...sampleGroupDb, privateGroup: true };
      mockPrismaAuth.group.findUnique.mockResolvedValue(privateGroup);
      mockPrismaAuth.groupMembership.count.mockResolvedValue(1); // User is a member
      const result = await service.getGroupByGroupId(groupId, mockRegularUser);
      expect(result.id).toEqual(groupId);
    });

    it('should throw NotFoundException if group not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(
        service.getGroupByGroupId(groupId, mockAdminUser),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException if user tries to access private group without membership or admin role', async () => {
      const privateGroup = { ...sampleGroupDb, privateGroup: true };
      mockPrismaAuth.group.findUnique.mockResolvedValue(privateGroup);
      mockPrismaAuth.groupMembership.count.mockResolvedValue(0); // User is NOT a member
      await expect(
        service.getGroupByGroupId(groupId, mockRegularUser),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should allow machine user with read scopes to access private group', async () => {
      const privateGroup = { ...sampleGroupDb, privateGroup: true };
      mockPrismaAuth.group.findUnique.mockResolvedValue(privateGroup);

      const result = await service.getGroupByGroupId(
        1,
        mockMachineUserWithReadScope,
      );

      expect(result.id).toEqual(1);
      expect(mockPrismaAuth.group.findUnique).toHaveBeenCalledWith({
        where: { id: 1 },
      });
    });
  });

  describe('getGroupById (Hierarchy)', () => {
    const groupId = 1;
    const subGroupId = 2;

    it('should get group without subgroups', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      const result = await service.getGroupById(
        groupId,
        mockAdminUser,
        false,
        false,
      );
      expect(result.id).toBe(groupId);
      expect(result.subGroups).toEqual([]); // or undefined based on mapping
      expect(mockPrismaAuth.groupMembership.findMany).not.toHaveBeenCalled();
    });

    it('should get group with one level of subgroups', async () => {
      const parentGroupData = { ...sampleGroupDb, id: groupId };
      const subGroupData = {
        ...sampleGroupDb,
        id: subGroupId,
        name: 'SubGroup 1',
      };
      mockPrismaAuth.group.findUnique.mockResolvedValue(parentGroupData);
      // Mock for getSubGroupsRecursively (depth 1)
      mockPrismaAuth.groupMembership.findMany.mockResolvedValueOnce([
        { memberId: subGroupId },
      ]); // Parent has subGroup
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([subGroupData]); // Fetch subGroup
      // subGroup has no further subgroups for this call path
      mockPrismaAuth.groupMembership.findMany.mockResolvedValueOnce([]);

      const result = await service.getGroupById(
        groupId,
        mockAdminUser,
        true,
        true,
      ); // includeSubGroups = true, oneLevel = true
      expect(result.id).toBe(groupId);
      expect(result.subGroups).toHaveLength(1);
      expect(result.subGroups[0].id).toBe(subGroupId);
      expect(result.subGroups[0].subGroups).toEqual([]); // Max depth reached for subGroup
    });

    it('should throw NotFoundException if group not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(
        service.getGroupById(groupId, mockAdminUser, true, false),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('getParentGroupByGroupId', () => {
    const childGroupId = 2;
    const parentGroupId = 2;

    it('should get parent group (one level)', async () => {
      const childGroupData = {
        ...sampleGroupDb,
        id: childGroupId,
        name: 'Child',
      };
      const parentGroupData = {
        ...sampleGroupDb,
        id: parentGroupId,
        name: 'Parent',
      };

      mockPrismaAuth.group.findUnique.mockResolvedValue(childGroupData); // Find child
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([parentGroupData]); // findPrimaryParentGroup for child

      const result = await service.getParentGroupByGroupId(
        childGroupId,
        mockAdminUser,
        true,
      ); // oneLevel = true
      expect(result).not.toBeNull();
      expect(result.id).toBe(parentGroupId);
      expect(result.parentGroup).toBeUndefined(); // Parent of parent not fetched
    });

    it('should get parent group with all its parents recursively', async () => {
      const group1 = { ...sampleGroupDb, id: 1, name: 'G1-GrandParent' };
      const group2 = { ...sampleGroupDb, id: 2, name: 'G2-Parent' };
      const group3 = { ...sampleGroupDb, id: 3, name: 'G3-Child' };

      mockPrismaAuth.group.findUnique.mockResolvedValue(group3); // Find child G3

      // G3's parent is G2
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([group2]);
      // G2's parent is G1 (recursive call in getParentGroupsRecursively)
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([group1]);
      // G1 has no parent
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([]);

      const result = await service.getParentGroupByGroupId(
        3,
        mockAdminUser,
        false,
      ); // oneLevel = false
      expect(result).not.toBeNull();
      expect(result.id).toBe(2); // Direct parent
    });

    it('should return null if no parent group found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb); // Child group exists
      mockPrismaAuth.group.findMany.mockResolvedValue([]); // No parent found

      const result = await service.getParentGroupByGroupId(
        childGroupId,
        mockAdminUser,
        true,
      );
      expect(result).toBeNull();
    });

    it('should throw NotFoundException if child group not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(
        service.getParentGroupByGroupId(childGroupId, mockAdminUser, true),
      ).rejects.toThrow(NotFoundException);
    });
    it('should throw InternalServerErrorException when database query fails in findPrimaryParentGroup', async () => {
      // Arrange
      const childMemberId = 123;
      const membershipType = 2;
      const dbError = new Error('Database connection failed');

      mockPrismaAuth.group.findMany.mockRejectedValue(dbError);
      const loggerErrorSpy = jest.spyOn(service['logger'], 'error');

      // Act & Assert
      await expect(
        service['findPrimaryParentGroup'](childMemberId, membershipType),
      ).rejects.toThrow(InternalServerErrorException);

      expect(loggerErrorSpy).toHaveBeenCalledWith(
        `Error finding primary parent group for child ID ${childMemberId}: ${dbError.message}`,
        dbError.stack,
      );

      expect(mockPrismaAuth.group.findMany).toHaveBeenCalledWith({
        where: {
          memberships: { some: { memberId: childMemberId, membershipType } },
        },
        orderBy: { id: 'asc' },
      });

      loggerErrorSpy.mockRestore();
    });
  });

  describe('getSubGroupsRecursivelyOrignal', () => {
    // Using a structure similar to sampleGroupDb for group objects
    const baseGroupData = {
      description: 'A test group',
      privateGroup: true,
      selfRegister: false,
      createdBy: 1,
      createdAt: new Date(),
      modifiedBy: 1,
      modifiedAt: new Date(),
    };

    // Define a type for the group objects used in this test for clarity
    interface TestGroup {
      id: number;
      name: string;
      subGroups?: TestGroup[];
      description?: string;
      privateGroup?: boolean;
      selfRegister?: boolean;
      createdBy?: number | null;
      createdAt?: Date;
      modifiedBy?: number | null;
      modifiedAt?: Date;
    }

    it('should correctly populate subgroups recursively for multiple levels', async () => {
      const parentGroup: TestGroup = {
        ...baseGroupData,
        id: 1,
        name: 'G1',
        subGroups: [],
      };
      const subGroupL1: TestGroup = {
        ...baseGroupData,
        id: 2,
        name: 'G1_Sub1',
        subGroups: [],
      };
      const subGroupL2: TestGroup = {
        ...baseGroupData,
        id: 3,
        name: 'G1_Sub1_Sub1',
        subGroups: [],
      };

      // Mock Prisma responses:
      // 1. For parentGroup (G1), find its subgroups (subGroupL1)
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([
        subGroupL1,
      ] as any[]);
      // 2. For subGroupL1, find its subgroups (subGroupL2)
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([
        subGroupL2,
      ] as any[]);
      // 3. For subGroupL2, find its subgroups (none)
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([]);

      await service.getSubGroupsRecursivelyOrignal(parentGroup as any);

      expect(mockPrismaAuth.group.findMany).toHaveBeenCalledTimes(3);
      expect(mockPrismaAuth.group.findMany).toHaveBeenNthCalledWith(1, {
        where: {
          memberships: { some: { groupId: parentGroup.id, membershipType: 2 } },
        },
        orderBy: { id: 'asc' },
      });
      expect(mockPrismaAuth.group.findMany).toHaveBeenNthCalledWith(2, {
        where: {
          memberships: { some: { groupId: subGroupL1.id, membershipType: 2 } },
        },
        orderBy: { id: 'asc' },
      });
      expect(mockPrismaAuth.group.findMany).toHaveBeenNthCalledWith(3, {
        where: {
          memberships: { some: { groupId: subGroupL2.id, membershipType: 2 } },
        },
        orderBy: { id: 'asc' },
      });

      expect(parentGroup.subGroups).toBeDefined();
      expect(parentGroup.subGroups).toHaveLength(1);
      expect(parentGroup.subGroups[0].id).toBe(subGroupL1.id);
      expect(parentGroup.subGroups[0].name).toBe(subGroupL1.name);

      const foundSubGroupL1 = parentGroup.subGroups[0];
      expect(foundSubGroupL1.subGroups).toBeDefined();
      expect(foundSubGroupL1.subGroups).toHaveLength(1);
      expect(foundSubGroupL1.subGroups[0].id).toBe(subGroupL2.id);
      expect(foundSubGroupL1.subGroups[0].name).toBe(subGroupL2.name);

      const foundSubGroupL2 = foundSubGroupL1.subGroups[0];
      expect(foundSubGroupL2.subGroups).toBeDefined();
      expect(foundSubGroupL2.subGroups).toHaveLength(0);
    });

    it('should handle a parent group with no subgroups', async () => {
      const parentGroup: TestGroup = {
        ...baseGroupData,
        id: 10,
        name: 'G10_NoSubs',
        subGroups: [],
      };

      mockPrismaAuth.group.findMany.mockResolvedValueOnce([]); // No subgroups for G10

      await service.getSubGroupsRecursivelyOrignal(parentGroup as any);

      expect(mockPrismaAuth.group.findMany).toHaveBeenCalledTimes(1);
      expect(mockPrismaAuth.group.findMany).toHaveBeenCalledWith({
        where: {
          memberships: { some: { groupId: parentGroup.id, membershipType: 2 } },
        },
        orderBy: { id: 'asc' },
      });
      expect(parentGroup.subGroups).toBeDefined();
      expect(parentGroup.subGroups).toHaveLength(0);
    });

    it('should set subgroups to an empty array and log error if Prisma query fails', async () => {
      const parentGroup: TestGroup = {
        ...baseGroupData,
        id: 20,
        name: 'G20_ErrorCase',
        subGroups: [],
      };
      const dbError = new Error('Database query failed');
      mockPrismaAuth.group.findMany.mockRejectedValueOnce(dbError);

      const loggerErrorSpy = jest.spyOn(service['logger'], 'error');

      await service.getSubGroupsRecursivelyOrignal(parentGroup as any);

      expect(mockPrismaAuth.group.findMany).toHaveBeenCalledTimes(1);
      expect(mockPrismaAuth.group.findMany).toHaveBeenCalledWith({
        where: {
          memberships: { some: { groupId: parentGroup.id, membershipType: 2 } },
        },
        orderBy: { id: 'asc' },
      });
      expect(parentGroup.subGroups).toBeDefined();
      expect(parentGroup.subGroups).toHaveLength(0);
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        `Error in getSubGroupsRecursivelyOrignal for parent ${parentGroup.id}: ${dbError.message}`,
      );
      loggerErrorSpy.mockRestore();
    });

    it('should handle a parent group with one level of subgroups', async () => {
      const parentGroup: TestGroup = {
        ...baseGroupData,
        id: 30,
        name: 'G30_OneLevel',
        subGroups: [],
      };
      const subGroup1: TestGroup = {
        ...baseGroupData,
        id: 31,
        name: 'G30_Sub1',
        subGroups: [],
      };
      const subGroup2: TestGroup = {
        ...baseGroupData,
        id: 32,
        name: 'G30_Sub2',
        subGroups: [],
      };

      // Mock Prisma responses:
      // 1. For parentGroup (G30), find its subgroups (subGroup1, subGroup2)
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([
        subGroup1,
        subGroup2,
      ] as any[]);
      // 2. For subGroup1, find its subgroups (none)
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([]);
      // 3. For subGroup2, find its subgroups (none)
      mockPrismaAuth.group.findMany.mockResolvedValueOnce([]);

      await service.getSubGroupsRecursivelyOrignal(parentGroup as any);

      expect(mockPrismaAuth.group.findMany).toHaveBeenCalledTimes(3);
      expect(mockPrismaAuth.group.findMany).toHaveBeenNthCalledWith(1, {
        where: {
          memberships: { some: { groupId: parentGroup.id, membershipType: 2 } },
        },
        orderBy: { id: 'asc' },
      });
      expect(mockPrismaAuth.group.findMany).toHaveBeenNthCalledWith(2, {
        where: {
          memberships: { some: { groupId: subGroup1.id, membershipType: 2 } },
        },
        orderBy: { id: 'asc' },
      });
      expect(mockPrismaAuth.group.findMany).toHaveBeenNthCalledWith(3, {
        where: {
          memberships: { some: { groupId: subGroup2.id, membershipType: 2 } },
        },
        orderBy: { id: 'asc' },
      });

      expect(parentGroup.subGroups).toBeDefined();
      expect(parentGroup.subGroups).toHaveLength(2);
      expect(parentGroup.subGroups).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ id: subGroup1.id, subGroups: [] }),
          expect.objectContaining({ id: subGroup2.id, subGroups: [] }),
        ]),
      );
    });
  });

  describe('getMembers', () => {
    const groupId = 1;

    it('should return members for a public group to any user', async () => {
      const publicGroup = { ...sampleGroupDb, privateGroup: false };

      // Mock all the methods that getMembers calls
      mockPrismaAuth.groupMembership.findMany.mockResolvedValue([
        sampleGroupMembershipDb,
      ]);

      // Mock the service methods that are called internally
      const mockFind = jest
        .spyOn(service, 'findGroupById')
        .mockResolvedValue(publicGroup);

      const mapSpy = jest.spyOn(service as any, 'mapMembershipListToDto');
      if (mapSpy) {
        mapSpy.mockReturnValue([sampleGroupMembershipDb]);
      }

      const result = await service.getMembers(mockAdminUser, groupId);

      expect(result).toHaveLength(1);
      expect(mockFind).toHaveBeenCalledWith(groupId);
    });

    it('should throw BadRequestException if groupId is not provided', async () => {
      await expect(service.getMembers(mockAdminUser, null)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw NotFoundException if group not found', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      await expect(service.getMembers(mockAdminUser, groupId)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw ForbiddenException for private group if user is not admin and not member', async () => {
      const privateGroup = { ...sampleGroupDb, privateGroup: true };
      mockPrismaAuth.group.findUnique.mockResolvedValue(privateGroup);
      mockPrismaAuth.groupMembership.count.mockResolvedValue(0); // User is NOT member

      await expect(
        service.getMembers(mockRegularUser, groupId),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw InternalServerErrorException on prisma findMany error', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      mockPrismaAuth.groupMembership.findMany.mockRejectedValue(
        new Error('DB error'),
      );
      await expect(service.getMembers(mockAdminUser, groupId)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('getGroupByMember', () => {
    const memberId = 2;

    it('should return groups for the authenticated non-admin user', async () => {
      mockPrismaAuth.group.findMany.mockResolvedValue([sampleGroupDb]);
      jest.spyOn(MembershipTypeHelper, 'getByKey').mockReturnValueOnce(1);
      const result = await service.getGroupByMember(mockRegularUser, null, ''); // memberId and type ignored for non-admin
      expect(result).toHaveLength(1);
      expect(mockPrismaAuth.group.findMany).toHaveBeenCalledWith({
        where: {
          memberships: {
            some: {
              memberId: Number(mockRegularUser.userId),
              membershipType: 1,
            },
          },
        },
        orderBy: { id: 'asc' },
      });
    });

    it('should throw ForbiddenException for machine user without read scopes', async () => {
      await expect(
        service.getGroupByMember(mockMachineUserWithoutScope, memberId, 'user'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should allow machine user with read scopes to get all groups if no memberId/type', async () => {
      mockPrismaAuth.group.findMany.mockResolvedValue([sampleGroupDb]);
      await service.getGroupByMember(mockMachineUserWithReadScope, null, '');
      expect(mockPrismaAuth.group.findMany).toHaveBeenCalledWith({
        orderBy: { id: 'asc' },
      });
    });

    const expectedError = new BadRequestException(
      'Member ID and membership type are required.',
    );

    it('should throw BadRequestException for machine user if membershipType is provided but memberId is null', async () => {
      await expect(
        service.getGroupByMember(mockMachineUserWithReadScope, null, 'user'),
      ).rejects.toThrow(expectedError);
    });
  });

  describe('groupExists', () => {
    const groupName = 'Existing Group';

    it('should return true if group exists', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(sampleGroupDb);
      const exists = await service.groupExists(groupName);
      expect(exists).toBe(true);
      expect(mockPrismaAuth.group.findUnique).toHaveBeenCalledWith({
        where: { name: groupName },
      });
    });

    it('should return false if group does not exist', async () => {
      mockPrismaAuth.group.findUnique.mockResolvedValue(null);
      const exists = await service.groupExists('Non Existing Group');
      expect(exists).toBe(false);
    });

    it('should throw InternalServerErrorException on prisma error', async () => {
      mockPrismaAuth.group.findUnique.mockRejectedValue(new Error('DB error'));
      await expect(service.groupExists(groupName)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });
});
