import { Test, TestingModule } from '@nestjs/testing';
import { GroupController } from './group.controller';
import { GroupService } from './group.service';
import { AuthGuard } from '@nestjs/passport';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { AuthenticatedUser, JwtPayload } from '../../core/auth/jwt.strategy';
import {
  GroupBodyDto,
  GroupDto,
  GroupResponseDto,
  SecurityBodyDto,
  SecurityGroups,
  SecurityGroupsResponseDto,
} from '../../dto/group/group.dto';
import {
  GroupMemberBodyDto,
  GroupMemberDto,
  GroupMembershipResponseDto,
} from '../../dto/group/group-membership.dto';
import { createBaseResponse } from '../../shared/util/responseBuilder';

const sampleGroupResponse: GroupResponseDto = {
  id: 1,
  name: 'Test Group From Service',
  description: 'A test group description from service',
  privateGroup: true,
  selfRegister: false,
  createdBy: 1,
  createdAt: new Date(),
  modifiedBy: 1,
  modifiedAt: new Date(),
};

const sampleSecurityGroupsResponse: SecurityGroupsResponseDto = {
  securityGroups: {
    id: 100,
    name: 'Test_SG_From_Service',
    createuserId: 1,
  },
};

const sampleGroupMembershipResponse: GroupMembershipResponseDto = {
  id: 1,
  groupId: 1,
  memberId: 2,
  membershipType: 'user',
  createdBy: 1,
  createdAt: new Date(),
  modifiedBy: 1,
  modifiedAt: new Date(),
};

const mockGroupService = {
  create: jest
    .fn<Promise<GroupResponseDto>, [GroupDto, AuthenticatedUser]>()
    .mockResolvedValue(sampleGroupResponse),
  createSecurityGroup: jest
    .fn<
      Promise<SecurityGroupsResponseDto>,
      [SecurityGroups, AuthenticatedUser]
    >()
    .mockResolvedValue(sampleSecurityGroupsResponse),
  findMembershipByGroupAndMember: jest
    .fn<Promise<GroupMembershipResponseDto | null>, [number, number]>()
    .mockResolvedValue(sampleGroupMembershipResponse),
  getMemberCount: jest
    .fn<Promise<number>, [number, boolean | undefined, number]>()
    .mockResolvedValue(5),
  update: jest
    .fn<
      Promise<GroupResponseDto>,
      [number, Partial<GroupDto>, AuthenticatedUser]
    >()
    .mockResolvedValue(sampleGroupResponse),
  deleteGroupAndMemberships: jest
    .fn<Promise<GroupResponseDto>, [number, AuthenticatedUser]>()
    .mockResolvedValue(sampleGroupResponse),
  getGroupByGroupId: jest
    .fn<Promise<GroupResponseDto>, [number, AuthenticatedUser]>()
    .mockResolvedValue(sampleGroupResponse),
  addMemberToGroup: jest
    .fn<
      Promise<GroupMembershipResponseDto>,
      [AuthenticatedUser, number, GroupMemberDto]
    >()
    .mockResolvedValue(sampleGroupMembershipResponse),
  removeMembershipById: jest
    .fn<
      Promise<GroupMembershipResponseDto>,
      [AuthenticatedUser, number, number]
    >()
    .mockResolvedValue(sampleGroupMembershipResponse),
  getGroupById: jest
    .fn<
      Promise<GroupResponseDto>,
      [number, AuthenticatedUser, boolean, boolean]
    >()
    .mockResolvedValue(sampleGroupResponse),
  getParentGroupByGroupId: jest
    .fn<
      Promise<GroupResponseDto | null>,
      [number, AuthenticatedUser, boolean]
    >()
    .mockResolvedValue(sampleGroupResponse),
  getMembers: jest
    .fn<Promise<GroupMembershipResponseDto[]>, [AuthenticatedUser, number]>()
    .mockResolvedValue([sampleGroupMembershipResponse]),
  getGroupByMember: jest
    .fn<
      Promise<GroupResponseDto[]>,
      [AuthenticatedUser, number | null, string]
    >()
    .mockResolvedValue([sampleGroupResponse]),
};

const mockAdminJwtPayload: JwtPayload = {
  userId: '1',
  roles: ['admin'],
  scope: 'write:groups read:groups all:groups',
};
const mockAdminUser: AuthenticatedUser = {
  userId: '1',
  roles: ['admin', 'administrator'],
  scopes: ['write:groups', 'read:groups', 'all:groups'],
  isAdmin: true,
  isMachine: false,
  payload: mockAdminJwtPayload,
};

const mockRegularUserJwtPayload: JwtPayload = {
  userId: '2',
  roles: ['user'],
  scope: '',
};
const mockRegularUser: AuthenticatedUser = {
  userId: '2',
  roles: ['user'],
  scopes: [],
  isAdmin: false,
  isMachine: false,
  payload: mockRegularUserJwtPayload,
};

describe('GroupController', () => {
  let controller: GroupController;
  let service: GroupService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [GroupController],
      providers: [{ provide: GroupService, useValue: mockGroupService }],
    })
      .overrideGuard(AuthGuard('jwt'))
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<GroupController>(GroupController);
    service = module.get<GroupService>(GroupService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  const createMockRequest = (user: AuthenticatedUser): any => ({ user });

  const validGroupInput: GroupDto = {
    name: 'Valid Group',
    description: 'Valid Desc',
  };
  const validSecurityGroupInput: SecurityGroups = {
    id: 101,
    name: 'Valid SG',
    createuserId: 1,
  };
  const validMemberInput: GroupMemberDto = {
    memberId: 3,
    membershipType: 1,
    groupId: 1,
    createdAt: new Date(),
    createdBy: '1',
  };

  describe('createGroup', () => {
    it('should create a group with defaults', async () => {
      const req = createMockRequest(mockAdminUser);
      const groupBodyDto: GroupBodyDto = { param: validGroupInput };
      const expectedServiceData: GroupDto = {
        ...validGroupInput,
        privateGroup: true,
        selfRegister: false,
      };
      mockGroupService.create.mockResolvedValueOnce(sampleGroupResponse);

      const result = await controller.createGroup(groupBodyDto, req);

      expect(service.create).toHaveBeenCalledWith(
        expectedServiceData,
        mockAdminUser,
      );
      expect(result).toEqual(createBaseResponse(sampleGroupResponse, 201));
    });

    it('should throw BadRequestException if param is missing', async () => {
      const req = createMockRequest(mockAdminUser);
      await expect(
        controller.createGroup({} as GroupBodyDto, req),
      ).rejects.toThrow(BadRequestException);
      await expect(
        controller.createGroup({ param: null } as GroupBodyDto, req),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('createSecurityGroup', () => {
    it('should create a security group', async () => {
      const req = createMockRequest(mockAdminUser);
      const securityBodyDto: SecurityBodyDto = {
        param: validSecurityGroupInput,
      };
      mockGroupService.createSecurityGroup.mockResolvedValueOnce(
        sampleSecurityGroupsResponse,
      );

      const result = await controller.createSecurityGroup(securityBodyDto, req);
      expect(service.createSecurityGroup).toHaveBeenCalledWith(
        validSecurityGroupInput,
        mockAdminUser,
      );
      expect(result).toEqual(createBaseResponse(sampleSecurityGroupsResponse));
    });
  });

  describe('getSingleMember', () => {
    it('should return a member if found', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.findMembershipByGroupAndMember.mockResolvedValueOnce(
        sampleGroupMembershipResponse,
      );
      const result = await controller.getSingleMember(1, 2, req);
      expect(service.findMembershipByGroupAndMember).toHaveBeenCalledWith(1, 2);
      expect(result).toEqual(createBaseResponse(sampleGroupMembershipResponse));
    });

    it('should throw NotFoundException if member not found', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.findMembershipByGroupAndMember.mockResolvedValueOnce(
        null,
      );
      await expect(controller.getSingleMember(1, 99, req)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('getMembersCount', () => {
    it('should get member count with specified includeSubGroups', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.getMemberCount.mockResolvedValueOnce(10);
      const result = await controller.getMembersCount(req, 1, true);
      expect(service.getMemberCount).toHaveBeenCalledWith(1, true, 1);
      expect(result).toEqual(createBaseResponse({ count: 10 }));
    });

    it('should get member count with default includeSubGroups (undefined)', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.getMemberCount.mockResolvedValueOnce(5);
      const result = await controller.getMembersCount(req, 1, undefined);
      expect(service.getMemberCount).toHaveBeenCalledWith(1, undefined, 1);
      expect(result).toEqual(createBaseResponse({ count: 5 }));
    });
  });

  describe('updateGroup', () => {
    const groupId = 1;
    const updateData: Partial<GroupDto> = { description: 'Updated Desc' };
    const updateBodyDto: GroupBodyDto = {
      param: { name: 'Ensure Name For Update', ...updateData },
    }; // param needs to be full GroupDto

    it('should update a group', async () => {
      const req = createMockRequest(mockAdminUser);

      mockGroupService.update.mockResolvedValueOnce(sampleGroupResponse);

      const result = await controller.updateGroup(groupId, updateBodyDto, req);
      expect(service.update).toHaveBeenCalledWith(
        groupId,
        updateBodyDto.param,
        mockAdminUser,
      );
      expect(result).toEqual(createBaseResponse(sampleGroupResponse));
    });

    it('should throw BadRequestException if param is missing or null', async () => {
      const req = createMockRequest(mockAdminUser);
      await expect(
        controller.updateGroup(groupId, {} as GroupBodyDto, req),
      ).rejects.toThrow(BadRequestException);
      await expect(
        controller.updateGroup(groupId, { param: null } as GroupBodyDto, req),
      ).rejects.toThrow(BadRequestException);
    });

    it('should group param is null', async () => {
      const req = createMockRequest(mockAdminUser);
      const updateBodyDtoWithNullParam: GroupBodyDto = { param: null }; // param needs to be full GroupDto
      await expect(
        controller.updateGroup(groupId, updateBodyDtoWithNullParam, req),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('deleteGroup', () => {
    it('should delete a group', async () => {
      const req = createMockRequest(mockAdminUser);
      mockGroupService.deleteGroupAndMemberships.mockResolvedValueOnce(
        sampleGroupResponse,
      );
      const result = await controller.deleteGroup(1, req);
      expect(service.deleteGroupAndMemberships).toHaveBeenCalledWith(
        1,
        mockAdminUser,
      );
      expect(result).toEqual(createBaseResponse(sampleGroupResponse));
    });
  });

  describe('getGroupById', () => {
    it('should get a group by ID with fields', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.getGroupByGroupId.mockResolvedValueOnce(
        sampleGroupResponse,
      );
      const result = await controller.getGroupById(1, req, 'id');
      expect(service.getGroupByGroupId).toHaveBeenCalledWith(
        1,
        mockRegularUser,
      );
      expect(result).toEqual(
        createBaseResponse(sampleGroupResponse, 200, 'id'),
      );
    });

    it('should get a group by ID without fields', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.getGroupByGroupId.mockResolvedValueOnce(
        sampleGroupResponse,
      );
      const result = await controller.getGroupById(1, req, undefined);
      expect(service.getGroupByGroupId).toHaveBeenCalledWith(
        1,
        mockRegularUser,
      );
      expect(result).toEqual(
        createBaseResponse(sampleGroupResponse, 200, undefined),
      );
    });
  });

  describe('addMemberToGroup', () => {
    it('should add a member to a group', async () => {
      const req = createMockRequest(mockAdminUser);
      const memberBodyDto: GroupMemberBodyDto = { param: validMemberInput };
      mockGroupService.addMemberToGroup.mockResolvedValueOnce(
        sampleGroupMembershipResponse,
      );

      const result = await controller.addMemberToGroup(1, memberBodyDto, req);
      expect(service.addMemberToGroup).toHaveBeenCalledWith(
        mockAdminUser,
        1,
        validMemberInput,
      );
      expect(result).toEqual(createBaseResponse(sampleGroupMembershipResponse));
    });

    it('should throw BadRequestException if param is missing', async () => {
      const req = createMockRequest(mockAdminUser);
      await expect(
        controller.addMemberToGroup(1, {} as GroupMemberBodyDto, req),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('removeMemberFromGroup', () => {
    it('should remove a member from a group', async () => {
      const req = createMockRequest(mockAdminUser);
      mockGroupService.removeMembershipById.mockResolvedValueOnce(
        sampleGroupMembershipResponse,
      );
      const result = await controller.removeMemberFromGroup(1, 5, req);
      expect(service.removeMembershipById).toHaveBeenCalledWith(
        mockAdminUser,
        1,
        5,
      );
      expect(result).toEqual(createBaseResponse(sampleGroupMembershipResponse));
    });
  });

  describe('getGroupWithSubGroups', () => {
    it('should get group with default subGroup options', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.getGroupById.mockResolvedValueOnce(sampleGroupResponse);
      const result = await controller.getGroupWithSubGroups(
        req,
        1,
        undefined,
        undefined,
      );
      expect(service.getGroupById).toHaveBeenCalledWith(
        1,
        mockRegularUser,
        false,
        false,
      );
      expect(result).toEqual(createBaseResponse(sampleGroupResponse));
    });

    it('should get group with specified subGroup options', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.getGroupById.mockResolvedValueOnce(sampleGroupResponse);
      const result = await controller.getGroupWithSubGroups(req, 1, true, true);
      expect(service.getGroupById).toHaveBeenCalledWith(
        1,
        mockRegularUser,
        true,
        true,
      );
      expect(result).toEqual(createBaseResponse(sampleGroupResponse));
    });
  });

  describe('getParentGroupForChild', () => {
    it('should get parent group with default oneLevel', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.getParentGroupByGroupId.mockResolvedValueOnce(
        sampleGroupResponse,
      );
      const result = await controller.getParentGroupForChild(req, 1, undefined);
      expect(service.getParentGroupByGroupId).toHaveBeenCalledWith(
        1,
        mockRegularUser,
        true,
      );
      expect(result).toEqual(createBaseResponse(sampleGroupResponse));
    });

    it('should get parent group with oneLevel false', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.getParentGroupByGroupId.mockResolvedValueOnce(
        sampleGroupResponse,
      );
      const result = await controller.getParentGroupForChild(req, 1, false);
      expect(service.getParentGroupByGroupId).toHaveBeenCalledWith(
        1,
        mockRegularUser,
        false,
      );
      expect(result).toEqual(createBaseResponse(sampleGroupResponse));
    });

    it('should return base response with null if service returns null', async () => {
      const req = createMockRequest(mockRegularUser);
      mockGroupService.getParentGroupByGroupId.mockResolvedValueOnce(null);
      const result = await controller.getParentGroupForChild(req, 1, true);
      expect(result).toEqual(createBaseResponse(null));
    });
  });

  describe('getMemebrs', () => {
    it('should get members for a group', async () => {
      const req = createMockRequest(mockRegularUser);
      const membersList = [
        sampleGroupMembershipResponse,
        { ...sampleGroupMembershipResponse, id: 2 },
      ];
      mockGroupService.getMembers.mockResolvedValueOnce(membersList);

      const result = await controller.getMemebrs(req, 1);
      expect(service.getMembers).toHaveBeenCalledWith(mockRegularUser, 1);
      expect(result).toEqual(createBaseResponse(membersList));
    });
  });

  describe('getGroupByMember', () => {
    it('should get groups for a member', async () => {
      const req = createMockRequest(mockRegularUser);
      const groupsList = [sampleGroupResponse];
      mockGroupService.getGroupByMember.mockResolvedValueOnce(groupsList);

      const result = await controller.getGroupByMember(
        req,
        2,
        'membershipType' as string,
      );
      expect(service.getGroupByMember).toHaveBeenCalledWith(
        mockRegularUser,
        2,
        'membershipType',
      );
      expect(result).toEqual(createBaseResponse(groupsList));
    });
  });
});
