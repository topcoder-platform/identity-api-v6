import {
  Injectable,
  Inject,
  NotFoundException,
  ConflictException,
  Logger,
  InternalServerErrorException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import {
  PRISMA_CLIENT,
  PRISMA_CLIENT_GROUP,
} from '../../shared/prisma/prisma.module';
import {
  Prisma,
  PrismaClient,
  security_groups as PrismaSecurityGroupsFromDb,
} from '@prisma/client';
import {
  Prisma as PrismaGroup,
  Group as PrismaGroupFromDb,
  PrismaClient as PrismaClientGroup,
  GroupMembership,
} from '@prisma/client-group';

import {
  GroupResponseDto,
  GroupDto,
  SecurityGroups,
  SecurityGroupsResponseDto,
} from 'src/dto/group/group.dto';
import {
  GroupMemberDto,
  GroupMembershipResponseDto,
} from 'src/dto/group/group-membership.dto';
import { AuthenticatedUser } from 'src/core/auth/jwt.strategy';
import { MembershipTypeHelper } from './membership-type.enum';
import { Constants } from '../../core/constant/constants';

// Extended Group type with subGroups
interface Group extends PrismaGroupFromDb {
  subGroups?: Group[];
  parentGroup?: GroupWithParentForDto;
}

// Interface for Group DTO mapping that includes potential parent
interface GroupWithParentForDto extends Group {
  parentGroup?: GroupWithParentForDto;
}

@Injectable()
export class GroupService {
  private readonly writeScopes = ['write:groups', 'all:groups'];
  private readonly readScopes = ['read:groups', 'write:groups', 'all:groups'];
  private readonly adminRoles = ['administrator'];
  private readonly logger = new Logger(GroupService.name);

  constructor(
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient,
    @Inject(PRISMA_CLIENT_GROUP)
    private readonly groupClient: PrismaClientGroup,
  ) {}

  // --- UTILITY METHODS ---
  private checkAccessPermissions(
    user: AuthenticatedUser,
    requiredScopes: string[] | null,
    requiredRoles: string[] | null,
  ): void {
    if (!user) {
      throw new BadRequestException('Authentication user is mandatory.');
    }

    if (user.isMachine) {
      if (
        requiredScopes?.length &&
        !requiredScopes.some((scope) => user.scopes?.includes(scope))
      ) {
        throw new ForbiddenException('Insufficient scopes');
      }
    } else if (
      requiredRoles?.length &&
      !requiredRoles.some((role) => user.roles?.includes(role))
    ) {
      throw new ForbiddenException('Insufficient roles');
    }
  }

  private hasAdminRole(authUser: AuthenticatedUser | null): boolean {
    return (
      authUser?.roles?.some((role) => this.adminRoles.includes(role)) ?? false
    );
  }

  // --- DTO MAPPING METHODS ---

  private mapToGroupResponseDto(
    group: PrismaGroupFromDb | null,
  ): GroupResponseDto | null {
    if (!group) return null;
    const typedGroup = group as Required<PrismaGroupFromDb>;
    return {
      id: typedGroup.id,
      name: typedGroup.name,
      description: typedGroup.description,
      privateGroup: typedGroup.privateGroup,
      selfRegister: typedGroup.selfRegister,
      createdBy: typedGroup.createdBy,
      createdAt: typedGroup.createdAt,
      modifiedBy: typedGroup.modifiedBy,
      modifiedAt: typedGroup.modifiedAt,
    };
  }

  private mapDomainGroupToResponseDtoRecursive(group: Group): GroupResponseDto {
    const dto: GroupResponseDto = {
      ...this.mapToGroupResponseDto(group),
      subGroups:
        group.subGroups?.map((sg) =>
          this.mapDomainGroupToResponseDtoRecursive(sg),
        ) ?? [],
    };
    return dto;
  }

  private mapMembershipToDto(
    membership: GroupMembership & { group?: { name: string } },
  ): GroupMembershipResponseDto {
    const baseDto = {
      id: membership.id,
      groupId: membership.groupId,
      memberId: membership.memberId,
      membershipType: MembershipTypeHelper.lowerName(membership.membershipType),
      createdBy: membership.createdBy ?? null,
      createdAt: membership.createdAt ?? new Date(),
      modifiedBy: membership.modifiedBy ?? null,
      modifiedAt: membership.modifiedAt ?? new Date(),
    };

    const groupName = membership.group?.name;

    return {
      ...baseDto,
      ...(groupName && { groupName }),
    };
  }

  private mapPrismaMembershipToDto(
    membership: PrismaGroup.GroupMembershipGetPayload<{
      include: { group: { select: { name: true } } };
    }>,
  ): GroupMembershipResponseDto {
    return this.mapMembershipToDto(membership);
  }

  private mapMembershipListToDto(
    memberships: GroupMembership[],
  ): GroupMembershipResponseDto[] {
    return memberships.map((m) => this.mapMembershipToDto(m));
  }

  // --- CORE GROUP METHODS ---

  async create(
    groupData: GroupDto,
    authUser: AuthenticatedUser,
  ): Promise<GroupResponseDto> {
    this.checkAccessPermissions(authUser, this.writeScopes, this.adminRoles);
    this.logger.debug(
      `Creating group: ${groupData.name} by user: ${authUser.userId}`,
    );

    if (await this.groupExists(groupData.name)) {
      throw new ConflictException(
        `Group with name '${groupData.name}' already exists`,
      );
    }
    if (groupData.id && (await this.findGroupById(groupData.id))) {
      throw new ConflictException(
        `Group with ID '${groupData.id}' already exists`,
      );
    }

    const now = new Date();
    const dataToCreate: PrismaGroup.GroupCreateInput = {
      name: groupData.name,
      description: groupData.description,
      privateGroup: groupData.privateGroup ?? true,
      selfRegister: groupData.selfRegister ?? false,
      createdBy: authUser.isMachine ? null : Number(authUser.userId),
      createdAt: now,
    };

    try {
      const group = await this.groupClient.group.create({
        data: dataToCreate,
      });
      return this.mapToGroupResponseDto(group);
    } catch (error) {
      this.logger.error(`Error creating group: ${error.message}`, error.stack);
      throw new InternalServerErrorException(
        `Failed to create group '${groupData.name}'. Please try again later.`,
      );
    }
  }

  async createSecurityGroup(
    securityData: SecurityGroups,
    authUser: AuthenticatedUser,
  ): Promise<SecurityGroupsResponseDto> {
    this.logger.debug(
      `Creating security group: ${securityData.name} by user: ${authUser.userId}`,
    );

    this.checkAccessPermissions(authUser, this.writeScopes, this.adminRoles);

    if (await this.findSecurityGroupByName(securityData.name)) {
      throw new ConflictException(
        `Security group with name '${securityData.name}' already exists`,
      );
    }
    if (
      securityData.id &&
      (await this.findSecurityGroupById(securityData.id))
    ) {
      throw new ConflictException(
        `Security group with ID '${securityData.id}' already exists`,
      );
    }

    const dataToCreate: Prisma.security_groupsCreateInput = {
      group_id: securityData.id,
      description: securityData.name,
      create_user_id: authUser.isMachine ? null : Number(authUser.userId),
    };

    try {
      await this.prismaClient.security_groups.create({
        data: dataToCreate,
      });
      return { securityGroups: securityData };
    } catch (error) {
      this.logger.error(
        `Error creating security group: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to create security group '${securityData.name}'. Please try again later.`,
      );
    }
  }

  async findGroupById(id: number): Promise<Group | null> {
    this.logger.debug(`Finding group with ID: ${id}`);
    try {
      return (await this.groupClient.group.findUnique({
        where: { id },
      })) as Group | null;
    } catch (error) {
      this.logger.error(
        `Error finding group by ID ${id}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to find group with ID ${id}. Please try again later.`,
      );
    }
  }

  async getGroupOrThrow(id: number): Promise<Group> {
    this.logger.debug(`Validating group exists with ID: ${id}`);
    const group = await this.findGroupById(id);
    if (!group) {
      this.logger.warn(`Group with ID ${id} not found`);
      throw new NotFoundException(`Group with ID ${id} not found.`);
    }
    return group;
  }

  async update(
    groupId: number,
    groupUpdateData: Partial<GroupDto>,
    authUser: AuthenticatedUser,
  ): Promise<GroupResponseDto> {
    if (!Object.keys(groupUpdateData).length) {
      throw new BadRequestException('No update data provided.');
    }

    this.checkAccessPermissions(authUser, this.writeScopes, this.adminRoles);

    // const existingGroup = await this.findGroupById(groupId);
    // if (!existingGroup) {
    //   throw new NotFoundException(`Group with ID ${groupId} not found.`);
    // }
    const existingGroup = await this.getGroupOrThrow(groupId);

    if (groupUpdateData.name && groupUpdateData.name !== existingGroup.name) {
      if (await this.groupExists(groupUpdateData.name)) {
        throw new ConflictException(
          `Group with name '${groupUpdateData.name}' already exists.`,
        );
      }
    }

    const dataToUpdate: PrismaGroup.GroupUpdateInput = {
      modifiedAt: new Date(),
      modifiedBy: authUser.isMachine ? undefined : Number(authUser.userId),
      name: groupUpdateData.name ?? existingGroup.name,
      description: groupUpdateData.description ?? existingGroup.description,
      privateGroup: groupUpdateData.privateGroup ?? existingGroup.privateGroup,
      selfRegister: groupUpdateData.selfRegister ?? existingGroup.selfRegister,
    };

    try {
      const updatedGroup = await this.groupClient.group.update({
        where: { id: groupId },
        data: dataToUpdate,
      });
      return this.mapToGroupResponseDto(updatedGroup);
    } catch (error) {
      this.logger.error(
        `Error updating group ID ${groupId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to update group with ID ${groupId}. Please try again later.`,
      );
    }
  }

  async deleteGroupAndMemberships(
    groupId: number,
    user: AuthenticatedUser,
  ): Promise<Group> {
    this.logger.debug(
      `Attempting to delete group ID: ${groupId} and its memberships.`,
    );
    this.checkAccessPermissions(user, this.writeScopes, this.adminRoles);

    // const group = await this.findGroupById(groupId);
    // if (!group) {
    //   throw new NotFoundException(`Group with ID ${groupId} not found.`);
    // }
    const group = await this.getGroupOrThrow(groupId);

    try {
      await this.groupClient.$transaction(async (prisma) => {
        await prisma.groupMembership.deleteMany({ where: { groupId } });
        await prisma.group.delete({ where: { id: groupId } });
      });
      this.logger.debug(
        `Successfully deleted group ID: ${groupId} and its memberships.`,
      );
      return group;
    } catch (error) {
      this.logger.error(
        `Error deleting group ID ${groupId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to delete group with ID ${groupId}. Please try again later.`,
      );
    }
  }

  // --- GROUP MEMBERSHIP METHODS ---

  async findMembershipByGroupAndMember(
    groupId: number,
    memberId: number,
  ): Promise<GroupMembershipResponseDto | null> {
    this.logger.debug(
      `Finding membership for group ${groupId} and member ${memberId}`,
    );
    // const group = await this.findGroupById(groupId);
    // if (!group) {
    //   throw new NotFoundException(`Group with ID ${groupId} not found.`);
    // }
    await this.getGroupOrThrow(groupId);

    try {
      const membership = await this.groupClient.groupMembership.findFirst({
        where: { groupId, memberId },
        include: { group: { select: { name: true } } },
      });
      return membership ? this.mapPrismaMembershipToDto(membership) : null;
    } catch (error) {
      this.logger.error(
        `Error finding membership for group ${groupId} and member ${memberId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to find membership for group ${groupId} and member ${memberId}. Please try again later.`,
      );
    }
  }

  async getMemberCount(
    groupId: number,
    includeSubGroups: boolean,
    memberType: number = Constants.memberGroupMembershipType,
  ): Promise<number> {
    // const group = await this.findGroupById(groupId);
    // if (!group) {
    //   throw new NotFoundException(`Group with ID ${groupId} not found.`);
    // }
    const group = await this.getGroupOrThrow(groupId);

    const groupIds: number[] = [groupId];
    if (includeSubGroups) {
      await this.getSubGroupsRecursively(group);
      this.collectGroupIds(group, groupIds);
    }

    try {
      return await this.groupClient.groupMembership.count({
        where: { groupId: { in: groupIds }, membershipType: memberType },
      });
    } catch (error) {
      this.logger.error(
        `Error counting members for group ${groupId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to count members for group ${groupId}. Please try again later.`,
      );
    }
  }

  async isMemberOfGroup(
    memberId: number,
    groupId: number,
    membershipType: number,
  ): Promise<boolean> {
    this.logger.debug(
      `Checking if member ${memberId} is part of group ${groupId}`,
    );
    try {
      return (
        (await this.groupClient.groupMembership.count({
          where: { groupId, memberId, membershipType },
        })) > 0
      );
    } catch (error) {
      this.logger.error(
        `Error checking membership for member ${memberId} in group ${groupId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to check membership for member ${memberId} in group ${groupId}. Please try again later.`,
      );
    }
  }

  async membershipExists(
    groupId: number,
    memberId: number,
    membershipTypeId: number,
  ): Promise<boolean> {
    this.logger.debug(
      `Checking membership: group ${groupId}, member ${memberId}, type ${membershipTypeId}`,
    );
    return this.isMemberOfGroup(memberId, groupId, membershipTypeId);
  }

  async addMemberToGroup(
    authUser: AuthenticatedUser,
    groupId: number,
    memberData: GroupMemberDto,
  ): Promise<GroupMembershipResponseDto> {
    this.logger.debug(
      `Adding member ${memberData.memberId} to group ${groupId}`,
    );

    this.checkAccessPermissions(authUser, this.writeScopes, null);

    this.validateMembership(memberData);

    // const group = await this.findGroupById(groupId);
    // if (!group) {
    //   throw new NotFoundException(`Group with ID ${groupId} not found.`);
    // }
    const group = await this.getGroupOrThrow(groupId);

    if (
      await this.membershipExists(
        groupId,
        memberData.memberId,
        MembershipTypeHelper.getByKey('User'),
      )
    ) {
      throw new ConflictException(
        `Member ${memberData.memberId} already exists in group ${groupId}.`,
      );
    }

    if (
      !authUser.isMachine &&
      !this.hasAdminRole(authUser) &&
      !(
        group.selfRegister &&
        memberData.memberId.toString() === authUser.userId.toString()
      )
    ) {
      throw new ForbiddenException('Forbidden');
    }

    const now = new Date();
    const membershipData: Omit<GroupMembership, 'id'> = {
      groupId,
      memberId: memberData.memberId,
      membershipType: MembershipTypeHelper.getByKey(
        (memberData.membershipType as string).toLowerCase(),
      ),
      createdBy: authUser.isMachine ? null : Number(authUser.userId),
      createdAt: now,
      modifiedBy: null,
      modifiedAt: null,
    };

    try {
      const created = await this.groupClient.groupMembership.create({
        data: membershipData,
        include: { group: { select: { name: true } } },
      });
      return this.mapPrismaMembershipToDto(created);
    } catch (error) {
      this.logger.error(
        `Error adding member to group: ${error.message}`,
        error.stack,
      );

      throw new InternalServerErrorException(
        `Failed to add member ${memberData.memberId} to group ${groupId}. Please try again later.`,
      );
    }
  }

  private async findMembership(id: number): Promise<GroupMembership | null> {
    return await this.groupClient.groupMembership.findUnique({
      where: { id },
    });
  }

  async removeMembershipById(
    authUser: AuthenticatedUser,
    groupId: number,
    membershipId: number,
  ): Promise<GroupMembershipResponseDto> {
    this.logger.debug(`Removing membership record ID: ${membershipId}`);

    this.checkAccessPermissions(authUser, this.writeScopes, null);

    // const group = await this.findGroupById(groupId);
    // if (!group) {
    //   throw new NotFoundException(`Group with ID ${groupId} not found.`);
    // }
    const group = await this.getGroupOrThrow(groupId);

    const membership = await this.findMembership(membershipId);
    if (!membership) {
      throw new NotFoundException(
        `Membership record with ID ${membershipId} not found.`,
      );
    }
    if (membership.groupId !== groupId) {
      throw new BadRequestException(
        `Membership ${membershipId} does not belong to group ${groupId}.`,
      );
    }

    if (
      !authUser.isMachine &&
      !this.hasAdminRole(authUser) &&
      !(
        group.selfRegister &&
        membership.memberId.toString() === authUser.userId.toString()
      )
    ) {
      throw new ForbiddenException('Forbidden');
    }

    try {
      await this.groupClient.groupMembership.delete({
        where: { id: membershipId },
      });
      return this.mapMembershipToDto(membership);
    } catch (error) {
      this.logger.error(
        `Error removing membership ID ${membershipId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to remove membership with ID ${membershipId}. Please try again later.`,
      );
    }
  }

  async getGroupByGroupId(
    groupId: number,
    user: AuthenticatedUser,
  ): Promise<GroupResponseDto> {
    // const group = await this.findGroupById(groupId);
    // if (!group) {
    //   throw new NotFoundException(`Group with ID ${groupId} not found.`);
    // }
    const group = await this.getGroupOrThrow(groupId);

    await this.validateAdminRoleOrPrivateGroupMembership(
      user,
      group,
      Constants.memberGroupMembershipType,
      this.readScopes,
      this.adminRoles,
    );
    return this.mapToGroupResponseDto(group);
  }

  async validateAdminRoleOrPrivateGroupMembership(
    user: AuthenticatedUser,
    group: PrismaGroupFromDb,
    membershipTypeId: number,
    readScopes: string[],
    adminRoles: string[],
  ): Promise<void> {
    this.logger.debug(
      `Validating access for user ${user.userId} to group ${group.id}`,
    );

    if (!group.privateGroup) {
      this.logger.debug(`Access granted: Group ${group.id} is public.`);
      return;
    }

    if (
      user.isMachine &&
      readScopes.some((scope) => user.scopes?.includes(scope))
    ) {
      this.logger.debug(
        `Access granted for machine user to private group ${group.id} via scope.`,
      );
      return;
    }

    if (
      !user.isMachine &&
      adminRoles.some((role) => user.roles?.includes(role))
    ) {
      this.logger.debug(
        `Access granted for admin user to private group ${group.id} via role.`,
      );
      return;
    }

    const numericUserId = Number(user.userId);
    if (await this.isMemberOfGroup(numericUserId, group.id, membershipTypeId)) {
      this.logger.debug(
        `Access granted for user ${user.userId} to private group ${group.id} as member.`,
      );
      return;
    }

    this.logger.warn(
      `Access denied for user ${user.userId} to private group ${group.id}.`,
    );
    throw new ForbiddenException(
      `Forbidden: You do not have access to group '${group.name}'.`,
    );
  }

  async getGroupById(
    groupId: number,
    requestingUser: AuthenticatedUser,
    includeSubGroups: boolean,
    oneLevel: boolean,
  ): Promise<GroupResponseDto> {
    this.logger.debug(
      `Fetching group hierarchy for ID: ${groupId}, includeSubGroups: ${includeSubGroups}, oneLevel: ${oneLevel}`,
    );

    // const group = await this.findGroupById(groupId);
    // if (!group) {
    //   throw new NotFoundException(`Group with ID ${groupId} not found.`);
    // }
    const group = await this.getGroupOrThrow(groupId);

    if (includeSubGroups) {
      await this.getSubGroupsRecursively(group, oneLevel ? 1 : undefined);
    }

    return this.mapDomainGroupToResponseDtoRecursive(group);
  }

  private async getSubGroupsRecursively(
    parent: Group,
    maxDepth?: number,
    currentDepth: number = 0,
    visitedGroups: Set<number> = new Set(),
  ): Promise<void> {
    if (
      visitedGroups.has(parent.id) ||
      (maxDepth && currentDepth >= maxDepth)
    ) {
      parent.subGroups = parent.subGroups || [];
      return;
    }
    visitedGroups.add(parent.id);

    try {
      const membershipRecords = await this.groupClient.groupMembership.findMany(
        {
          where: {
            groupId: parent.id,
            membershipType: Constants.subGroupMembershipType,
          },
          select: { memberId: true },
        },
      );

      const memberIds = membershipRecords.map((record) => record.memberId);
      if (!memberIds.length) {
        parent.subGroups = [];
        return;
      }

      parent.subGroups = (await this.groupClient.group.findMany({
        where: { id: { in: memberIds } },
        orderBy: { id: 'asc' },
      })) as Group[];

      for (const subGroup of parent.subGroups) {
        await this.getSubGroupsRecursively(
          subGroup,
          maxDepth,
          currentDepth + 1,
          new Set(visitedGroups),
        );
      }
    } catch (error) {
      this.logger.error(
        `Error in getSubGroupsRecursively for parent ${parent.id}: ${error.message}`,
      );
      throw new InternalServerErrorException(
        `Failed to fetch subgroups for parent group ID ${parent.id}. Please try again later.`,
      );
    }
  }

  private async findPrimaryParentGroup(
    childMemberId: number,
    membershipType: number = MembershipTypeHelper.getByKey('Group'),
  ): Promise<PrismaGroupFromDb[] | null> {
    this.logger.debug(`Finding primary parent for group ID: ${childMemberId}`);
    try {
      return await this.groupClient.group.findMany({
        where: {
          memberships: { some: { memberId: childMemberId, membershipType } },
        },
        orderBy: { id: 'asc' },
      });
    } catch (error) {
      this.logger.error(
        `Error finding primary parent group for child ID ${childMemberId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to find primary parent group for child ID ${childMemberId}. Please try again later.`,
      );
    }
  }

  async getParentGroupByGroupId(
    childGroupId: number,
    user: AuthenticatedUser,
    oneLevel: boolean,
  ): Promise<GroupResponseDto | null> {
    this.logger.debug(
      `Fetching parent for group ${childGroupId}, oneLevel: ${oneLevel}`,
    );

    const childGroup = await this.findGroupById(childGroupId);
    if (!childGroup) {
      throw new NotFoundException(
        `Child group with ID ${childGroupId} not found.`,
      );
    }

    const parentGroups = await this.findPrimaryParentGroup(childGroupId);
    if (!parentGroups?.length) {
      return null;
    }

    const parentGroup = parentGroups[0] as Group;
    if (!oneLevel) {
      await this.getParentGroupsRecursively(parentGroup);
    }
    childGroup.parentGroup = parentGroup;

    return this.mapDomainGroupToResponseDtoRecursive(parentGroup);
  }

  async getSubGroupsRecursivelyOrignal(parent: Group): Promise<void> {
    try {
      const subGroups = await this.groupClient.group.findMany({
        where: {
          memberships: {
            some: {
              groupId: parent.id,
              membershipType: MembershipTypeHelper.getByKey('Group'),
            },
          }, // Group = 2
        },
        orderBy: { id: 'asc' },
      });

      parent.subGroups = subGroups as Group[];
      for (const group of parent.subGroups) {
        await this.getSubGroupsRecursivelyOrignal(group);
      }
    } catch (error) {
      this.logger.error(
        `Error in getSubGroupsRecursivelyOrignal for parent ${parent.id}: ${error.message}`,
      );
      parent.subGroups = [];
    }
  }

  public collectGroupIds(group: Group, groupIds: number[]): void {
    groupIds.push(group.id);
    if (group.subGroups?.length) {
      for (const sub of group.subGroups) {
        this.collectGroupIds(sub, groupIds);
      }
    }
  }

  private async getParentGroupsRecursively(group: Group): Promise<void> {
    const parentGroups = await this.findPrimaryParentGroup(group.id);
    if (parentGroups?.length) {
      group.parentGroup = parentGroups[0];
      await this.getParentGroupsRecursively(parentGroups[0]);
    }
  }

  async getMembers(
    user: AuthenticatedUser,
    groupId: number,
  ): Promise<GroupMembershipResponseDto[]> {
    if (!groupId) {
      throw new BadRequestException('Group ID is required.');
    }

    // const group = await this.findGroupById(groupId);
    // if (!group) {
    //   throw new NotFoundException(`Group with ID ${groupId} not found.`);
    // }
    const group = await this.getGroupOrThrow(groupId);

    await this.validateAdminRoleOrPrivateGroupMembership(
      user,
      group,
      Constants.memberGroupMembershipType,
      this.readScopes,
      this.adminRoles,
    );

    try {
      const memberships = await this.groupClient.groupMembership.findMany({
        where: { groupId },
        orderBy: { id: 'asc' },
      });
      return this.mapMembershipListToDto(memberships);
    } catch (error) {
      this.logger.error(
        `Error fetching members for group ID ${groupId}: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to fetch members for group with ID ${groupId}. Please try again later.`,
      );
    }
  }

  async getGroupByMember(
    user: AuthenticatedUser,
    memberId: number | null,
    membershipType: string,
  ): Promise<Group[]> {
    this.logger.log(`getGroupByMember(${memberId}, ${membershipType})`);
    this.checkAccessPermissions(user, this.readScopes, null);

    // if (user.isMachine || user.roles?.includes('administrator')) {
    if (user.isMachine || this.hasAdminRole(user)) {
      if (!memberId && !membershipType) {
        return this.findAllGroups();
      }
    } else {
      memberId = Number(user.userId);
      membershipType = 'user';
    }

    if (!memberId || !membershipType) {
      throw new BadRequestException(
        'Member ID and membership type are required.',
      );
    }

    const membershipTypeInt = MembershipTypeHelper.getByKey(membershipType);
    if (!membershipTypeInt) {
      throw new BadRequestException(
        `Unsupported MembershipType: ${membershipType}`,
      );
    }

    return this.findGroupsByMember(memberId, membershipTypeInt);
  }

  private async findAllGroups(): Promise<Group[]> {
    return await this.groupClient.group.findMany({
      orderBy: { id: 'asc' },
    });
  }

  private async findGroupsByMember(
    memberId: number,
    type: number,
  ): Promise<Group[]> {
    return await this.groupClient.group.findMany({
      where: { memberships: { some: { memberId, membershipType: type } } },
      orderBy: { id: 'asc' },
    });
  }

  async groupExists(name: string): Promise<boolean> {
    this.logger.debug(`Checking if group exists with name: ${name}`);
    try {
      return !!(await this.groupClient.group.findUnique({ where: { name } }));
    } catch (error) {
      this.logger.error(
        `Error checking if group exists: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        `Failed to check if group exists with name '${name}'. Please try again later.`,
      );
    }
  }

  private async findSecurityGroupByName(
    name: string,
  ): Promise<PrismaSecurityGroupsFromDb | null> {
    return await this.prismaClient.security_groups.findFirst({
      where: { description: name },
    });
  }

  private async findSecurityGroupById(
    id: number,
  ): Promise<PrismaSecurityGroupsFromDb | null> {
    return await this.prismaClient.security_groups.findUnique({
      where: { group_id: id },
    });
  }

  private validateMembership(request: GroupMemberDto) {
    if (request.memberId == null) {
      throw new BadRequestException('Mandatory field missing: memberId');
    }

    if (request.membershipType == null) {
      throw new BadRequestException('Mandatory field missing: membershipType');
    }

    const type = MembershipTypeHelper.getByKey(
      request.membershipType as string,
    );
    if (type == null) {
      throw new BadRequestException('Mandatory field missing: membershipType');
    }
  }
}
