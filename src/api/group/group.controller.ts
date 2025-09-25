import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Delete,
  Query,
  UseGuards,
  Req,
  ParseIntPipe,
  NotFoundException,
  Put,
  HttpCode,
  HttpStatus,
  Logger,
  ParseBoolPipe,
  BadRequestException,
} from '@nestjs/common';
// import { AuthGuard } from '@nestjs/passport';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';
import { GroupService } from './group.service';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import {
  GroupBodyDto,
  GroupDto,
  GroupResponseDto,
  SecurityBodyDto,
  SecurityGroupsResponseDto,
} from '../../dto/group/group.dto';
import { Request } from 'express';
import {
  GroupMemberBodyDto,
  GroupMembershipResponseDto,
} from '../../dto/group/group-membership.dto';
import {
  BaseResponse,
  createBaseResponse,
} from '../../shared/util/responseBuilder';
import { Constants } from '../../core/constant/constants';
import { describeAccess } from '../../shared/swagger/access-description.util';

/**
 * Check if request body and param are present. Throw 400 Bad Request if not.
 * @param reqBody Request body containing the parameter to check
 */
function checkParamExists(
  reqBody: GroupBodyDto | SecurityBodyDto | GroupMemberBodyDto,
) {
  if (!reqBody || !reqBody.param) {
    throw new BadRequestException('Request param is required');
  }
}

@ApiTags('groups')
@Controller('groups')
@UseGuards(AuthRequiredGuard)
@ApiBearerAuth()
export class GroupController {
  private readonly logger = new Logger(GroupController.name);

  constructor(private readonly groupService: GroupService) {}

  /**
   * Create a new group.
   * @param groupDataParam Group data containing the group details
   * @param req Request object to get user information
   * @returns Created group details with appropriate HTTP status
   */
  @Post()
  @ApiOperation({
    summary: 'Create a new group',
    description: describeAccess({
      summary:
        'Creates a group record. If flags are omitted, the group is private and self-registration is disabled.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: ['write:groups', 'all:groups'],
    }),
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'The group has been successfully created.',
    type: GroupResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async createGroup(
    @Body() groupDataParam: GroupBodyDto,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupResponseDto>> {
    checkParamExists(groupDataParam);
    const groupData = groupDataParam.param;
    const user = (req as any).authUser || (req as any).user;
    this.logger.debug(`User ${user.userId} creating group: ${groupData.name}`);

    const dataToSubmit = { ...groupData };
    dataToSubmit.privateGroup = dataToSubmit.privateGroup ?? true;
    dataToSubmit.selfRegister = dataToSubmit.selfRegister ?? false;

    const response = await this.groupService.create(dataToSubmit, user);

    return createBaseResponse(response, HttpStatus.CREATED);
  }

  /**
   * Create a new security group.
   * @param securityDataParam Security group data containing the group details
   * @param req Request object to get user information
   * @returns Created security group details with appropriate HTTP status
   */
  @Post('securityGroups')
  @ApiOperation({
    summary: 'Create a new security group',
    description: describeAccess({
      summary:
        'Creates a security group mapping for authorization services.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: ['write:groups', 'all:groups'],
    }),
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'The security group has been successfully created.',
    type: GroupResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async createSecurityGroup(
    @Body() securityDataParam: SecurityBodyDto,
    @Req() req: Request,
  ): Promise<BaseResponse<SecurityGroupsResponseDto>> {
    checkParamExists(securityDataParam);
    const securityData = securityDataParam.param;
    const user = (req as any).authUser || (req as any).user;
    this.logger.debug(
      `User ${user.userId} creating security group: ${securityData.name}`,
    );
    const dataToSubmit = { ...securityData };
    const response = await this.groupService.createSecurityGroup(
      dataToSubmit,
      user,
    );
    return createBaseResponse(response);
  }

  /**
   * Get a single member from a group.
   * @param groupId ID of the group
   * @param memberId ID of the member
   * @param req Request object to get user information
   * @returns Member details if found, otherwise throws an error
   */
  @Get(':groupId/singleMember/:memberId')
  @ApiOperation({
    summary: 'Get a single member from a group',
    description: describeAccess({
      summary:
        'Fetch a specific membership record for the supplied group and member IDs.',
      jwt: 'Any authenticated user.',
      m2m: 'No additional scope requirement beyond authentication.',
    }),
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'The member has been successfully retrieved.',
    type: GroupMembershipResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group or member not found.',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getSingleMember(
    @Param('groupId', ParseIntPipe) groupId: number,
    @Param('memberId', ParseIntPipe) memberId: number,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupMembershipResponseDto>> {
    const user = (req as any).authUser || (req as any).user;
    this.logger.debug(
      `User ${user.userId} getting member ${memberId} from group ${groupId}`,
    );

    const membership = await this.groupService.findMembershipByGroupAndMember(
      groupId,
      memberId,
    );
    if (!membership) {
      throw new NotFoundException(
        `Member with ID ${memberId} not found in group ${groupId}`,
      );
    }
    return createBaseResponse(membership);
  }

  /**
   * Get the count of members in a group.
   * @param req Request object to get user information
   * @param groupId ID of the group
   * @param includeSubGroups Whether to include members from subgroups
   * @returns Member count for the group
   */
  @Get(':groupId/membersCount')
  @ApiOperation({
    summary: 'Get the count of members in a group',
    description: describeAccess({
      summary:
        'Returns a count of member-type memberships for the specified group, optionally including sub-groups.',
      jwt: 'Any authenticated user.',
      m2m: 'No additional scope requirement beyond authentication.',
    }),
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'The member count has been successfully retrieved.',
    type: Number,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group not found.',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getMembersCount(
    @Req() req: Request,
    @Param('groupId', ParseIntPipe) groupId: number,
    @Query('includeSubGroups', new ParseBoolPipe({ optional: true }))
    includeSubGroups?: boolean,
  ): Promise<BaseResponse<{ count: number }>> {
    const user = (req as any).authUser || (req as any).user;
    this.logger.debug(
      `User ${user.userId} getting member count for group ${groupId}`,
    );
    const count = await this.groupService.getMemberCount(
      groupId,
      includeSubGroups,
      Constants.memberGroupMembershipType,
    );
    return createBaseResponse({ count });
  }

  /**
   * Update an existing group.
   * @param groupId ID of the group to update
   * @param groupDataParam Updated group data
   * @param req Request object to get user information
   * @returns Updated group details with appropriate HTTP status
   */
  @Put(':groupId')
  @ApiOperation({
    summary: 'Update an existing group',
    description: describeAccess({
      summary: 'Updates the metadata for an existing group.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: ['write:groups', 'all:groups'],
    }),
  })
  @ApiBody({
    type: GroupDto,
    description: 'Data to update the group. All fields are optional.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'The group has been successfully updated.',
    type: GroupResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group not found.',
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Conflict (e.g., name already exists).',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async updateGroup(
    @Param('groupId', ParseIntPipe) groupId: number,
    @Body() groupDataParam: GroupBodyDto,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupResponseDto>> {
    checkParamExists(groupDataParam);
    const groupData = groupDataParam.param;
    const user = (req as any).authUser || (req as any).user;
    this.logger.log(`User ${user.userId} updating group ID: ${groupId}`);

    const dataToSubmit = { ...groupData };
    const response = await this.groupService.update(
      groupId,
      dataToSubmit,
      user,
    );

    return createBaseResponse(response);
  }

  /**
   * Delete a group.
   * @param groupId ID of the group to delete
   * @param req Request object to get user information
   * @returns Deleted group details with appropriate HTTP status
   */
  @Delete(':groupId')
  @ApiOperation({
    summary: 'Delete a group',
    description: describeAccess({
      summary: 'Deletes a group and all of its memberships.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: ['write:groups', 'all:groups'],
    }),
  })
  @ApiParam({
    name: 'groupId',
    description: 'The ID of the group to delete',
    type: Number,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'The group has been successfully deleted.',
    type: GroupResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden. Insufficient permissions.',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group not found.',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.OK)
  async deleteGroup(
    @Param('groupId', ParseIntPipe) groupId: number,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupResponseDto>> {
    const user = (req as any).authUser || (req as any).user;
    this.logger.debug(`User ${user.userId} deleting group ID: ${groupId}`);

    const group = await this.groupService.deleteGroupAndMemberships(
      groupId,
      user,
    );
    return createBaseResponse(group);
  }

  /**
   * Get a specific group by its ID.
   * @param groupId ID of the group to retrieve
   * @param req Request object to get user information
   * @param fields Optional fields to include in the response
   * @returns Group details if found, otherwise throws an error
   */
  @Get(':groupId')
  @ApiOperation({
    summary: 'Get a specific group by its ID',
    description: describeAccess({
      summary:
        'Returns the metadata for a single group. Private group visibility follows membership and admin rules.',
      jwt: 'Requires the `administrator` role for private groups; members of the group can access their own private groups. Public groups are available to any authenticated user.',
      m2m: ['read:groups', 'write:groups', 'all:groups'],
      notes:
        'Authorization failures result in HTTP 403 rather than leaking the existence of the group.',
    }),
  })
  @ApiParam({
    name: 'groupId',
    description: 'The ID of the group to retrieve',
    type: Number,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'The group has been successfully retrieved.',
    type: GroupResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid group ID format.',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description:
      'Forbidden. Insufficient permissions or not a member of private group.',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group not found.',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getGroupById(
    @Param('groupId', ParseIntPipe) groupId: number,
    @Req() req: Request,
    @Query('fields') fields?: string,
  ): Promise<BaseResponse<GroupResponseDto>> {
    const user = (req as any).authUser || (req as any).user;
    this.logger.debug(`User ${user.userId} retrieving group ID: ${groupId}`);
    const response = await this.groupService.getGroupByGroupId(groupId, user);
    this.logger.debug(`Group retrieved: ${JSON.stringify(response)}`);
    this.logger.debug(`Fields requested: ${fields} 'all fields'}`);

    return createBaseResponse(response, HttpStatus.OK, fields);
  }

  /**
   * Add a member to a group.
   * @param groupId ID of the group to add the member to
   * @param addMemberDtoParam Member data containing the member details
   * @param req Request object to get user information
   * @returns Added membership details with appropriate HTTP status
   */
  @Post(':groupId/members')
  @ApiOperation({
    summary: 'Add a member to a group',
    description: describeAccess({
      summary:
        'Adds a membership record to the target group for the supplied member.',
      jwt: 'Requires the `administrator` role. If the group allows self-registration, members may add themselves with their own JWT.',
      m2m: ['write:groups', 'all:groups'],
    }),
  })
  @ApiParam({
    name: 'groupId',
    description: 'The ID of the group to add a member to',
    type: Number,
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'The member has been successfully added to the group.',
    type: GroupMembershipResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Bad request (e.g., missing fields, invalid ID format).',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden. Insufficient permissions or action not allowed.',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group not found.',
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Membership already exists.',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.CREATED)
  async addMemberToGroup(
    @Param('groupId', ParseIntPipe) groupId: number,
    @Body() addMemberDtoParam: GroupMemberBodyDto,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupMembershipResponseDto>> {
    checkParamExists(addMemberDtoParam);
    if (!addMemberDtoParam || !addMemberDtoParam.param) {
      throw new BadRequestException('Member data is required.');
    }
    const addMemberDto = addMemberDtoParam.param;

    const user = (req as any).authUser || (req as any).user;
    this.logger.debug(
      `User ${user.userId} adding member ${addMemberDto.memberId} to group ${groupId}`,
    );

    const response = await this.groupService.addMemberToGroup(
      user,
      groupId,
      addMemberDto,
    );

    return createBaseResponse(response);
  }

  /**
   * Remove a member from a group using the membership ID.
   * @param groupId ID of the group (for context and permission checks)
   * @param membershipId ID of the membership record to remove
   * @param req Request object to get user information
   * @returns Removed membership details with appropriate HTTP status
   */
  @Delete(':groupId/members/:membershipId')
  @ApiOperation({
    summary: 'Remove a member from a group using the membership ID',
    description: describeAccess({
      summary:
        'Deletes a specific membership row for the provided group and membership identifiers.',
      jwt: 'Requires the `administrator` role. Members can remove themselves when the group allows self-registration.',
      m2m: ['write:groups', 'all:groups'],
    }),
  })
  @ApiParam({
    name: 'groupId',
    description: 'The ID of the group (for context and permission checks)',
    type: Number,
  })
  @ApiParam({
    name: 'membershipId',
    description: 'The ID of the membership record to remove',
    type: Number,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'The member has been successfully removed from the group.',
    type: GroupMembershipResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid ID format.',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden. Insufficient permissions or action not allowed.',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group or Membership record not found.',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.OK)
  async removeMemberFromGroup(
    @Param('groupId', ParseIntPipe) groupId: number,
    @Param('membershipId', ParseIntPipe) membershipId: number,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupMembershipResponseDto>> {
    const user = (req as any).authUser || (req as any).user;
    this.logger.debug(
      `User ${user.userId} removing membership ${membershipId} from group ${groupId}`,
    );

    const response = await this.groupService.removeMembershipById(
      user,
      groupId,
      membershipId,
    );
    return createBaseResponse(response);
  }
  /**
   * Retrieve a group along with its subgroups.
   * @param req - The request object containing user information.
   * @param groupId - The ID of the parent group to retrieve.
   * @param includeSubGroups - Flag indicating whether to include subgroups (default: false).
   * @param oneLevel - Flag indicating whether to fetch only one level of subgroups (default: false).
   * @param fields - Optional fields to include in the response.
   * @returns A response containing the group and its subgroups.
   */
  @Get(':groupId/getSubGroups')
  @ApiOperation({
    summary: 'Get a group and its subgroups',
    description: describeAccess({
      summary:
        'Returns the group tree for the requested group, optionally including nested levels.',
      jwt: 'Any authenticated user.',
      m2m: 'No additional scope requirement beyond authentication.',
      notes:
        'Private group visibility currently mirrors legacy behaviour and does not enforce additional role checks for this endpoint.',
    }),
  })
  @ApiParam({
    name: 'groupId',
    description: 'The ID of the parent group',
    type: Number,
  })
  @ApiQuery({
    name: 'includeSubGroups',
    description:
      'Whether to include subgroups in the response. Defaults to false.',
    type: Boolean,
    required: false,
  })
  @ApiQuery({
    name: 'oneLevel',
    description:
      'If including subgroups, whether to fetch only one level deep. Defaults to false.',
    type: Boolean,
    required: false,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Group and subgroups retrieved successfully.',
    type: GroupResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid parameter format.',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description:
      'Forbidden. Insufficient permissions or not a member of private group.',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group not found.',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getGroupWithSubGroups(
    @Req() req: Request,
    @Param('groupId', ParseIntPipe) groupId: number,
    @Query('includeSubGroups', new ParseBoolPipe({ optional: true }))
    includeSubGroups?: boolean,
    @Query('oneLevel', new ParseBoolPipe({ optional: true }))
    oneLevel?: boolean,
    @Query('fields') fields?: string,
  ): Promise<BaseResponse<GroupResponseDto>> {
    const user = (req as any).authUser || (req as any).user;
    this.logger.debug(
      `User ${user.userId} requesting subgroups for group ${groupId}`,
    );

    const effectiveIncludeSubGroups = includeSubGroups ?? false;
    const effectiveOneLevel = oneLevel ?? false;

    const response = await this.groupService.getGroupById(
      groupId,
      user,
      effectiveIncludeSubGroups,
      effectiveOneLevel,
    );

    return createBaseResponse(response, HttpStatus.OK, fields);
  }

  /**
   * Retrieve the primary parent or ultimate ancestor of a group.
   * @param req - The request object containing user information.
   * @param groupId - The ID of the group whose parent is to be retrieved.
   * @param oneLevel - Flag indicating whether to fetch only the direct primary parent (default: true).
   * @param fields - Optional fields to include in the response.
   * @returns A response containing the parent group.
   */
  @Get(':groupId/getParentGroup')
  @ApiOperation({
    summary: "Get a group's primary parent or ultimate ancestor",
    description: describeAccess({
      summary:
        'Retrieves the direct parent group or the full ancestry chain for the supplied group.',
      jwt: 'Any authenticated user.',
      m2m: 'No additional scope requirement beyond authentication.',
    }),
  })
  @ApiParam({
    name: 'groupId',
    description: 'The ID of the group whose parent is sought',
    type: Number,
  })
  @ApiQuery({
    name: 'oneLevel',
    description: 'Fetch only the direct primary parent. Defaults to true.',
    type: Boolean,
    required: false,
    schema: { default: true },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Parent group retrieved successfully.',
    type: GroupResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group or its parent not found.',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid parameter format.',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getParentGroupForChild(
    @Req() req: Request,
    @Param('groupId', ParseIntPipe) groupId: number,
    @Query('oneLevel', new ParseBoolPipe({ optional: true }))
    oneLevel?: boolean,
    @Query('fields') fields?: string,
  ): Promise<BaseResponse<GroupResponseDto>> {
    const user = (req as any).authUser || (req as any).user;
    const effectiveOneLevel = oneLevel === undefined ? true : oneLevel;
    this.logger.debug(
      `User ${user.userId} requesting parent for group ${groupId}, oneLevel: ${effectiveOneLevel}`,
    );

    const parentGroupDto = await this.groupService.getParentGroupByGroupId(
      groupId,
      user,
      effectiveOneLevel,
    );
    return createBaseResponse(parentGroupDto, HttpStatus.OK, fields);
  }

  /**
   * Retrieve members of a specific group.
   * @param req - The request object containing user information.
   * @param groupId - The ID of the group to retrieve members from.
   * @returns A response containing the list of group members.
   */
  @Get(':groupId/members')
  @ApiOperation({
    summary: 'List members of a group',
    description: describeAccess({
      summary:
        'Lists member-type memberships for the requested group.',
      jwt: 'Requires the `administrator` role for private groups; group members can access their own private groups. Public groups are available to any authenticated user.',
      m2m: ['read:groups', 'write:groups', 'all:groups'],
    }),
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Group members retrieved successfully.',
    type: GroupMembershipResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Group not found.',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid parameter format.',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getMemebrs(
    @Req() req: Request,
    @Param('groupId', ParseIntPipe) groupId: number,
  ): Promise<BaseResponse<GroupMembershipResponseDto[]>> {
    this.logger.debug(`getMembers : ` + groupId);
    const user = (req as any).authUser || (req as any).user;
    const response = await this.groupService.getMembers(user, groupId);
    return createBaseResponse(response);
  }

  /**
   * Retrieve groups associated with a specific member and membership type.
   * @param req - The request object containing user information.
   * @param memberId - The ID of the member.
   * @param membershipType - The type of membership to filter by.
   * @returns A response containing the list of groups associated with the member.
   */
  @Get()
  @ApiOperation({
    summary: 'List groups for a member',
    description: describeAccess({
      summary:
        'Returns groups associated with a member and membership type. Non-admin JWT callers are restricted to their own user id and the `user` membership type.',
      jwt: 'Administrators can query any member. Other users are limited to their own memberships.',
      m2m: ['read:groups', 'write:groups', 'all:groups'],
    }),
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Groups retrieved successfully by member.',
    type: GroupResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'No groups found for the member.',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid parameter format.',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getGroupByMember(
    @Req() req: Request,
    @Query('memberId') memberId: number,
    @Query('membershipType') membershipType: string,
  ): Promise<BaseResponse<GroupResponseDto[]>> {
    this.logger.debug(`getGroupByMember : ` + memberId);
    const user = (req as any).authUser || (req as any).user;

    const response = await this.groupService.getGroupByMember(
      user,
      memberId,
      membershipType,
    );

    return createBaseResponse(response);
  }
}
