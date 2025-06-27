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
  BadRequestException,
  Put,
  HttpCode,
  HttpStatus,
  Logger,
  ParseBoolPipe,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
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
import { AuthenticatedUser } from '../../core/auth/jwt.strategy';
import {
  BaseResponse,
  createBaseResponse,
} from '../../shared/util/responseBuilder';
import { Constants } from '../../core/constant/constants';

@ApiTags('groups')
@Controller('groups')
@UseGuards(AuthGuard('jwt'))
@ApiBearerAuth()
export class GroupController {
  private readonly logger = new Logger(GroupController.name);

  constructor(private readonly groupService: GroupService) { }

  //create group
  @Post()
  @ApiOperation({ summary: 'Create a new group' })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'The group has been successfully created.',
    type: GroupResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized.' })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: 'Internal server error.' })
  async createGroup(
    @Body() groupDataParam: GroupBodyDto,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupResponseDto>> {
    if (!groupDataParam || !groupDataParam.param) {
      throw new BadRequestException('Group data is required.');
    }
    const groupData = groupDataParam.param;
    const user = req.user as AuthenticatedUser;
    this.logger.debug(`User ${user.userId} creating group: ${groupData.name}`);

    const dataToSubmit = { ...groupData };
    dataToSubmit.privateGroup = dataToSubmit.privateGroup ?? true;
    dataToSubmit.selfRegister = dataToSubmit.selfRegister ?? false;

    const response = await this.groupService.create(dataToSubmit, user);

    return createBaseResponse(response, HttpStatus.CREATED);
  }

  //create security group
  @Post('securityGroups')
  @ApiOperation({ summary: 'Create a new security group' })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'The security group has been successfully created.',
    type: GroupResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized.' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: 'Internal server error.' })
  async createSecurityGroup(
    @Body() securityDataParam: SecurityBodyDto,
    @Req() req: Request,
  ): Promise<BaseResponse<SecurityGroupsResponseDto>> {
    const securityData = securityDataParam.param;
    const user = req.user as AuthenticatedUser;
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

  //get single group member
  @Get(':groupId/singleMember/:memberId')
  @ApiOperation({ summary: 'Get a single member from a group' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'The member has been successfully retrieved.',
    type: GroupMembershipResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Group or member not found.' })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: 'Internal server error.' })
  async getSingleMember(
    @Param('groupId', ParseIntPipe) groupId: number,
    @Param('memberId', ParseIntPipe) memberId: number,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupMembershipResponseDto>> {
    const user = req.user as AuthenticatedUser;
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

  // get members count
  @Get(':groupId/membersCount')
  @ApiOperation({ summary: 'Get the count of members in a group' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'The member count has been successfully retrieved.',
    type: Number,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Group not found.' })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: 'Internal server error.' })
  async getMembersCount(
    @Req() req: Request,
    @Param('groupId', ParseIntPipe) groupId: number,
    @Query('includeSubGroups', new ParseBoolPipe({ optional: true }))
    includeSubGroups?: boolean,
  ): Promise<BaseResponse<{ count: number }>> {
    const user = req.user as AuthenticatedUser; 
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

  //update group
  @Put(':groupId')
  @ApiOperation({ summary: 'Update an existing group' })
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
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized.' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Group not found.' })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Conflict (e.g., name already exists).',
  })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: 'Internal server error.' })
  async updateGroup(
    @Param('groupId', ParseIntPipe) groupId: number,
    @Body() groupDataParam: GroupBodyDto,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupResponseDto>> {
    // Extract the actual group data from the DTO
    if (!groupDataParam || !groupDataParam.param) {
      throw new BadRequestException('Group data is required for update.');
    }
    const groupData = groupDataParam.param;
    const user = req.user as AuthenticatedUser;
    this.logger.log(`User ${user.userId} updating group ID: ${groupId}`);

    const dataToSubmit = { ...groupData };
    const response = await this.groupService.update(
      groupId,
      dataToSubmit,
      user,
    );

    return createBaseResponse(response);
  }

  //delete group
  @Delete(':groupId')
  @ApiOperation({ summary: 'Delete a group' })
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
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized.' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden. Insufficient permissions.',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Group not found.' })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: 'Internal server error.' })
  @HttpCode(HttpStatus.OK)
  async deleteGroup(
    @Param('groupId', ParseIntPipe) groupId: number,
    @Req() req: Request,
  ): Promise<BaseResponse<GroupResponseDto>> {
    const user = req.user as AuthenticatedUser;
    this.logger.debug(`User ${user.userId} deleting group ID: ${groupId}`);

    const group = await this.groupService.deleteGroupAndMemberships(
      groupId,
      user,
    );
    return createBaseResponse(group);
  }

  //get group by id
  @Get(':groupId')
  @ApiOperation({ summary: 'Get a specific group by its ID' })
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
    const user = req.user as AuthenticatedUser;
    this.logger.debug(`User ${user.userId} retrieving group ID: ${groupId}`);
    const response = await this.groupService.getGroupByGroupId(groupId, user);
    this.logger.debug(`Group retrieved: ${JSON.stringify(response)}`);
    this.logger.debug(`Fields requested: ${fields} 'all fields'}`);

    return createBaseResponse(response, HttpStatus.OK, fields);
  }

  //add member to group
  @Post(':groupId/members')
  @ApiOperation({ summary: 'Add a member to a group' })
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
    if (!addMemberDtoParam || !addMemberDtoParam.param) {
      throw new BadRequestException('Member data is required.');
    }
    const addMemberDto = addMemberDtoParam.param;

    const user = req.user as AuthenticatedUser;
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

  //remove member from group
  @Delete(':groupId/members/:membershipId')
  @ApiOperation({
    summary: 'Remove a member from a group using the membership ID',
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
    const user = req.user as AuthenticatedUser;
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


  // Get subgroups
  @Get(':groupId/getSubGroups')
  @ApiOperation({ summary: 'Get a group and its subgroups' })
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
    const user = req.user as AuthenticatedUser;
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


  // Get Parent Group
  @Get(':groupId/getParentGroup')
  @ApiOperation({
    summary: "Get a group's primary parent or ultimate ancestor",
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
    const user = req.user as AuthenticatedUser;
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

  @Get(':groupId/members')
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
  async getMemebrs(
    @Req() req: Request,
    @Param('groupId', ParseIntPipe) groupId: number,
  ): Promise<BaseResponse<GroupMembershipResponseDto[]>> {
    this.logger.debug(`getMembers : ` + groupId);
    const user = req.user as AuthenticatedUser;
    const response = await this.groupService.getMembers(user, groupId);
    return createBaseResponse(response);
  }

  // Get Group by Member
  @Get()
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
  async getGroupByMember(
    @Req() req: Request,
    @Query('memberId') memberId: number,
    @Query('membershipType') membershipType: string,
  ): Promise<BaseResponse<GroupResponseDto[]>> {
    this.logger.debug(`getGroupByMember : ` + memberId);
    const user = req.user as AuthenticatedUser;

    const response = await this.groupService.getGroupByMember(
      user,
      memberId,
      membershipType,
    );

    return createBaseResponse(response);
  }
}
