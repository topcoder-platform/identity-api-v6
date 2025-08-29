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
  ForbiddenException,
  BadRequestException,
  Put,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { RoleService } from './role.service';
import {
  RoleResponseDto,
  CreateRoleBodyDto,
  UpdateRoleBodyDto,
  RoleQueryDto,
} from '../../dto/role/role.dto';
import { Request } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';

@Controller('roles')
@UseGuards(AuthGuard('jwt'))
@ApiTags('roles')
export class RoleController {
  private readonly logger = new Logger(RoleController.name);

  constructor(private readonly roleService: RoleService) {}

  /**
   * Search for roles based on query parameters.
   * Non-admins can only query roles where subjectId matches their own user ID.
   * @param query Query parameters including filter for subjectId
   * @param req Request object containing user information
   * @returns Array of matching RoleResponseDto objects
   */
  @Get()
  @ApiOperation({ summary: 'Search roles with given parameters' })
  @ApiResponse({ status: HttpStatus.OK, type: [RoleResponseDto] })
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
  findAll(
    @Query() query: RoleQueryDto,
    @Req() req: Request,
  ): Promise<RoleResponseDto[]> {
    const user = req.user;
    let subjectId: number | undefined;

    this.logger.debug(`findAll received query: ${JSON.stringify(query)}`);

    if (query.filter) {
      this.logger.debug(`findAll received filter: ${query.filter}`);
      const filterParts = query.filter.split('=');
      if (
        filterParts.length === 2 &&
        filterParts[0].toLowerCase() === 'subjectid'
      ) {
        const parsedId = parseInt(filterParts[1], 10);
        // subject id should be > 0 as in v3 java code
        if (!isNaN(parsedId) && parsedId > 0) {
          subjectId = parsedId;
        } else {
          throw new BadRequestException(
            'Invalid format for subjectId in filter parameter.',
          );
        }
      }
    }

    if (!user.isAdmin) {
      if (subjectId === undefined || Number(user.userId) !== subjectId) {
        throw new ForbiddenException(
          'Permission denied. Non-admins can only query their own roles by providing the correct subjectId filter.',
        );
      }
    }

    return this.roleService.findAll(subjectId);
  }

  /**
   * Retrieve a role by its unique ID.
   * @param roleId Numeric ID of the role to fetch
   * @param fields Optional fields to include in the response
   * @returns RoleResponseDto object if found, otherwise throws NotFoundException
   */
  @Get(':roleId')
  @ApiOperation({ summary: 'Get role by role id' })
  @ApiParam({ name: 'roleId', description: 'role id', type: 'number' })
  @ApiResponse({ status: HttpStatus.OK, type: RoleResponseDto })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Not Found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async findOne(
    @Param('roleId', ParseIntPipe) roleId: number,
    @Query('fields') fields?: string,
  ): Promise<RoleResponseDto> {
    const result = await this.roleService.findOne(roleId, fields);
    if (!result) {
      throw new NotFoundException(`Role with ID ${roleId} not found.`);
    }
    return result;
  }

  /**
   * Create a new role.
   * Requires admin privileges.
   * @param req Request object containing user information
   * @param createRoleBody Body containing role creation data
   * @returns Created RoleResponseDto object
   */
  @Post()
  @ApiOperation({ summary: 'Create role' })
  @ApiResponse({ status: HttpStatus.OK, type: RoleResponseDto })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Conflict.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async create(
    @Req() req: Request,
    @Body() createRoleBody: CreateRoleBodyDto,
  ): Promise<RoleResponseDto> {
    const user = req.user;
    if (!user.isAdmin) {
      throw new ForbiddenException(
        'Admin privileges required to create roles.',
      );
    }
    const createRoleDto = { roleName: createRoleBody.param.roleName };
    return this.roleService.create(createRoleDto, Number(user.userId));
  }

  /**
   * Update an existing role by ID.
   * Requires admin privileges.
   * @param req Request object containing user information
   * @param roleId Numeric ID of the role to update
   * @param updateRoleBody Body containing role update data
   * @returns Updated RoleResponseDto object
   */
  @Put(':roleId')
  @ApiOperation({ summary: 'Update role with id and parameters' })
  @ApiParam({ name: 'roleId', description: 'role id', type: 'number' })
  @ApiResponse({ status: HttpStatus.OK, type: RoleResponseDto })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad request.' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Not Found' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Conflict.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async update(
    @Req() req: Request,
    @Param('roleId', ParseIntPipe) roleId: number,
    @Body() updateRoleBody: UpdateRoleBodyDto,
  ): Promise<RoleResponseDto> {
    const user = req.user;
    if (!user.isAdmin) {
      throw new ForbiddenException(
        'Admin privileges required to update roles.',
      );
    }
    const updateRoleDto = { roleName: updateRoleBody.param.roleName };
    return this.roleService.update(roleId, updateRoleDto, Number(user.userId));
  }

  /**
   * Delete a role by ID.
   * Requires admin privileges.
   * @param req Request object containing user information
   * @param roleId Numeric ID of the role to delete
   */
  @Delete(':roleId')
  @ApiOperation({ summary: 'Delete role with id' })
  @ApiParam({ name: 'roleId', description: 'role id', type: 'number' })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
    description: 'Operation successful',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Not Found' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Conflict.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(
    @Req() req: Request,
    @Param('roleId', ParseIntPipe) roleId: number,
  ): Promise<void> {
    const user = req.user;
    if (!user.isAdmin) {
      throw new ForbiddenException(
        'Admin privileges required to delete roles.',
      );
    }
    await this.roleService.remove(roleId);
  }

  // --- Role Assignment ---

  /**
   * Assign a role to a subject by subject ID.
   * Requires admin privileges.
   * @param req Request object containing user information
   * @param roleId Numeric ID of the role to assign
   * @param filter Query parameter containing subjectId=ID format
   * @returns Success message upon successful assignment
   */
  @Post(':roleId/assign')
  @ApiOperation({
    summary: 'Assign role to subject id. Subject id is in filter parameter',
  })
  @ApiParam({ name: 'roleId', description: 'role id', type: 'number' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Operation successful' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Not Found' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Conflict.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async assignRoleToSubject(
    @Req() req: Request,
    @Param('roleId', ParseIntPipe) roleId: number,
    @Query('filter') filter: string,
  ): Promise<any> {
    const user = req.user;
    if (!user.isAdmin) {
      throw new ForbiddenException(
        'Admin privileges required to assign roles.',
      );
    }

    if (roleId <= 0) {
      throw new BadRequestException('roleId must be a positive number.');
    }

    let subjectId: number | undefined;

    this.logger.debug(`assignRoleToSubject received filter: ${filter}`);

    if (filter) {
      const filterParts = filter.split('=');
      if (
        filterParts.length === 2 &&
        filterParts[0].toLowerCase() === 'subjectid'
      ) {
        const parsedId = parseInt(filterParts[1], 10);
        if (!isNaN(parsedId)) {
          subjectId = parsedId;
          if (subjectId <= 0) {
            throw new BadRequestException(
              'subjectId must be a positive number.',
            );
          }
        }
      }
    }

    if (subjectId === undefined) {
      throw new BadRequestException(
        'Missing or invalid subjectID in filter parameter.',
      );
    }

    await this.roleService.assignRoleToSubject(
      roleId,
      subjectId,
      Number(user.userId),
    );

    return { message: `Role ${roleId} assigned to subject ${subjectId}.` };
  }

  /**
   * Deassign a role from a subject by subject ID.
   * Requires admin privileges.
   * @param req Request object containing user information
   * @param roleId Numeric ID of the role to deassign
   * @param filter Query parameter containing subjectId=ID format
   * @returns Success message upon successful deassignment
   */
  @Delete(':roleId/deassign')
  @ApiOperation({
    summary: 'Deassign role for subject id. Subject id is in filter parameter',
  })
  @ApiParam({ name: 'roleId', description: 'role id', type: 'number' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Operation successful' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Not Found' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Conflict.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async deassignRoleFromSubject(
    @Req() req: Request,
    @Param('roleId', ParseIntPipe) roleId: number,
    @Query('filter') filter: string,
  ): Promise<any> {
    const user = req.user;
    if (!user.isAdmin) {
      throw new ForbiddenException(
        'Admin privileges required to unassign roles.',
      );
    }

    if (roleId <= 0) {
      throw new BadRequestException('roleId must be a positive number.');
    }

    let subjectId: number | undefined;

    this.logger.debug(`deassignRoleFromSubject received filter: ${filter}`);

    if (filter) {
      const filterParts = filter.split('=');
      if (
        filterParts.length === 2 &&
        filterParts[0].toLowerCase() === 'subjectid'
      ) {
        const parsedId = parseInt(filterParts[1], 10);
        if (!isNaN(parsedId)) {
          subjectId = parsedId;
          if (subjectId <= 0) {
            throw new BadRequestException(
              'subjectId must be a positive number.',
            );
          }
        }
      }
    }

    if (subjectId === undefined) {
      throw new BadRequestException(
        'Missing or invalid subjectID in filter parameter.',
      );
    }

    await this.roleService.deassignRoleFromSubject(roleId, subjectId);

    return { message: `Role ${roleId} unassigned from subject ${subjectId}.` };
  }

  /**
   * Check if a subject has a specific role.
   * Non-admins can only check their own roles.
   * @param req Request object containing user information
   * @param roleId Numeric ID of the role to check
   * @param filter Query parameter containing subjectId=ID format
   * @returns RoleResponseDto if the subject has the role, otherwise throws NotFoundException
   */
  @Get(':roleId/hasrole')
  @ApiOperation({
    summary:
      'Check role has been assigned to subject id or not. Subject id is in filter parameter',
  })
  @ApiParam({ name: 'roleId', description: 'role id', type: 'number' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Operation successful' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Not Found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async checkSubjectHasRole(
    @Req() req: Request,
    @Param('roleId', ParseIntPipe) roleId: number,
    @Query('filter') filter: string,
  ): Promise<RoleResponseDto> {
    const user = req.user;

    if (roleId <= 0) {
      throw new BadRequestException('roleId must be a positive number.');
    }

    let subjectId: number | undefined;
    let subjectIdString: string | undefined;

    this.logger.debug(`checkSubjectHasRole received filter: ${filter}`);

    if (filter) {
      const filterParts = filter.split('=');
      if (
        filterParts.length === 2 &&
        filterParts[0].toLowerCase() === 'subjectid'
      ) {
        const parsedId = parseInt(filterParts[1], 10);
        subjectIdString = filterParts[1];
        if (!isNaN(parsedId)) {
          subjectId = parsedId;
          if (subjectId <= 0) {
            throw new BadRequestException(
              'subjectId must be a positive number.',
            );
          }
        }
      }
    }

    if (subjectId === undefined || subjectIdString === undefined) {
      throw new BadRequestException(
        'Missing or invalid subjectID in filter parameter.',
      );
    }

    if (!user.isAdmin && user.userId !== subjectIdString) {
      throw new ForbiddenException(
        'Non-admin users can only check their own roles.',
      );
    }

    const roleDetails = await this.roleService.checkSubjectHasRole(
      roleId,
      subjectId,
    );

    if (!roleDetails) {
      throw new NotFoundException('Subject does not have the specified role.');
    }

    return roleDetails;
  }
}
