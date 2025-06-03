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

@Controller('roles')
@UseGuards(AuthGuard('jwt'))
export class RoleController {
  private readonly logger = new Logger(RoleController.name);

  constructor(private readonly roleService: RoleService) {}

  @Get()
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
        if (!isNaN(parsedId)) {
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

    return this.roleService.findAll(subjectId, query.fields);
  }

  @Get(':roleId')
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

  @Post()
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

  @Put(':roleId')
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

  @Delete(':roleId')
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

  @Post(':roleId/assign')
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

  @Delete(':roleId/deassign')
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

  @Get(':roleId/hasrole')
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
