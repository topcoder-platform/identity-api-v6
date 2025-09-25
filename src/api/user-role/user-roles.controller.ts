import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Param,
  ParseIntPipe,
  Patch,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';
import { SCOPES } from '../../auth/constants';
import { RoleResponseDto } from '../../dto/role/role.dto';
import { ModifyUserRoleDto } from '../../dto/user-role/user-role.dto';
import { UserRolesService } from './user-roles.service';
import { describeAccess } from '../../shared/swagger/access-description.util';

interface AuthenticatedRequest extends Request {
  authUser?: any;
  user?: any;
}

@ApiTags('user-roles')
@ApiBearerAuth()
@Controller('user-roles')
@UseGuards(AuthRequiredGuard)
export class UserRolesController {
  private readonly logger = new Logger(UserRolesController.name);

  constructor(private readonly userRolesService: UserRolesService) {}

  @Get(':identifier')
  @ApiOperation({
    summary: 'List roles assigned to a user by ID or Topcoder member handle',
    description: describeAccess({
      summary:
        'Retrieves all role assignments for the identified member.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: ['read:usersRole', 'all:usersRole'],
    }),
  })
  @ApiParam({
    name: 'identifier',
    description: 'Numeric user id or Topcoder member handle',
    required: true,
  })
  @ApiResponse({ status: HttpStatus.OK, type: [RoleResponseDto] })
  async listUserRoles(
    @Param('identifier') identifier: string,
    @Req() req: AuthenticatedRequest,
  ): Promise<RoleResponseDto[]> {
    const user = this.getAuthenticatedUser(req);
    this.ensureAdminOrScope(user, [SCOPES.READ_USERS_ROLE]);
    return this.userRolesService.getUserRoles(identifier);
  }

  @Get(':identifier/:roleId')
  @ApiOperation({
    summary: 'Get a single role assigned to a user by role id',
    description: describeAccess({
      summary:
        'Retrieves a specific role assignment for the given member and role id.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: ['read:usersRole', 'all:usersRole'],
    }),
  })
  @ApiParam({
    name: 'identifier',
    description: 'Numeric user id or handle',
    required: true,
  })
  @ApiParam({
    name: 'roleId',
    description: 'Role id to retrieve',
    required: true,
    type: Number,
  })
  @ApiResponse({ status: HttpStatus.OK, type: RoleResponseDto })
  async getRoleForUser(
    @Param('identifier') identifier: string,
    @Param('roleId', ParseIntPipe) roleId: number,
    @Req() req: AuthenticatedRequest,
  ): Promise<RoleResponseDto> {
    const user = this.getAuthenticatedUser(req);
    this.ensureAdminOrScope(user, [SCOPES.READ_USERS_ROLE]);
    return this.userRolesService.getRoleForUser(identifier, roleId);
  }

  @Patch(':identifier')
  @ApiOperation({
    summary: 'Assign a role to the specified user',
    description: describeAccess({
      summary:
        'Adds the provided role id to the user identified by id or handle.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: ['update:usersRole', 'all:usersRole'],
    }),
  })
  @ApiParam({
    name: 'identifier',
    description: 'Numeric user id or handle',
    required: true,
  })
  @ApiBody({ type: ModifyUserRoleDto })
  @ApiResponse({ status: HttpStatus.OK, type: RoleResponseDto })
  async assignRole(
    @Param('identifier') identifier: string,
    @Body() body: ModifyUserRoleDto,
    @Req() req: AuthenticatedRequest,
  ): Promise<RoleResponseDto> {
    const user = this.getAuthenticatedUser(req);
    this.ensureAdminOrScope(user, [SCOPES.UPDATE_USERS_ROLE]);

    return this.userRolesService.assignRoleToUser(
      identifier,
      body.roleId,
      this.getOperatorId(user),
    );
  }

  @Delete(':identifier/:roleId')
  @ApiOperation({
    summary: 'Remove a role from the specified user',
    description: describeAccess({
      summary:
        'Deletes the specified role assignment from the target member.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: ['delete:usersRole', 'all:usersRole'],
    }),
  })
  @ApiParam({
    name: 'identifier',
    description: 'Numeric user id or handle',
    required: true,
  })
  @ApiParam({
    name: 'roleId',
    description: 'Role id to delete',
    required: true,
    type: Number,
  })
  @ApiResponse({ status: HttpStatus.NO_CONTENT })
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeRole(
    @Param('identifier') identifier: string,
    @Param('roleId', ParseIntPipe) roleId: number,
    @Req() req: AuthenticatedRequest,
  ): Promise<void> {
    const user = this.getAuthenticatedUser(req);
    this.ensureAdminOrScope(user, [SCOPES.DELETE_USERS_ROLE]);

    await this.userRolesService.removeRoleFromUser(identifier, roleId);
  }

  private getAuthenticatedUser(req: AuthenticatedRequest): any {
    const result:any = (req as any).authUser || (req as any).user;
    if(result.roles?.includes(process.env.ADMIN_ROLE_NAME)) {
      result.isAdmin=true;
    }
    return result;
  }

  private extractScopes(user: any): Set<string> {
    const raw = user?.scopes ?? user?.scope;
    if (Array.isArray(raw)) {
      return new Set(raw as string[]);
    }
    if (typeof raw === 'string') {
      return new Set(
        raw
          .split(/[ ,]/)
          .map((scope) => scope.trim())
          .filter(Boolean),
      );
    }
    return new Set();
  }

  private ensureAdminOrScope(user: any, requiredScopes: string[]): void {
    if (user?.isAdmin) {
      return;
    }

    const scopes = this.extractScopes(user);
    const acceptedScopes = new Set(
      [...requiredScopes, SCOPES.ALL_USERS_ROLE].filter(Boolean),
    );

    const hasScope = Array.from(acceptedScopes).some((scope) =>
      scopes.has(scope),
    );

    if (!hasScope) {
      this.logger.warn('Access denied: missing admin role or required scope.');
      throw new ForbiddenException(
        'Admin role or appropriate M2M scope is required to manage user roles.',
      );
    }
  }

  private getOperatorId(user: any): number | undefined {
    if (!user) {
      return undefined;
    }
    const maybeId = Number(user.userId ?? user.id ?? user.userID);
    return Number.isFinite(maybeId) ? maybeId : undefined;
  }
}
