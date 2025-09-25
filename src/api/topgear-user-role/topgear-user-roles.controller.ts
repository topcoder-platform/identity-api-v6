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
import { UserRolesService } from '../user-role/user-roles.service';
import { describeAccess } from '../../shared/swagger/access-description.util';

interface AuthenticatedRequest extends Request {
  authUser?: any;
  user?: any;
}

const TOPGEAR_OPTIONS = { requireTopgear: true } as const;

@ApiTags('topgear-user-roles')
@ApiBearerAuth()
@Controller('topgear-user-roles')
@UseGuards(AuthRequiredGuard)
export class TopgearUserRolesController {
  private readonly logger = new Logger(TopgearUserRolesController.name);

  constructor(private readonly userRolesService: UserRolesService) {}

  @Get(':identifier')
  @ApiOperation({
    summary: 'List roles assigned to a Topgear user by ID or handle',
    description: describeAccess({
      summary:
        'Retrieves Topgear-specific role assignments for the supplied member.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m:
        'Requires `read:topgear-user-roles` or a broader scope such as `all:topgear-user-roles`, `all:usersRole`, `all:roles`, or `all:user`.',
    }),
  })
  @ApiParam({
    name: 'identifier',
    description: 'Numeric user id or handle',
    required: true,
  })
  @ApiResponse({ status: HttpStatus.OK, type: [RoleResponseDto] })
  async listTopgearUserRoles(
    @Param('identifier') identifier: string,
    @Req() req: AuthenticatedRequest,
  ): Promise<RoleResponseDto[]> {
    const user = this.getAuthenticatedUser(req);
    this.ensureAdminOrScope(user, [SCOPES.READ_TOPGEAR_USER_ROLES]);
    return this.userRolesService.getUserRoles(identifier, TOPGEAR_OPTIONS);
  }

  @Get(':identifier/:roleId')
  @ApiOperation({
    summary: 'Get a single role assigned to a Topgear user by role id',
    description: describeAccess({
      summary:
        'Returns the details of a single Topgear role assignment for the member.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m:
        'Requires `read:topgear-user-roles` or a broader scope such as `all:topgear-user-roles`, `all:usersRole`, `all:roles`, or `all:user`.',
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
  async getTopgearRoleForUser(
    @Param('identifier') identifier: string,
    @Param('roleId', ParseIntPipe) roleId: number,
    @Req() req: AuthenticatedRequest,
  ): Promise<RoleResponseDto> {
    const user = this.getAuthenticatedUser(req);
    this.ensureAdminOrScope(user, [SCOPES.READ_TOPGEAR_USER_ROLES]);
    return this.userRolesService.getRoleForUser(
      identifier,
      roleId,
      TOPGEAR_OPTIONS,
    );
  }

  @Patch(':identifier')
  @ApiOperation({
    summary: 'Assign a role to the specified Topgear user',
    description: describeAccess({
      summary:
        'Assigns the provided role id to the target member, limited to Topgear contexts.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m:
        'Requires `write:topgear-user-roles` or a broader scope such as `all:topgear-user-roles`, `all:usersRole`, `all:roles`, or `all:user`.',
    }),
  })
  @ApiParam({
    name: 'identifier',
    description: 'Numeric user id or handle',
    required: true,
  })
  @ApiBody({ type: ModifyUserRoleDto })
  @ApiResponse({ status: HttpStatus.OK, type: RoleResponseDto })
  async assignTopgearRole(
    @Param('identifier') identifier: string,
    @Body() body: ModifyUserRoleDto,
    @Req() req: AuthenticatedRequest,
  ): Promise<RoleResponseDto> {
    const user = this.getAuthenticatedUser(req);
    this.ensureAdminOrScope(user, [SCOPES.WRITE_TOPGEAR_USER_ROLES]);

    return this.userRolesService.assignRoleToUser(
      identifier,
      body.roleId,
      this.getOperatorId(user),
      TOPGEAR_OPTIONS,
    );
  }

  @Delete(':identifier/:roleId')
  @ApiOperation({
    summary: 'Remove a role from the specified Topgear user',
    description: describeAccess({
      summary: 'Removes the specified Topgear role assignment from the member.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m:
        'Requires `write:topgear-user-roles` or a broader scope such as `all:topgear-user-roles`, `all:usersRole`, `all:roles`, or `all:user`.',
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
  async removeTopgearRole(
    @Param('identifier') identifier: string,
    @Param('roleId', ParseIntPipe) roleId: number,
    @Req() req: AuthenticatedRequest,
  ): Promise<void> {
    const user = this.getAuthenticatedUser(req);
    this.ensureAdminOrScope(user, [SCOPES.WRITE_TOPGEAR_USER_ROLES]);

    await this.userRolesService.removeRoleFromUser(
      identifier,
      roleId,
      TOPGEAR_OPTIONS,
    );
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
      [
        ...requiredScopes,
        SCOPES.ALL_TOPGEAR_USER_ROLES,
        SCOPES.ALL_USER_ROLES,
        SCOPES.ALL_USERS_ROLE,
        SCOPES.ALL_ROLES,
        SCOPES.ALL_USERS,
      ].filter(Boolean),
    );

    const hasScope = Array.from(acceptedScopes).some((scope) =>
      scopes.has(scope),
    );

    if (!hasScope) {
      this.logger.warn('Access denied: missing admin role or required scope.');
      throw new ForbiddenException(
        'Admin role or Topgear user-role scope is required to manage Topgear user roles.',
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
