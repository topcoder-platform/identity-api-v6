import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaClient, Role } from '@prisma/client';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { Constants } from '../../core/constant/constants';
import { RoleService } from '../role/role.service';
import { RoleResponseDto } from '../../dto/role/role.dto';

interface ResolvedUser {
  userId: number;
  handle: string;
}

@Injectable()
export class UserRolesService {
  private readonly logger = new Logger(UserRolesService.name);

  constructor(
    @Inject(PRISMA_CLIENT) private readonly prismaClient: PrismaClient,
    private readonly roleService: RoleService,
  ) {}

  private toRoleResponseDto(role: Role): RoleResponseDto {
    const dto = new RoleResponseDto();
    dto.id = role.id;
    dto.roleName = role.name;
    dto.createdAt = role.createdAt?.toISOString();
    dto.createdBy = role.createdBy;
    dto.updatedAt = role.modifiedAt?.toISOString();
    dto.updatedBy = role.modifiedBy;
    return dto;
  }

  private async resolveUser(identifier: string): Promise<ResolvedUser> {
    const trimmed = identifier?.trim();
    if (!trimmed) {
      throw new BadRequestException('User identifier is required.');
    }

    this.logger.debug(`Resolving user identifier '${trimmed}'.`);

    const handleMatch = await this.prismaClient.user.findFirst({
      where: { handle_lower: trimmed.toLowerCase() },
      select: { user_id: true, handle: true },
    });

    if (handleMatch) {
      const userId = Number(handleMatch.user_id);
      this.logger.debug(
        `Resolved identifier '${trimmed}' to handle '${handleMatch.handle}' (ID ${userId}).`,
      );
      return { userId, handle: handleMatch.handle };
    }

    const numericId = Number(trimmed);
    if (!Number.isNaN(numericId)) {
      const idMatch = await this.prismaClient.user.findUnique({
        where: { user_id: numericId },
        select: { user_id: true, handle: true },
      });
      if (idMatch) {
        const userId = Number(idMatch.user_id);
        this.logger.debug(
          `Resolved identifier '${trimmed}' to user id ${userId}.`,
        );
        return { userId, handle: idMatch.handle };
      }
    }

    this.logger.warn(`Unable to resolve user identifier '${trimmed}'.`);
    throw new NotFoundException(
      `User '${trimmed}' was not found by handle or identifier.`,
    );
  }

  async getUserRoles(identifier: string): Promise<RoleResponseDto[]> {
    const { userId } = await this.resolveUser(identifier);
    const assignments = await this.prismaClient.roleAssignment.findMany({
      where: {
        subjectId: userId,
        subjectType: Constants.memberSubjectType,
      },
      include: { role: true },
      orderBy: { role: { name: 'asc' } },
    });

    return assignments
      .filter((assignment) => assignment.role)
      .map((assignment) => this.toRoleResponseDto(assignment.role));
  }

  async getRoleForUser(
    identifier: string,
    roleId: number,
  ): Promise<RoleResponseDto> {
    const { userId } = await this.resolveUser(identifier);
    const role = await this.roleService.checkSubjectHasRole(roleId, userId);
    if (!role) {
      throw new NotFoundException(
        `User '${identifier}' does not have role with id ${roleId}.`,
      );
    }
    return role;
  }

  async assignRoleToUser(
    identifier: string,
    roleId: number,
    operatorId?: number,
  ): Promise<RoleResponseDto> {
    const { userId } = await this.resolveUser(identifier);
    const actorId =
      typeof operatorId === 'number' && Number.isFinite(operatorId)
        ? operatorId
        : userId;

    await this.roleService.assignRoleToSubject(roleId, userId, actorId);
    const assigned = await this.roleService.checkSubjectHasRole(roleId, userId);
    if (!assigned) {
      throw new NotFoundException(
        `Role ${roleId} was not assigned to user '${identifier}'.`,
      );
    }
    return assigned;
  }

  async removeRoleFromUser(identifier: string, roleId: number): Promise<void> {
    const { userId } = await this.resolveUser(identifier);
    const role = await this.roleService.checkSubjectHasRole(roleId, userId);
    if (!role) {
      throw new NotFoundException(
        `User '${identifier}' does not have role with id ${roleId}.`,
      );
    }
    await this.roleService.deassignRoleFromSubject(roleId, userId);
  }
}
