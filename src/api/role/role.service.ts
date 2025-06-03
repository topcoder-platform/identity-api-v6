import {
  Injectable,
  Inject,
  NotFoundException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { PRISMA_CLIENT_AUTHORIZATION } from '../../shared/prisma/prisma.module';
import {
  PrismaClient as PrismaClientAuthorization,
  Role,
} from '@prisma/client-authorization';
import { RoleResponseDto } from '../../dto/role/role.dto';
import { MemberApiService } from '../../shared/member-api/member-api.service';
import { MemberInfoResponseDto } from '../../dto/member/member.dto';

interface InternalCreateRoleDto {
  roleName: string;
}

interface InternalUpdateRoleDto {
  roleName: string;
}

@Injectable()
export class RoleService {
  private readonly logger = new Logger(RoleService.name);

  constructor(
    @Inject(PRISMA_CLIENT_AUTHORIZATION)
    private prismaAuth: PrismaClientAuthorization,
    private memberApiService: MemberApiService,
  ) {}

  private mapToRoleResponseDto(
    role: Role,
    memberInfos?: MemberInfoResponseDto[],
  ): RoleResponseDto {
    const dto = new RoleResponseDto();
    dto.id = role.id;
    dto.roleName = role.name;
    dto.createdAt = role.createdAt?.toISOString();
    dto.createdBy = role.createdBy;
    dto.updatedAt = role.modifiedAt?.toISOString();
    dto.updatedBy = role.modifiedBy;
    dto.subjects = memberInfos;
    return dto;
  }

  async findAll(
    subjectId?: number,
    fields?: string,
  ): Promise<RoleResponseDto[]> {
    this.logger.debug(`Finding all roles, subjectId: ${subjectId}`);

    const whereClause: any = subjectId
      ? {
          roleAssignments: {
            some: {
              subjectId: subjectId,
              subjectType: 1,
            },
          },
        }
      : {};

    const roles = await this.prismaAuth.role.findMany({
      where: whereClause,
    });

    return roles.map((role) => this.mapToRoleResponseDto(role));
  }

  async findOne(
    roleId: number,
    fields?: string,
  ): Promise<RoleResponseDto | null> {
    this.logger.debug(`Finding role by id: ${roleId}, fields: ${fields}`);
    const includeSubjects = fields?.toLowerCase().includes('subjects');

    const role = await this.prismaAuth.role.findUnique({
      where: { id: roleId },
      include: {
        roleAssignments: includeSubjects
          ? {
              where: { subjectType: 1 },
              select: { subjectId: true },
            }
          : false,
      },
    });

    if (!role) {
      this.logger.warn(`Role with ID ${roleId} not found.`);
      return null;
    }

    let memberInfos: MemberInfoResponseDto[] | undefined = undefined;

    if (
      includeSubjects &&
      role.roleAssignments &&
      role.roleAssignments.length > 0
    ) {
      const subjectIds = role.roleAssignments.map((a) => a.subjectId);
      this.logger.debug(
        `Fetching member info for ${subjectIds.length} subject IDs.`,
      );
      try {
        memberInfos = await this.memberApiService.getUserInfoList(subjectIds);
      } catch (error) {
        this.logger.error(
          `Failed to fetch member info for role ${roleId}: ${error.message}`,
          error.stack,
        );
      }
    }

    return this.mapToRoleResponseDto(role, memberInfos);
  }

  async create(
    createRoleDto: InternalCreateRoleDto,
    creatorId: number,
  ): Promise<RoleResponseDto> {
    this.logger.debug(
      `Creating role: ${JSON.stringify(createRoleDto)} by user ${creatorId}`,
    );
    const existing = await this.prismaAuth.role.findUnique({
      where: { name: createRoleDto.roleName },
    });
    if (existing) {
      throw new ConflictException(
        `Role with name '${createRoleDto.roleName}' already exists.`,
      );
    }

    const newRole = await this.prismaAuth.role.create({
      data: {
        name: createRoleDto.roleName,
        createdBy: creatorId,
        modifiedBy: creatorId,
      },
    });
    return this.mapToRoleResponseDto(newRole);
  }

  async update(
    roleId: number,
    updateRoleDto: InternalUpdateRoleDto,
    modifierId: number,
  ): Promise<RoleResponseDto> {
    this.logger.debug(
      `Updating role ${roleId}: ${JSON.stringify(updateRoleDto)} by user ${modifierId}`,
    );

    return this.prismaAuth.$transaction(async (tx) => {
      const existingRole = await tx.role.findUnique({
        where: { id: roleId },
      });

      if (!existingRole) {
        throw new NotFoundException(`Role with ID ${roleId} not found.`);
      }

      // If roleName is provided and different from the current one, check for conflicts
      if (
        updateRoleDto.roleName &&
        updateRoleDto.roleName !== existingRole.name
      ) {
        const conflictingRole = await tx.role.findUnique({
          where: { name: updateRoleDto.roleName },
        });
        if (conflictingRole) {
          throw new ConflictException(
            `Role with name '${updateRoleDto.roleName}' already exists.`,
          );
        }
      }

      try {
        const updatedRole = await tx.role.update({
          where: { id: roleId },
          data: {
            name: updateRoleDto.roleName,
            modifiedBy: modifierId,
          },
        });
        // Assuming mapToRoleResponseDto does not involve database operations
        // or uses the correct Prisma client if it does.
        // For simplicity, we'll call it outside the direct scope of this change's focus,
        // but if it makes its own DB calls, it might need `tx` or be re-evaluated.
        // However, standard DTO mapping usually doesn't.
        return this.mapToRoleResponseDto(updatedRole);
      } catch (error) {
        // The P2002 check for unique constraint violation on 'name'
        // becomes a fallback, as the explicit check above should catch it.
        if (error.code === 'P2002' && error.meta?.target?.includes('name')) {
          throw new ConflictException(
            `Role with name '${updateRoleDto.roleName}' already exists.`,
          );
        }
        this.logger.error(
          `Error updating role ${roleId}: ${error.message}`,
          error.stack,
        );
        throw error;
      }
    });
  }

  async remove(roleId: number): Promise<void> {
    this.logger.debug(`Removing role ${roleId}`);
    const existingRole = await this.prismaAuth.role.findUnique({
      where: { id: roleId },
    });
    if (!existingRole) {
      throw new NotFoundException(`Role with ID ${roleId} not found.`);
    }
    try {
      await this.prismaAuth.roleAssignment.deleteMany({
        where: { roleId: roleId },
      });

      await this.prismaAuth.role.delete({
        where: { id: roleId },
      });
    } catch (error) {
      if (error.code === 'P2003' || error.code === 'P2025') {
        const assignments = await this.prismaAuth.roleAssignment.count({
          where: { roleId },
        });
        if (assignments > 0) {
          throw new ConflictException(
            `Cannot delete role ${roleId} as it is still assigned to subjects.`,
          );
        } else {
          throw new NotFoundException(
            `Role with ID ${roleId} not found or could not be deleted.`,
          );
        }
      }
      this.logger.error(
        `Failed to delete role ${roleId}: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  async assignRoleToSubject(
    roleId: number,
    subjectId: number,
    operatorId: number,
  ): Promise<void> {
    this.logger.debug(
      `Assigning role ${roleId} to subject ${subjectId} by operator ${operatorId}`,
    );
    const roleExists = await this.prismaAuth.role.count({
      where: { id: roleId },
    });
    if (!roleExists) {
      throw new NotFoundException(`Role with ID ${roleId} not found.`);
    }

    try {
      await this.prismaAuth.roleAssignment.create({
        data: {
          roleId: roleId,
          subjectId: subjectId,
          subjectType: 1,
          createdBy: operatorId,
          modifiedBy: operatorId,
        },
      });
    } catch (error) {
      if (error.code === 'P2002') {
        this.logger.warn(
          `Attempt to assign role ${roleId} to subject ${subjectId} which already exists.`,
        );
        throw new ConflictException(
          `Role ${roleId} is already assigned to subject ${subjectId}.`,
        );
      } else {
        this.logger.error(
          `Failed to assign role ${roleId} to subject ${subjectId}: ${error.message}`,
          error.stack,
        );
        throw error;
      }
    }
  }

  async deassignRoleFromSubject(
    roleId: number,
    subjectId: number,
  ): Promise<void> {
    this.logger.debug(`Deassigning role ${roleId} from subject ${subjectId}`);
    const deleteResult = await this.prismaAuth.roleAssignment.deleteMany({
      where: {
        roleId: roleId,
        subjectId: subjectId,
        subjectType: 1,
      },
    });

    if (deleteResult.count === 0) {
      this.logger.warn(
        `No assignment found for role ${roleId} and subject ${subjectId} to deassign.`,
      );
    }
  }

  async checkSubjectHasRole(
    roleId: number,
    subjectId: number,
  ): Promise<RoleResponseDto | null> {
    this.logger.debug(`Checking if subject ${subjectId} has role ${roleId}`);
    const assignment = await this.prismaAuth.roleAssignment.findUnique({
      where: {
        roleId_subjectId_subjectType: {
          roleId: roleId,
          subjectId: subjectId,
          subjectType: 1,
        },
      },
      include: {
        role: true,
      },
    });

    if (!assignment || !assignment.role) {
      return null;
    }

    return this.mapToRoleResponseDto(assignment.role);
  }

  /**
   * Finds a role by its name.
   */
  async findRoleByName(roleName: string): Promise<Role | null> {
    this.logger.debug(`Finding role by name: ${roleName}`);
    return this.prismaAuth.role.findUnique({
      where: { name: roleName },
    });
  }

  /**
   * Assigns a role to a subject using the role name.
   */
  async assignRoleByName(
    roleName: string,
    subjectId: number,
    operatorId: number,
  ): Promise<void> {
    this.logger.debug(
      `Assigning role '${roleName}' to subject ${subjectId} by operator ${operatorId}`,
    );
    const role = await this.findRoleByName(roleName);
    if (!role) {
      throw new NotFoundException(`Role with name '${roleName}' not found.`);
    }
    await this.assignRoleToSubject(role.id, subjectId, operatorId);
  }

  /**
   * Deassigns a role from a subject using the role name.
   */
  async deassignRoleByName(roleName: string, subjectId: number): Promise<void> {
    this.logger.debug(
      `Deassigning role by name '${roleName}' from subject ${subjectId}`,
    );
    const role = await this.findRoleByName(roleName);
    if (!role) {
      throw new NotFoundException(`Role with name '${roleName}' not found.`);
    }
    await this.deassignRoleFromSubject(role.id, subjectId);
  }
}
