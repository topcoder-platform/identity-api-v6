import {
  Injectable,
  Inject,
  NotFoundException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { PrismaClient, Role } from '@prisma/client';
import { RoleResponseDto } from '../../dto/role/role.dto';
import { MemberApiService } from '../../shared/member-api/member-api.service';
import { MemberInfoResponseDto } from '../../dto/member/member.dto';
import { Constants } from '../../core/constant/constants';

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
    @Inject(PRISMA_CLIENT)
    private prismaClient: PrismaClient,
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

  /**
   * List members (subjects) assigned to a given role, with optional filters and pagination.
   */
  async listRoleMembers(
    roleId: number,
    opts?: { userId?: number; userHandle?: string; email?: string },
    page: number = 1,
    perPage: number = Constants.defaultPageSize,
  ): Promise<{ members: MemberInfoResponseDto[]; total: number }> {
    this.logger.debug(
      `Listing role members for roleId=${roleId} with filters ${JSON.stringify(
        opts || {},
      )}`,
    );

    // Ensure role exists
    const existing = await this.prismaClient.role.findUnique({ where: { id: roleId } });
    if (!existing) {
      throw new NotFoundException(`Role with ID ${roleId} not found.`);
    }

    // Build base query for assignments
    const whereClause: any = {
      roleId,
      subjectType: Constants.memberSubjectType,
    };

    if (opts?.userId && Number.isFinite(opts.userId) && opts.userId > 0) {
      whereClause.subjectId = opts.userId;
    }

    const assignments = await this.prismaClient.roleAssignment.findMany({
      where: whereClause,
      select: { subjectId: true },
    });

    if (!assignments.length) {
      return { members: [], total: 0 };
    }

    const subjectIds = assignments.map((a) => a.subjectId);

    // When filtering by handle/email, we must fetch then filter to compute total correctly
    if (opts?.userHandle || opts?.email) {
      let members = (await this.memberApiService.getUserInfoList(
        subjectIds,
      )) as MemberInfoResponseDto[];
      if (opts.userHandle) {
        members = members.filter((m) => m.handle === opts.userHandle);
      }
      if (opts.email) {
        members = members.filter((m) => m.email === opts.email);
      }
      const total = members.length;
      const start = Math.max(0, (page - 1) * perPage);
      const end = start + perPage;
      return { members: members.slice(start, end), total };
    }

    // Otherwise paginate subjectIds first, then fetch only the required page
    const total = subjectIds.length;
    const start = Math.max(0, (page - 1) * perPage);
    const end = start + perPage;
    const pageIds = subjectIds.slice(start, end);
    if (pageIds.length === 0) {
      return { members: [], total };
    }
    const pageMembers = (await this.memberApiService.getUserInfoList(
      pageIds,
    )) as MemberInfoResponseDto[];

    // Fallback: ensure all assigned subject IDs are represented even if
    // Member API does not return info for some IDs. This guarantees the
    // identity API returns all role members regardless of audit field values.
    const returnedIds = new Set<number>(pageMembers.map((m) => m.userId));
    const missingIds = pageIds.filter((id) => !returnedIds.has(id));
    const placeholders: MemberInfoResponseDto[] = missingIds.map((id) =>
      ({ userId: id, handle: null as any, email: null as any }) as unknown as MemberInfoResponseDto,
    );

    return { members: [...pageMembers, ...placeholders], total };
  }

  async findAll(
    subjectId?: number,
    roleName?: string,
  ): Promise<RoleResponseDto[]> {
    this.logger.debug(
      `Finding all roles, subjectId: ${subjectId}, roleName: ${roleName}`,
    );

    const whereClause: any = {};
    if (subjectId) {
      whereClause.roleAssignments = {
        some: {
          subjectId: subjectId,
          subjectType: Constants.memberSubjectType,
        },
      };
    }
    if (roleName && roleName.trim().length > 0) {
      whereClause.name = roleName;
    }

    const roles = await this.prismaClient.role.findMany({
      where: whereClause,
    });
    // No member infos in this section; omit subjects field by leaving undefined
    return roles.map((role) => this.mapToRoleResponseDto(role));
  }

  async findOne(
    roleId: number,
    selector?: string,
  ): Promise<RoleResponseDto | null> {
    this.logger.debug(`Finding role by id: ${roleId}, selector: ${selector}`);
    const includeSubjects = selector?.toLowerCase().includes('subjects');

    const role = await this.prismaClient.role.findUnique({
      where: { id: roleId },
      include: {
        roleAssignments: includeSubjects
          ? {
              where: { subjectType: Constants.memberSubjectType },
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
        const infos = await this.memberApiService.getUserInfoList(subjectIds);
        const returnedIds = new Set<number>(infos.map((m) => m.userId));
        const missingIds = subjectIds.filter((id) => !returnedIds.has(id));
        const placeholders = missingIds.map((id) =>
          ({ userId: id, handle: null as any, email: null as any }) as unknown as MemberInfoResponseDto,
        );
        memberInfos = [...infos, ...placeholders];
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
    const existing = await this.prismaClient.role.findUnique({
      where: { name: createRoleDto.roleName },
    });
    if (existing) {
      throw new ConflictException(
        `Role with name '${createRoleDto.roleName}' already exists.`,
      );
    }

    const newRole = await this.prismaClient.role.create({
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

    return this.prismaClient.$transaction(async (tx) => {
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
        if (
          error.code === Constants.prismaUniqueConflictcode &&
          error.meta?.target?.includes('name')
        ) {
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
    const existingRole = await this.prismaClient.role.findUnique({
      where: { id: roleId },
    });
    if (!existingRole) {
      throw new NotFoundException(`Role with ID ${roleId} not found.`);
    }
    try {
      await this.prismaClient.roleAssignment.deleteMany({
        where: { roleId: roleId },
      });

      await this.prismaClient.role.delete({
        where: { id: roleId },
      });
    } catch (error) {
      if (
        error.code === 'P2003' ||
        error.code === Constants.prismaNotFoundCode
      ) {
        const assignments = await this.prismaClient.roleAssignment.count({
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
    const roleExists = await this.prismaClient.role.count({
      where: { id: roleId },
    });
    if (!roleExists) {
      throw new NotFoundException(`Role with ID ${roleId} not found.`);
    }

    try {
      const now = new Date();
      await this.prismaClient.roleAssignment.create({
        data: {
          roleId: roleId,
          subjectId: subjectId,
          subjectType: Constants.memberSubjectType,
          createdBy: operatorId,
          createdAt: now,
          modifiedBy: operatorId,
          modifiedAt: now,
        },
      });
    } catch (error) {
      if (error.code === Constants.prismaUniqueConflictcode) {
        this.logger.warn(
          `Attempt to assign role ${roleId} to subject ${subjectId} which already exists. Ignoring duplicate.`,
        );
        return;
      }
      this.logger.error(
        `Failed to assign role ${roleId} to subject ${subjectId}: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  async deassignRoleFromSubject(
    roleId: number,
    subjectId: number,
  ): Promise<void> {
    this.logger.debug(`Deassigning role ${roleId} from subject ${subjectId}`);
    const deleteResult = await this.prismaClient.roleAssignment.deleteMany({
      where: {
        roleId: roleId,
        subjectId: subjectId,
        subjectType: Constants.memberSubjectType,
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
    const assignment = await this.prismaClient.roleAssignment.findUnique({
      where: {
        roleId_subjectId_subjectType: {
          roleId: roleId,
          subjectId: subjectId,
          subjectType: Constants.memberSubjectType,
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
    return this.prismaClient.role.findUnique({
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
