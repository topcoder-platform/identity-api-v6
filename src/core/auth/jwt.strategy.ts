import {
  Injectable,
  UnauthorizedException,
  Logger,
  Inject,
} from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager'; // Correct import
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { Request } from 'express';
import { createJwtVerifier, type JwtVerifier } from 'tc-core-library-js';
import { ConfigService } from '@nestjs/config';
import { Cache } from 'cache-manager'; // Re-add Cache type import
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { PrismaClient } from '@prisma/client';

// Combined payload structure for both HS256 and RS256 tokens
export interface JwtPayload {
  // Common
  iss?: string;
  sub?: string;
  aud?: string | string[];
  iat?: number;
  exp?: number;
  gty?: string;
  isMachine?: boolean;
  scopes?: string[];
  // From HS256 examples
  userId?: string;
  roles?: string[];
  handle?: string;
  email?: string;
  jti?: string;
  // From RS256 examples (Auth0)
  azp?: string;
  scope?: string;
  permissions?: string[];
}

// AuthenticatedUser now includes DB roles
export interface AuthenticatedUser {
  userId: string;
  roles: string[]; // Populated from DB lookup
  scopes: string[]; // Populated from JWT payload
  isAdmin: boolean; // Determined from DB roles
  isMachine: boolean; // Determined from JWT payload
  handle?: string; // From JWT payload
  email?: string; // From JWT payload
  payload: JwtPayload; // Original JWT payload
}

/** Authenticates bearer tokens through tc-core and enriches human identities with database roles. */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);
  private readonly verifier: JwtVerifier;
  private readonly cacheTtlSeconds: number;

  constructor(
    private configService: ConfigService,
    @Inject(PRISMA_CLIENT)
    private prisma: PrismaClient,
    @Inject(CACHE_MANAGER) private cacheManager: Cache, // Re-add Inject Cache Manager
  ) {
    super();
    this.verifier = createJwtVerifier({
      VALID_ISSUERS: configService.get<string>('VALID_ISSUERS'),
      AUTH_SECRET: configService.get<string>('AUTH_SECRET'),
      JWT_AUDIENCE: configService.get<string>('JWT_AUDIENCE'),
      AUTH0_AUDIENCE: configService.get<string>('AUTH0_AUDIENCE'),
    });
    // Default cache TTL to 1 hour (3600 seconds), allow override via env
    this.cacheTtlSeconds = parseInt(
      configService.get<string>('AUTH_CACHE_TTL_SECONDS', '3600'),
      10,
    );
    this.logger.log('Initialized shared JWT issuer and audience policies');
    this.logger.log(`Auth cache TTL set to ${this.cacheTtlSeconds} seconds.`);
  }

  /** Returns the v6 database-permission cache key for an issuer/member identity; never throws. */
  private getCacheKey(userId: string): string {
    return `auth:v6:roles:${userId}`;
  }

  /** Verifies the request bearer token through tc-core, then loads service roles; returns identity or throws UnauthorizedException. */
  async validate(request: Request): Promise<AuthenticatedUser> {
    const header = request.headers.authorization;
    const match = typeof header === 'string' ? /^Bearer ([^\s]+)$/i.exec(header) : null;
    if (!match) throw new UnauthorizedException('A bearer token is required');
    try {
      const payload = await this.verifier.verify(match[1]);
      return await this.buildUser({ ...payload, userId: payload.userId === undefined ? undefined : String(payload.userId) });
    } catch { throw new UnauthorizedException('Invalid or expired access token'); }
  }

  /** Enriches verified claims with cached database roles; token scopes and machine identity are always taken from the current token.
   * @param payload Verified and normalized identity. @returns User with database authorization.
   * @throws UnauthorizedException when a human identity is missing or database authorization cannot be loaded.
   */
  private async buildUser(payload: JwtPayload): Promise<AuthenticatedUser> {
    const isMachine = payload.isMachine === true;
    const userId = payload.userId;
    let permissions = { roles: [] as string[], isAdmin: false };
    if (!isMachine) {
      if (!userId) throw new UnauthorizedException('A member ID is required');
      const cacheKey = this.getCacheKey(`${payload.iss}:${userId}`);
      try {
        const cached = await this.cacheManager.get<{ roles: string[]; isAdmin: boolean }>(cacheKey);
        permissions = cached ?? await this.fetchUserRolesAndAdminStatusFromDb(userId);
        if (!cached) await this.cacheManager.set(cacheKey, permissions, this.cacheTtlSeconds * 1000);
      } catch {
        permissions = await this.fetchUserRolesAndAdminStatusFromDb(userId);
      }
    }
    return {
      userId: userId || payload.sub || '',
      roles: permissions.roles,
      isAdmin: permissions.isAdmin,
      scopes: payload.scopes ?? [],
      isMachine,
      handle: payload.handle,
      email: payload.email,
      payload,
    };
  }

  /**
   * Fetches all assigned roles for a user from the database and determines
   * if the user has the administrator role.
   * @param userId The user ID (from JWT 'sub' or 'userId' claim)
   * @returns An object containing the list of role names and the admin status.
   */
  private async fetchUserRolesAndAdminStatusFromDb(
    userId: string,
  ): Promise<{ roles: string[]; isAdmin: boolean }> {
    const adminRoleName = this.configService.get<string>('ADMIN_ROLE_NAME');
    this.logger.debug(
      `[JwtStrategy] Configured ADMIN_ROLE_NAME: '${adminRoleName}'`,
    );

    if (!adminRoleName) {
      this.logger.error(
        '[JwtStrategy] ADMIN_ROLE_NAME environment variable is not set.',
      );
      // Cannot determine admin status, proceed without it, return no roles.
      return { roles: [], isAdmin: false };
    }

    const numericUserId = parseInt(userId, 10);
    if (isNaN(numericUserId)) {
      this.logger.warn(
        `[JwtStrategy] Cannot fetch roles: User ID '${userId}' is not a valid number.`,
      );
      return { roles: [], isAdmin: false }; // No roles if ID is invalid
    }

    try {
      // Find all role assignments for the user (assuming subjectType 1 = User)
      const assignments = await this.prisma.roleAssignment.findMany({
        where: {
          subjectId: numericUserId,
          subjectType: 1, // Hardcoded assumption: 1 = User
        },
        include: {
          role: {
            // Include the related Role to get the name
            select: { name: true },
          },
        },
      });

      // Extract role names
      const dbRoles = assignments
        .map((assignment) => assignment.role?.name)
        .filter((name): name is string => Boolean(name));
      this.logger.debug(
        `[JwtStrategy] Roles from DB for user ${userId}: ${JSON.stringify(dbRoles)}`,
      );

      // Check if the admin role name is among the assigned roles (case-insensitive)
      const normalizedAdminRole = adminRoleName.toLowerCase();
      const isAdmin = dbRoles
        .map((roleName) => roleName.toLowerCase())
        .includes(normalizedAdminRole);
      this.logger.debug(
        `[JwtStrategy] isAdmin check for user ${userId} (role: '${adminRoleName}'): ${isAdmin}`,
      );

      if (dbRoles.length > 0) {
        this.logger.debug(
          `Roles found for user ${userId} in DB: [${dbRoles.join(', ')}]. isAdmin: ${isAdmin}`,
        );
      } else {
        this.logger.debug(`No roles found for user ${userId} in DB.`);
      }

      return { roles: dbRoles, isAdmin };
    } catch (error) {
      this.logger.error(
        `[JwtStrategy] Error fetching roles for user ${userId} from DB: ${error.message}`,
        error.stack,
      );
      // Fail safe in case of DB error
      return { roles: [], isAdmin: false };
    }
  }
}
