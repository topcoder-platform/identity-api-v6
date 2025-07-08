import {
  Injectable,
  UnauthorizedException,
  Logger,
  Inject,
} from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager'; // Correct import
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy, StrategyOptions } from 'passport-jwt';
import { passportJwtSecret } from 'jwks-rsa';
import { ConfigService } from '@nestjs/config';
import { Cache } from 'cache-manager'; // Re-add Cache type import
import { PRISMA_CLIENT_AUTHORIZATION } from '../../shared/prisma/prisma.module';
import { PrismaClient as PrismaClientAuthorization } from '@prisma/client-authorization';

// Combined payload structure for both HS256 and RS256 tokens
export interface JwtPayload {
  // Common
  iss?: string;
  sub?: string;
  aud?: string | string[];
  iat?: number;
  exp?: number;
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

// Helper function to create Strategy Options based on config
const createStrategyOptions = (
  configService: ConfigService,
): StrategyOptions => {
  const validationMode = configService.get<string>(
    'JWT_VALIDATION_MODE',
    'RS256',
  );
  let options: StrategyOptions;
  if (validationMode === 'HS256') {
    const authSecret = configService.get<string>('AUTH_SECRET');
    if (!authSecret) {
      console.error('[JwtStrategy] AUTH_SECRET must be set for HS256 mode.');
      throw new Error('AUTH_SECRET must be set.');
    }
    const issuerURL = configService.get<string>('JWT_ISSUER_URL');
    const audience = configService.get<string>('JWT_AUDIENCE');
    if (!issuerURL)
      console.warn('[JwtStrategy] JWT_ISSUER_URL not set for HS256.');
    if (!audience)
      console.warn('[JwtStrategy] JWT_AUDIENCE not set for HS256.');

    options = {
      secretOrKey: authSecret,
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      audience: audience || undefined,
      issuer: issuerURL || undefined,
      algorithms: ['HS256'],
    };
  } else {
    // Default to RS256
    const issuerURL = configService.get<string>('JWT_ISSUER_URL');
    const jwksUri = configService.get<string>('JWT_JWKS_URI');
    const audience = configService.get<string>('JWT_AUDIENCE');

    if (!issuerURL || !jwksUri || !audience) {
      console.error(
        '[JwtStrategy] JWT_ISSUER_URL, JWT_JWKS_URI, JWT_AUDIENCE must be set for RS256 mode.',
      );
      throw new Error(
        'Required JWT environment variables missing for RS256 mode.',
      );
    }
    options = {
      secretOrKeyProvider: passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: jwksUri,
      }),
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      audience: audience,
      issuer: issuerURL,
      algorithms: ['RS256'],
    };
  }
  return options;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);
  private readonly validationMode: string;
  private readonly cacheTtlSeconds: number;

  constructor(
    private configService: ConfigService,
    @Inject(PRISMA_CLIENT_AUTHORIZATION)
    private prismaAuth: PrismaClientAuthorization,
    @Inject(CACHE_MANAGER) private cacheManager: Cache, // Re-add Inject Cache Manager
  ) {
    const strategyOptions = createStrategyOptions(configService);
    super(strategyOptions);
    this.validationMode = configService.get<string>(
      'JWT_VALIDATION_MODE',
      'RS256',
    );
    // Default cache TTL to 1 hour (3600 seconds), allow override via env
    this.cacheTtlSeconds = parseInt(
      configService.get<string>('AUTH_CACHE_TTL_SECONDS', '3600'),
      10,
    );
    this.logger.log(
      `Initialized JWT Strategy with mode: ${this.validationMode}`,
    );
    this.logger.log(`Auth cache TTL set to ${this.cacheTtlSeconds} seconds.`);
  }

  private getCacheKey(userId: string): string {
    return `auth:user:${userId}`;
  }

  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    this.logger.debug('[JwtStrategy] --- Entering validate method ---'); // Log entry
    this.logger.debug(
      `[JwtStrategy] Raw validated payload received from JWT: ${JSON.stringify(
        payload,
      )}`,
    );

    const userId = payload.userId || payload.sub;
    if (!userId) {
      this.logger.error(
        '[JwtStrategy] JWT payload missing user identifier (userId or sub claim).',
      );
      throw new UnauthorizedException(
        'JWT payload missing user identifier (userId or sub claim).',
      );
    }

    this.logger.debug(`[JwtStrategy] Extracted userId: ${userId}`); // Log extracted userId

    if (this.validationMode === 'HS256' && payload.roles) {
      this.logger.debug(
        `[JwtStrategy] Roles from HS256 token payload for user ${userId}: ${JSON.stringify(payload.roles)}`,
      );
    }

    const cacheKey = this.getCacheKey(userId);

    try {
      // 1. Check cache first
      const cachedUser =
        await this.cacheManager.get<AuthenticatedUser>(cacheKey);
      if (cachedUser) {
        this.logger.debug(`Returning cached auth data for user ${userId}`);
        // Ensure the payload is attached if returning from cache
        // (Payload isn't essential for authorization checks but good to have consistency)
        return { ...cachedUser, payload: payload };
      }
    } catch (error) {
      this.logger.error(
        `Error reading auth cache for user ${userId}: ${error.message}`,
        error.stack,
      );
      // Proceed without cache if error occurs
    }

    this.logger.debug(
      `[JwtStrategy] Cache miss for user ${userId}. Fetching roles from DB.`,
    );

    // 2. Fetch roles and determine admin status from DB (if not cached)
    let dbRoles: string[] = [];
    let isAdmin = false;
    try {
      const result = await this.fetchUserRolesAndAdminStatusFromDb(userId);
      dbRoles = result.roles;
      isAdmin = result.isAdmin;
      this.logger.debug(
        `[JwtStrategy] Roles for user ${userId} from DB: ${dbRoles.join(', ')}. isAdmin: ${isAdmin}`,
      );
    } catch (error) {
      this.logger.error(
        `[JwtStrategy] Error fetching roles/admin status for user ${userId} from DB: ${error.message}`,
        error.stack,
      );
      // If we cannot fetch roles, authentication fails
      throw new UnauthorizedException(
        `Failed to fetch authorization details for user ${userId}`,
      );
    }

    // Extract scopes from token payload
    let scopes: string[] = [];
    if (payload.scope && typeof payload.scope === 'string') {
      scopes = payload.scope.split(' ');
    } else if (payload.permissions && Array.isArray(payload.permissions)) {
      scopes = payload.permissions;
    }

    // Check if this is a machine token
    const isMachine = payload.azp === 'machine' || payload.aud === 'machine';

    // 3. Construct the AuthenticatedUser object
    const authenticatedUser: AuthenticatedUser = {
      userId: userId,
      roles: dbRoles, // Use roles fetched from the database
      scopes: scopes, // Use scopes from the token
      isAdmin: isAdmin, // Use admin status derived from DB roles
      isMachine: isMachine, // Use machine status derived from JWT payload
      handle: payload.handle,
      email: payload.email,
      payload: payload,
    };

    this.logger.debug(
      `[JwtStrategy] Constructed AuthenticatedUser object: ${JSON.stringify(authenticatedUser)}`,
    ); // Log the final object

    // 4. Store the result in cache
    try {
      // Create a cacheable version without the potentially large payload
      const { payload: _, ...cacheableUser } = authenticatedUser;
      void _;
      await this.cacheManager.set(
        cacheKey,
        cacheableUser,
        this.cacheTtlSeconds * 1000,
      ); // TTL in milliseconds
      this.logger.debug(
        `Stored auth data for user ${userId} in cache (excluding payload).`,
      );
    } catch (error) {
      this.logger.error(
        `Error writing auth cache for user ${userId}: ${error.message}`,
        error.stack,
      );
      // Continue even if caching fails
    }

    this.logger.debug(
      '[JwtStrategy] --- Exiting validate method successfully ---',
    ); // Log successful exit
    return authenticatedUser; // Return the full object for the current request
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
      const assignments = await this.prismaAuth.roleAssignment.findMany({
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
      const dbRoles = assignments.map((assignment) => assignment.role.name);
      this.logger.debug(
        `[JwtStrategy] Roles from DB for user ${userId}: ${JSON.stringify(dbRoles)}`,
      );

      // Check if the admin role name is among the assigned roles
      const isAdmin = dbRoles.includes(adminRoleName);
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
