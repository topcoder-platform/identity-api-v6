import {
  Controller,
  Get,
  Post,
  Patch,
  Put,
  Delete,
  Body,
  Param,
  Query,
  Req,
  Logger,
  ForbiddenException,
  BadRequestException,
  UnauthorizedException,
  ParseIntPipe,
  HttpCode,
  HttpStatus,
  UseFilters,
  UseGuards,
  InternalServerErrorException,
  NotFoundException,
  Inject,
  NotImplementedException,
  Res,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { UserService } from './user.service';
import { UserProfileService } from './user-profile.service';
import { AuthFlowService } from './auth-flow.service';
import { TwoFactorAuthService } from './two-factor-auth.service';
import { ValidationService } from './validation.service';
import { AuthenticatedUser, JwtStrategy } from '../../core/auth/jwt.strategy'; // For type hints
import { Roles } from '../../auth/decorators/roles.decorator';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { ADMIN_ROLE, SCOPES } from '../../auth/constants';
import { SelfOrAdmin } from '../../auth/decorators/self-or-admin.decorator';
import { SelfOrAdminGuard } from '../../auth/guards/self-or-admin.guard';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';
import { RoleService } from '../role/role.service'; // If needed directly
import * as DTOs from '../../dto/user/user.dto'; // Import all user DTOs
import { Constants } from '../../core/constant/constants';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiParam,
  ApiBody,
  ApiHeader,
  ApiConsumes,
} from '@nestjs/swagger'; // For Swagger documentation
import { ValidationExceptionFilter } from '../../shared/filters/validation-exception.filter';
// import { AuthGuard } from '@nestjs/passport';
import { PrismaClient } from '@prisma/client'; // Import PrismaClient
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module'; // Import injection token
import { MachineScopes } from '../../core/constant/constants';
import { CommonUtils } from '../../shared/util/common.utils';
import { MemberStatus } from '../../dto/member';
import { describeAccess } from '../../shared/swagger/access-description.util';
import { setPaginationHeaders } from '../../shared/util/pagination.util';

// Helper function to map UserModel to UserResponseDto
/**
 * Maps a UserModel object to a UserResponseDto object.
 * @param user The UserModel object to map.
 * @returns The mapped UserResponseDto object, or null if user is undefined.
 */
function mapUserToDto(user: any): DTOs.UserResponseDto {
  if (!user) return null;
  const dto = new DTOs.UserResponseDto();
  dto.id = user.user_id.toString(); // Changed from Number(user.user_id)
  dto.handle = user.handle;
  dto.firstName = user.first_name;
  dto.lastName = user.last_name;
  dto.status = user.status;
  dto.email = user.primaryEmailAddress ?? user.email ?? undefined;

  const rawEmailStatus =
    user.primaryEmailStatusId ??
    user.primaryEmailStatus ??
    user.emailStatusId ??
    user.email_status_id ??
    null;

  if (rawEmailStatus !== null && rawEmailStatus !== undefined) {
    let statusId: number | undefined;
    if (
      typeof rawEmailStatus === 'object' &&
      typeof rawEmailStatus.toNumber === 'function'
    ) {
      const numericValue = rawEmailStatus.toNumber();
      statusId = Number.isNaN(numericValue) ? undefined : numericValue;
    } else {
      const numericValue = Number(rawEmailStatus);
      statusId = Number.isNaN(numericValue) ? undefined : numericValue;
    }

    if (statusId !== undefined) {
      dto.emailActive = statusId === Constants.verifiedEmailStatus;
      dto.emailVerified ??= dto.emailActive;
    }
  }

  if (dto.emailActive === undefined && typeof user.emailActive === 'boolean') {
    dto.emailActive = user.emailActive;
  }

  if (
    dto.emailVerified === undefined &&
    typeof user.emailVerified === 'boolean'
  ) {
    dto.emailVerified = user.emailVerified;
  }
  // Map other fields as needed from UserModel to UserResponseDto
  dto.createdAt = user.create_date?.toISOString();
  dto.modifiedAt = user.modify_date?.toISOString();
  // ... map other fields defined in UserResponseDto
  dto.emailActive = user.email_active;
  dto.status = user.status;
  dto.mfaEnabled = user.user_2fa?.mfa_enabled ?? false;
  dto.last_login = user.last_login?.toISOString();
  dto.regSource = user.reg_source;
  dto.utmSource = user.utm_source;
  dto.utmMedium = user.utm_medium;
  dto.utmCampaign = user.utm_campaign;
  dto.active = user.status == MemberStatus.ACTIVE;
  // dto.country = null, // FIXME where to map
  // dto.profile = null,
  // dto.profiles = null,

  // credential fields expected by platform-ui (activation code display)
  // Map activation_code from DB into response credential.activationCode
  // Keep undefined if not present
  const activationCode = user.activation_code ?? undefined;
  const hasPassword = typeof user.password === 'string' && user.password.length > 0;
  dto.credential = {
    activationCode,
    hasPassword,
  } as DTOs.UserCredentialDto;

  return dto;
}

/**
 * Retrieves the authenticated user from the request object.
 * @param req The Express Request object.
 * @returns The AuthenticatedUser object.
 * @throws UnauthorizedException if user is not authenticated.
 * @throws InternalServerErrorException if user object is incomplete.
 */
function getAuthenticatedUser(req: Request): AuthenticatedUser {
  const user: any = (req as any).authUser || (req as any).user;
  const logger = new Logger('getAuthenticatedUser'); // It's a global helper, so create a local logger.
  logger.debug(`[getAuthenticatedUser] User user: ${JSON.stringify(user, null, 5)}`);

  // Ensure admin detection accounts for both DB roles and JWT-embedded roles
  try {
    const adminRoleName = (process.env.ADMIN_ROLE_NAME || 'administrator').toLowerCase();
    const dbRoles: string[] = Array.isArray(user?.roles) ? user.roles : [];
    const jwtRoles: string[] =
      (user?.payload?.['https://topcoder-dev.com/roles'] as string[]) ||
      (user?.payload?.roles as string[]) ||
      [];

    const hasAdminInDb = dbRoles.some((r) => String(r).toLowerCase() === adminRoleName);
    const hasAdminInJwt = Array.isArray(jwtRoles)
      ? jwtRoles.some((r) => String(r).toLowerCase() === adminRoleName)
      : false;

    if (!user.isAdmin && (hasAdminInDb || hasAdminInJwt)) {
      user.isAdmin = true;
    }
  } catch (e) {
    logger.warn(`[getAuthenticatedUser] Failed to evaluate admin from roles: ${(e as Error).message}`);
  }

  logger.debug(
    `[getAuthenticatedUser] Attempting to get authenticated user. req.user present: ${!!user}`,
  );
  if (user) {
    logger.debug(
      `[getAuthenticatedUser] req.user content: ${JSON.stringify(user)}`,
    );
  } else {
    logger.warn(
      `[getAuthenticatedUser] req.user is NOT present. Headers: ${JSON.stringify(req.headers)}`,
    );
  }

  if (!user) {
    // This should ideally not happen if AuthGuard('jwt') is effective
    throw new UnauthorizedException(
      'User not authenticated or user context is missing.',
    );
  }

  // Basic check for essential properties. Adjust as per your AuthenticatedUser interface definition from jwt.strategy.ts
  // if user is machine, no userId, handle, or roles, should ignore the following
  /**
  if (!user.userId || !user.handle || !user.roles) {
    throw new InternalServerErrorException(
      'Authenticated user object is incomplete.',
    );
  }
  */
  if (user.isMachine && !user.scopes) {
    throw new InternalServerErrorException('Machine token is missing scopes');
  }
  return user;
}

@ApiTags('users')
@Controller('users')
@UseFilters(new ValidationExceptionFilter())
export class UserController {
  private readonly logger = new Logger(UserController.name);

  constructor(
    private readonly userService: UserService,
    private readonly userProfileService: UserProfileService,
    private readonly authFlowService: AuthFlowService,
    private readonly twoFactorAuthService: TwoFactorAuthService,
    private readonly validationService: ValidationService,
    private readonly roleService: RoleService,
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient, // Inject PrismaClient
  ) {}

  /**
   * Checks param existence in the request body.
   * @param obj The request body object.
   * @throws BadRequestException if param is missing.
   */
  private checkParam(obj: any) {
    if (!obj || !obj.param) {
      throw new BadRequestException('The request does not contain param data.');
    }
  }

  private checkAccess(
    user: AuthenticatedUser | undefined,
    isAdminRequired: boolean = false,
    allowedScopes?: string[],
  ) {
    if (!user) {
      this.logger.warn(
        `[UserController.checkAccess] User object is undefined. Throwing BadRequestException.`,
      );
      // bad request is returned instead of forbidden in java
      throw new BadRequestException('Authentication user is required');
    }
    // checking for machine goes first
    // if machine, scopes are required to be checked
    if (user.isMachine) {
      if (Array.isArray(allowedScopes) && allowedScopes.length > 0) {
        if (!user.scopes?.some((scope) => allowedScopes.includes(scope))) {
          throw new ForbiddenException(
            `Missing required scope(s): ${allowedScopes.join(', ')}`,
          );
        }
      }
    } else {
      if (isAdminRequired && !user.isAdmin) {
        throw new ForbiddenException(`Administrator access is required`);
      }
    }
  }

  private checkResourceIdAndAccess(
    user: AuthenticatedUser | undefined,
    isAdminRequired: boolean = false,
    resourceId: number | null | string,
    allowedScopes?: string[],
  ) {
    if (!user) {
      this.logger.warn(
        `[UserController.checkResourceIdAndAccess] User object is undefined. Throwing BadRequestException.`,
      );
      throw new BadRequestException('Authentication user is required');
    }
    // check resource id
    if (!resourceId || Number(resourceId) <= 0) {
      throw new BadRequestException(
        'resourceId is required and should be a positive value',
      );
    }
    // check if self, then should be fine (normalize both sides to string)
    if (String(resourceId) === String(user.userId)) {
      return;
    }
    this.checkAccess(user, isAdminRequired, allowedScopes);
  }

  // --- Public Endpoints (No Auth Required) ---

  /**
   * Generates a password reset token and sends it via email (simulated).
   * @param email The user's email address.
   * @param handle The user's handle.
   * @param resetPasswordUrlPrefix The base URL for the reset link.
   * @returns A message indicating the token was sent.
   * @throws BadRequestException if email or handle is missing.
   */
  @Get('resetToken')
  @ApiOperation({
    summary:
      'Generates a password reset token and sends it via email (Simulated)',
    description: describeAccess({
      summary:
        'Provides a reset token for password recovery workflows. Authentication is not required; the caller must supply an email or handle.',
      jwt: 'Not required (public endpoint).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiQuery({ name: 'email', required: false, type: String })
  @ApiQuery({ name: 'handle', required: false, type: String })
  @ApiQuery({
    name: 'resetPasswordUrlPrefix',
    required: false,
    type: String,
    description:
      'Base URL for the reset link, e.g., http://localhost:3001/reset?token=',
  })
  @ApiQuery({
    name: 'source',
    required: false,
    type: String,
    description: 'Where request came from',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Reset token sent (simulated)',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Email or handle is required, or invalid input',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Conflict.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getResetToken(
    @Query('email') email?: string,
    @Query('handle') handle?: string,
    @Query('resetPasswordUrlPrefix') resetPasswordUrlPrefix?: string,
    @Query('source') source?: string,
  ): Promise<{ message: string } | DTOs.UserResponseDto> {
    this.logger.log(
      `Initiating password reset request for email: ${email}, handle: ${handle}`,
    );
    if (!email && !handle) {
      throw new BadRequestException(
        'Either email or handle query param is required.',
      );
    }
    // other validations done in service layer
    const user = await this.authFlowService.initiatePasswordReset(
      email || handle,
      resetPasswordUrlPrefix,
      source,
    );
    if (user) {
      const userResponse = mapUserToDto(user);
      // add profiles
      const userId = Number(userResponse.id);
      let profiles = await this.userProfileService.findSocialProfiles(userId);
      if (!(Array.isArray(profiles) && profiles.length > 0)) {
        // try SSO profiles
        profiles =
          await this.userProfileService.findSSOUserLoginsByUserId(userId);
      }
      userResponse.profiles = profiles;
      return userResponse; // return user as in legacy java
    }
    return { message: 'Password reset token has been sent (simulated).' };
  }

  /**
   * Validates if a user handle is available.
   * @param handle The handle to validate.
   * @returns A ValidationResponseDto indicating if the handle is available.
   * @throws BadRequestException if handle is missing.
   */
  @Get('validateHandle')
  @ApiOperation({
    summary: 'Validate if a user handle is available',
    description: describeAccess({
      summary:
        'Checks whether the supplied handle is available for registration.',
      jwt: 'Not required (public endpoint).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiQuery({ name: 'handle', required: true, type: String })
  @ApiResponse({ status: HttpStatus.OK, type: DTOs.ValidationResponseDto })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Conflict.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async validateHandle(
    @Query('handle') handle: string,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(`Validating handle: ${handle}`);
    if (!handle) {
      throw new BadRequestException('Handle is required.');
    }
    return this.validationService.validateHandle(handle);
  }

  /**
   * Validates if an email address is available.
   * @param email The email address to validate.
   * @returns A ValidationResponseDto indicating if the email is available.
   * @throws BadRequestException if email is missing.
   */
  @Get('validateEmail')
  @ApiOperation({
    summary: 'Validate if an email address is available',
    description: describeAccess({
      summary: 'Determines whether an email can be used for a new member.',
      jwt: 'Not required (public endpoint).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiQuery({ name: 'email', required: true, type: String })
  @ApiResponse({ status: HttpStatus.OK, type: DTOs.ValidationResponseDto })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Conflict.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async validateEmail(
    @Query('email') email: string,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(`Validating email: ${email}`);
    if (!email) {
      throw new BadRequestException('Email query parameter is required.');
    }
    return this.validationService.validateEmail(email);
  }

  /**
   * Validates social provider and user ID availability.
   * @param socialUserId The user's ID within the social provider.
   * @param socialProvider The key of the social provider.
   * @returns A ValidationResponseDto indicating if the social ID is available.
   * @throws BadRequestException if socialUserId or socialProvider is missing.
   */
  @Get('validateSocial')
  @ApiOperation({
    summary: 'Validate social provider and user ID availability',
    description: describeAccess({
      summary:
        'Checks if a social provider identity (provider + user id) is already linked to a Topcoder account.',
      jwt: 'Not required (public endpoint).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiQuery({
    name: 'socialUserId',
    required: true,
    type: String,
    description: "The user's ID within the social provider.",
  })
  @ApiQuery({
    name: 'socialProvider',
    required: true,
    type: String,
    description:
      "Key of the social provider (e.g., 'google-oauth2', 'facebook').",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Validation result.',
    type: DTOs.ValidationResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input or unsupported provider.',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async validateSocial(
    @Query('socialUserId') socialUserId: string,
    @Query('socialProvider') socialProvider: string,
  ): Promise<DTOs.ValidationResponseDto> {
    // Interceptor will wrap this
    this.logger.log(
      `Request to validate social provider ${socialProvider} for user ID ${socialUserId}`,
    );

    if (!socialUserId || socialUserId.trim() === '') {
      throw new BadRequestException(
        '%s is required'.replace('%s', 'socialUserId'),
      );
    }
    if (!socialProvider || socialProvider.trim() === '') {
      throw new BadRequestException(
        '%s is required'.replace('%s', 'socialProvider'),
      );
    }

    // Service handles the core logic and specific error mapping for BadRequestException (unsupported provider)
    // and the boolean validation result.
    return this.validationService.validateSocial(socialProvider, socialUserId);
  }

  // --- Authenticated Endpoints ---

  /**
   * Finds users based on query parameters.
   * @param query The UserSearchQueryDto containing search parameters.
   * @param req The Express Request object.
   * @returns An array of UserResponseDto objects.
   * @throws ForbiddenException if the user is not an admin.
   */
  @Get()
  @UseGuards(AuthRequiredGuard)
  @ApiOperation({
    summary: 'Find users based on query parameters',
    description: describeAccess({
      summary:
        'Searches for users using legacy filter syntax, returning v3-compatible envelopes.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: 'Requires an M2M token with the `read:user` or `all:user` scope.',
    }),
  })
  @ApiQuery({
    name: 'selector',
    type: String,
    required: false,
    description: 'Comma-separated list of fields to include in the response',
  })
  @ApiQuery({
    name: 'filter',
    type: String,
    required: false,
    description: `Request query filter, e.g.: filter=field=value[,field=value].
      Supported filters: id, handle, firstName, lastName, email, status, regSource, utmSource, utmMedium, utmCampaign, active.
      Example: filter=active=true` ,
  })
  @ApiQuery({
    name: 'limit',
    type: Number,
    required: false,
    description: 'Limit. Default 20.',
  })
  @ApiQuery({
    name: 'offset',
    type: Number,
    required: false,
    description: 'Offset. Default 0.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of users found',
    type: [DTOs.UserResponseDto],
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
  async findUsers(
    @Query() query: DTOs.UserSearchQueryDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<DTOs.UserResponseDto[]> {
    // AuthZ: admin role or machine token with required scope(s)
    const authUser = getAuthenticatedUser(req);
    const allowedScopes = [
      ...MachineScopes.readScopes,
      SCOPES.READ_USER,
      SCOPES.ALL_USERS,
    ];
    this.checkAccess(authUser, true, allowedScopes);
    this.logger.debug(`[findUsers] auth user: ${JSON.stringify(authUser)}`);
    this.logger.log('Finding users with query:', query);
    const { users, total } = await this.userService.findUsers(query);
    const mappedUsers = users.map(mapUserToDto);
    // derive page/perPage from offset/limit and set headers
    const perPage = query.limit ?? Constants.defaultPageSize;
    const page = Math.floor((query.offset ?? 0) / perPage) + 1;
    setPaginationHeaders(res, req, total, page, perPage);
    if (query.selector && query.selector.trim().length > 0) {
      const keys = query.selector.split(',');
      return CommonUtils.pickArray(mappedUsers, keys) as DTOs.UserResponseDto[];
    }
    return mappedUsers;
  }

  /**
   * Gets a specific user by ID.
   * @param resourceId The ID of the user.
   * @param req The Express Request object.
   * @returns The UserResponseDto object for the found user.
   * @throws BadRequestException if the resourceId is invalid.
   * @throws NotFoundException if the user is not found.
   */
  @Get(':resourceId')
  @UseGuards(SelfOrAdminGuard)
  @SelfOrAdmin('resourceId')
  @ApiOperation({
    summary: 'Get a specific user by ID',
    description: describeAccess({
      summary:
        'Retrieves the user profile for the requested resource id, enforcing the legacy envelope structure.',
      jwt: 'Requires the `administrator` role or a JWT for the user being queried.',
      m2m: 'Not supported; use a member JWT.',
    }),
  })
  @ApiParam({ name: 'resourceId', type: Number })
  @ApiQuery({
    name: 'selector',
    type: String,
    required: false,
    description: 'Comma-separated list of fields to include in the response',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User found',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async findUserById(
    @Param('resourceId') resourceId: string,
    @Req() req: Request,
    @Query('selector') selector?: string, // Optional selector query param
  ): Promise<DTOs.UserResponseDto> {
    // AuthZ: self or admin
    const authUser = getAuthenticatedUser(req);
    const idNum = parseInt(resourceId, 10);
    if (isNaN(idNum)) {
      throw new BadRequestException('Invalid user ID format.');
    }
    this.checkResourceIdAndAccess(
      authUser,
      true,
      resourceId,
      MachineScopes.readScopes,
    );
    this.logger.log(`Finding user by ID: ${idNum}`);
    const user = await this.userService.findUserById(idNum);
    const mappedUser = mapUserToDto(user);
    if (selector && selector.trim().length > 0) {
      const keys = selector.split(',');
      return CommonUtils.pick(mappedUser, keys) as DTOs.UserResponseDto;
    }
    return mappedUser;
  }

  /**
   * Registers a new user.
   * @param createUserDto The DTO containing user creation data.
   * @returns The created UserResponseDto.
   */
  @Post()
  @UseGuards(AuthRequiredGuard, ScopesGuard)
  @Scopes('auth0')
  @ApiOperation({
    summary:
      'Register a new user (Placeholder - actual registration flow might be different)',
    description: describeAccess({
      summary:
        'Creates a new member record using the legacy param envelope. Requires authentication.',
      jwt: 'Requires a bearer token containing the `auth0` scope.',
      m2m: 'Requires an M2M token containing the `auth0` scope.',
    }),
  })
  @ApiBody({ type: DTOs.CreateUserBodyDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'User created',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Handle or email already exists',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.CREATED)
  async registerUser(
    @Body() createUserDto: DTOs.CreateUserBodyDto,
  ): Promise<DTOs.UserResponseDto> {
    this.checkParam(createUserDto);
    this.logger.log(`Registering new user: ${createUserDto.param.handle}`);
    const user = await this.userService.registerUser(createUserDto);
    return mapUserToDto(user);
  }

  /**
   * Updates basic user information.
   * @param resourceId The ID of the user to update.
   * @param updateUserDto The DTO containing update data.
   * @param req The request object.
   * @returns The updated UserResponseDto.
   */
  @Patch(':resourceId')
  @UseGuards(SelfOrAdminGuard)
  @SelfOrAdmin('resourceId')
  @ApiOperation({
    summary: 'Update basic user information',
    description: describeAccess({
      summary:
        'Updates core profile fields for the specified user using the legacy envelope payload.',
      jwt: 'Requires the `administrator` role or a JWT for the user being updated.',
      m2m: ['update:user_profiles', 'all:user_profiles'],
    }),
  })
  @ApiParam({ name: 'resourceId', type: Number })
  @ApiBody({ type: DTOs.UpdateUserBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User updated',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized.',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden.' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async updateBasicInfo(
    @Param('resourceId') resourceId: string,
    @Body() updateUserDto: DTOs.UpdateUserBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto> {
    // AuthZ: self or admin
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      resourceId,
      MachineScopes.updateScopes,
    );
    this.logger.log(`Updating user: ${resourceId}`);
    const user = await this.userService.updateBasicInfo(
      resourceId,
      updateUserDto,
    );
    return mapUserToDto(user);
  }

  /**
   * Deletes a user (not implemented).
   * @param resourceId The ID of the user to delete.
   * @param req The request object.
   * @throws NotImplementedException Always, as this endpoint is not implemented.
   */
  @Delete(':resourceId')
  @UseGuards(RolesGuard)
  @Roles(ADMIN_ROLE)
  @ApiOperation({
    summary: 'Delete a user - NOT IMPLEMENTED as per legacy system.',
    description: describeAccess({
      summary:
        'Reserved for parity with the legacy API. The operation is not implemented and always returns HTTP 501.',
      jwt: 'Would require a JWT with the `administrator` role.',
      m2m: 'Not supported.',
    }),
  })
  @ApiParam({
    name: 'resourceId',
    description: 'User ID to delete',
    type: String,
  })
  @ApiResponse({
    status: HttpStatus.NOT_IMPLEMENTED,
    description: 'This endpoint is not implemented.',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (Admin role required)',
  })
  @HttpCode(HttpStatus.NOT_IMPLEMENTED) // Set default status code
  async deleteUser(
    @Param('resourceId') resourceId: string,
    @Req() req: Request,
  ): Promise<void> {
    const authUser = getAuthenticatedUser(req);
    this.logger.warn(
      `Admin ${authUser.userId} attempted to access DELETE /users/${resourceId}, which is not implemented.`,
    );
    return Promise.reject(new NotImplementedException('Not Implemented'));
  }

  // --- SSO Login Endpoints ---

  /**
   * Links an SSO profile to a user (admin only).
   * @param userId The ID of the user to link the SSO profile to.
   * @param createSSODto The DTO containing SSO creation data.
   * @param req The request object.
   * @returns The UserProfileDto for the updated user.
   */
  @Post(':userId/SSOUserLogin')
  @UseGuards(RolesGuard)
  @Roles(ADMIN_ROLE)
  @ApiOperation({
    summary: 'Link an SSO profile to a user (Admin only).',
    description: describeAccess({
      summary:
        'Creates or links an SSO identity (provider + user id) to the specified user.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: 'Not supported; use an administrator JWT.',
    }),
  })
  @ApiParam({
    name: 'userId',
    description: 'Numeric User ID to link the SSO profile to',
    type: Number,
  })
  @ApiBody({ type: DTOs.CreateUpdateSSOBodyDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'SSO profile linked successfully',
    type: DTOs.UserProfileDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input or missing provider/providerUserId',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden' })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User or SSO Provider not found',
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'SSO profile already linked',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async createSSOUserLogin(
    @Param('userId', ParseIntPipe) userId: number,
    @Body() createSSODto: DTOs.CreateUpdateSSOBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      userId,
      MachineScopes.createScopes,
    );
    this.logger.log(
      `Admin ${authUser.userId} creating SSO login for user: ${userId}, provider: ${createSSODto.param?.provider}`,
    );
    this.checkParam(createSSODto);
    return this.userProfileService.createSSOUserLogin(
      userId,
      createSSODto.param,
    );
  }

  /**
   * Updates an existing SSO profile linked to a user (admin only).
   * @param userId The ID of the user whose SSO profile is being updated.
   * @param updateSSODto The DTO containing SSO update data.
   * @param req The request object.
   * @returns The UserProfileDto for the updated user.
   */
  @Put(':userId/SSOUserLogin') // Using provider and ssoUserId from body to identify the record
  @UseGuards(SelfOrAdminGuard)
  @SelfOrAdmin('userId')
  @ApiOperation({
    summary: 'Update an existing SSO profile linked to a user (Admin only).',
    description: describeAccess({
      summary:
        'Updates metadata for an existing SSO identity associated with a user.',
      jwt: 'Requires the `administrator` role or a JWT for the user owning the SSO link.',
      m2m: ['update:user_profiles', 'all:user_profiles'],
    }),
  })
  @ApiParam({
    name: 'userId',
    description: 'Numeric User ID whose SSO profile is being updated',
    type: Number,
  })
  @ApiBody({
    type: DTOs.CreateUpdateSSOBodyDto,
    description:
      'The provider and userId in the DTO identify the link. Other fields are updated.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'SSO profile updated successfully',
    type: DTOs.UserProfileDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input or missing provider/providerUserId',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (Admin role required)',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User, SSO Provider, or specific SSO link not found',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async updateSSOUserLogin(
    @Param('userId', ParseIntPipe) userId: number,
    @Body() updateSSODto: DTOs.CreateUpdateSSOBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      userId,
      MachineScopes.updateScopes,
    );
    this.logger.log(
      `User ${authUser.userId} updating SSO login for user: ${userId}, provider: ${updateSSODto.param.provider}`,
    );

    // Check if user for whom SSO login is being updated exists
    const targetUser = await this.userService.findUserById(userId);
    if (!targetUser) {
      throw new NotFoundException(`User with ID ${userId} not found.`);
    }

    return this.userProfileService.updateSSOUserLogin(
      userId,
      updateSSODto.param,
    );
  }

  /**
   * Deletes an SSO login link for a user.
   * @param userId The ID of the user.
   * @param query The query parameters containing SSO details.
   * @param req The request object.
   */
  @Delete(':userId/SSOUserLogin')
  @UseGuards(SelfOrAdminGuard)
  @SelfOrAdmin('userId')
  @ApiOperation({
    summary: 'Delete an SSO login link for a user',
    description: describeAccess({
      summary:
        'Removes an existing SSO link for the specified user and provider.',
      jwt: 'Requires the `administrator` role or a JWT for the user owning the SSO link.',
      m2m: ['delete:user_profiles', 'all:user_profiles'],
    }),
  })
  @ApiParam({
    name: 'userId',
    type: Number,
    description: 'The Topcoder User ID',
  })
  @ApiQuery({
    name: 'provider',
    type: String,
    required: false,
    description: 'SSO Provider Name (e.g., okta-customer)',
  })
  @ApiQuery({
    name: 'providerId',
    type: Number,
    required: false,
    description: 'SSO Provider Numeric ID',
  })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
    description: 'SSO login link deleted successfully',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Missing required parameters or provider not found',
  })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden' })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User or SSO link not found',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteSSOUserLogin(
    @Param('userId', ParseIntPipe) userId: number,
    @Query() query: DTOs.DeleteSSOUserLoginQueryDto, // Use the new DTO
    @Req() req: Request,
  ): Promise<void> {
    this.logger.log(
      `[deleteSSOUserLogin] Received request to delete SSO login for user ID: ${userId}. Query: ${JSON.stringify(query)}. Headers: ${JSON.stringify(req.headers)}`,
    );
    const authUser = getAuthenticatedUser(req);
    this.logger.debug(
      `[deleteSSOUserLogin] Authenticated user from getAuthenticatedUser: ${JSON.stringify(authUser)}`,
    );
    // Allow self or admin to delete (consistent with decorator SelfOrAdmin)
    this.checkResourceIdAndAccess(
      authUser,
      true,
      userId,
      MachineScopes.deleteScopes,
    );

    const { provider: providerName } = query;
    let providerId = query.providerId;

    // validate parameters
    if (userId <= 0) {
      throw new BadRequestException(`userId should be positive: ${userId}`);
    }
    if (!providerName && !providerId) {
      throw new BadRequestException(
        'One of provider and providerId should be provided',
      );
    }
    if (!providerId && !CommonUtils.validateString(providerName)) {
      throw new BadRequestException('The provider should be non-empty string');
    }

    this.logger.log(
      `User ${authUser.userId} deleting SSO login for user: ${userId}, providerNameQuery: ${providerName}, providerId: ${providerId}`,
    );

    // check if provider is supplied and not providerId
    if (providerName && !providerId) {
      const selProviderId =
        await this.userProfileService.findProviderIdByName(providerName);
      if (!selProviderId) {
        throw new BadRequestException(
          `The provider id not found for the provider: ${providerName}`,
        );
      }
      providerId = selProviderId;
    }
    // at this point, providerId should have a value if it is initially null
    // validate if userId and providerId exists
    const count =
      await this.userProfileService.countLoginsByProviderIdAndUserId(
        providerId,
        userId,
      );
    if (count == 0) {
      if (providerName) {
        throw new NotFoundException(
          `The user and provider do not exist, userId: ${userId}, provider: ${providerName}`,
        );
      } else {
        throw new NotFoundException(
          `The user and provider do not exist, userId: ${userId}, providerId: ${providerId}`,
        );
      }
    }
    await this.userProfileService.deleteSSOUserLogin(userId, providerId);
  }

  /**
   * Retrieves all SSO profiles linked to a user. Accessible only by admins.
   *
   * @param userId - The numeric ID of the user.
   * @param req - The request object containing authentication information.
   * @returns A list of UserProfileDto objects representing the user's SSO profiles.
   * @throws UnauthorizedException if the user is not authenticated.
   * @throws ForbiddenException if the user is not an admin.
   * @throws NotFoundException if the user is not found.
   */
  @Get(':userId/SSOUserLogins')
  @UseGuards(RolesGuard)
  @Roles(ADMIN_ROLE)
  @ApiOperation({
    summary: 'Get all SSO profiles linked to a user (Admin only).',
    description: describeAccess({
      summary:
        'Lists all SSO identities associated with the specified user.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: 'Not supported; use an administrator JWT.',
    }),
  })
  @ApiParam({ name: 'userId', description: 'Numeric User ID', type: Number })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of linked SSO profiles',
    type: [DTOs.UserProfileDto],
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (Admin role required)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getSSOUserLogins(
    @Param('userId', ParseIntPipe) userId: number,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto[]> {
    const authUser = getAuthenticatedUser(req);
    this.checkAccess(authUser, true, MachineScopes.readScopes);
    this.logger.log(
      `Admin ${authUser.userId} getting SSO logins for user: ${userId}`,
    );
    return this.userProfileService.findSSOUserLoginsByUserId(userId);
  }

  // --- External Profiles (e.g. Topcoder, GitHub, etc. - Generic handling) ---
  /**
   * Adds an external profile (e.g., social media account) to a user. Accessible only by admins.
   *
   * @param resourceId - The numeric ID of the user.
   * @param createProfileDto - Data transfer object containing profile details.
   * @param req - The request object containing authentication information.
   * @returns The created UserProfileDto object.
   * @throws BadRequestException if the profile data is invalid or missing.
   * @throws UnauthorizedException if the user is not authenticated.
   * @throws ForbiddenException if the user is not an admin.
   * @throws NotFoundException if the user is not found.
   * @throws ConflictException if the profile already exists for the user.
   */
  @Post(':resourceId/profiles')
  @UseGuards(RolesGuard)
  @Roles(ADMIN_ROLE)
  @ApiOperation({
    summary: 'Add an external profile (social, etc.) to a user (Admin only).',
    description: describeAccess({
      summary:
        'Creates a new external profile entry (e.g., social account) for the specified user.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: 'Not supported; use an administrator JWT.',
    }),
  })
  @ApiParam({
    name: 'resourceId',
    description: 'Numeric User ID',
    type: Number,
  })
  @ApiBody({
    type: DTOs.CreateProfileBodyDto,
    description:
      'Profile data, including provider and provider-specific userId',
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'External profile added successfully',
    type: DTOs.UserProfileDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Profile already exists for this provider/user',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.CREATED)
  async addExternalProfile(
    @Param('resourceId', ParseIntPipe) resourceId: number,
    @Body() createProfileDto: DTOs.CreateProfileBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      resourceId,
      MachineScopes.createScopes,
    );
    this.logger.log(
      `Admin ${authUser.userId} adding profile for user: ${resourceId}, provider: ${createProfileDto.param?.provider}`,
    );
    if (!createProfileDto.param) {
      throw new BadRequestException('The request does not contain param data');
    }
    // validate complete profile (when validation fails, it throws BadRequestException)
    await this.validationService.validateProfile(
      createProfileDto.param,
      resourceId,
    );
    // other validations done in userprofile service layer
    return this.userProfileService.addExternalProfile(
      resourceId,
      createProfileDto.param,
    );
  }

  /**
   * Retrieves all external profiles for a user. Accessible by the user (self) or admins.
   *
   * @param resourceId - The numeric ID of the user whose profiles to retrieve.
   * @param req - The request object containing authentication information.
   * @returns A list of UserProfileDto objects.
   */
  @Get(':resourceId/profiles')
  @ApiOperation({
    summary: 'Get all external profiles for a user.',
    description: describeAccess({
      summary: 'Lists the external profiles associated with the specified user.',
      jwt: 'Requires the `administrator` role or a JWT for the user being queried.',
      m2m: ['read:user_profiles', 'all:user_profiles'],
    }),
  })
  @ApiParam({
    name: 'resourceId',
    description: 'Numeric User ID',
    type: Number,
  })
  @ApiResponse({ status: HttpStatus.OK, type: [DTOs.UserProfileDto] })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  async getAllExternalProfiles(
    @Param('resourceId', ParseIntPipe) resourceId: number,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto[]> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      resourceId,
      MachineScopes.readScopes,
    );
    this.logger.log(
      `User ${authUser.userId} fetching external profiles for user: ${resourceId}`,
    );
    return this.userProfileService.findAllUserProfiles(resourceId);
  }

  /**
   * Deletes all external profiles for a user under a specific provider. Accessible only by admins.
   *
   * @param resourceId - The numeric ID of the user.
   * @param providerName - The name of the external profile provider (e.g., 'github', 'topcoder').
   * @param req - The request object containing authentication information.
   * @throws UnauthorizedException if the user is not authenticated.
   * @throws ForbiddenException if the user is not an admin.
   * @throws NotFoundException if the user or profile is not found.
   */
  @Delete(':resourceId/profiles/:providerName')
  @UseGuards(RolesGuard)
  @Roles(ADMIN_ROLE)
  @ApiOperation({
    summary:
      'Delete all external profiles for a user under a specific provider (Admin only).',
    description: describeAccess({
      summary:
        'Removes the external profiles for the supplied provider from the target user.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: 'Not supported; use an administrator JWT.',
    }),
  })
  @ApiParam({
    name: 'resourceId',
    description: 'Numeric User ID of the user',
    type: Number,
  })
  @ApiParam({
    name: 'providerName',
    description:
      'Name of the external profile provider (e.g., github, topcoder)',
  })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
    description: 'External profiles for the provider deleted successfully',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden' })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User or profile not found',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteExternalProfile(
    @Param('resourceId', ParseIntPipe) resourceId: number,
    @Param('providerName') providerName: string,
    @Req() req: Request,
  ): Promise<void> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      resourceId,
      MachineScopes.deleteScopes,
    );
    this.logger.log(
      `Admin ${authUser.userId} deleting profiles for user: ${resourceId}, provider: ${providerName}`,
    );
    await this.userProfileService.deleteExternalProfile(
      resourceId,
      providerName,
    );
  }

  // --- Authentication/Session Related (Mostly for Auth0 Custom DB/Rules/Actions) ---

  /**
   * Authenticates a user for Auth0's Custom Database script.
   *
   * @param loginData - An object containing handle/email and password for authentication.
   * @returns Authentication response data (structure depends on Auth0 requirements).
   * @throws BadRequestException if handle/email or password is missing.
   * @throws UnauthorizedException if credentials are invalid.
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Authenticate user for Auth0 Custom Database script.',
    description: describeAccess({
      summary:
        'Validates credentials for Auth0 Custom DB login flows. Intended for Auth0 to call without a bearer token.',
      jwt: 'Not required (used by Auth0).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiConsumes('application/x-www-form-urlencoded')
  @ApiBody({
    description: 'Form data: handleOrEmail, password',
    schema: {
      type: 'object',
      properties: {
        handleOrEmail: { type: 'string' },
        password: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description:
      'User authenticated' /* type: Auth0CustomDbUserDto - define if needed */,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Missing parameters',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid credentials',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async auth0Login(
    @Body() loginData: { handleOrEmail?: string; password?: string },
  ): Promise<any> {
    this.logger.log(
      `Auth0 Custom DB Login attempt: ${loginData?.handleOrEmail}`,
    );
    if (!loginData?.handleOrEmail || !loginData?.password) {
      throw new BadRequestException('handleOrEmail and password are required.');
    }
    return this.authFlowService.authenticateForAuth0(
      loginData.handleOrEmail,
      loginData.password,
    );
  }

  /**
   * Retrieves user profile and roles for Auth0 Rules/Actions.
   *
   * @param rolesData - An object containing either email or handle to identify the user.
   * @returns User profile and role data formatted for Auth0.
   * @throws BadRequestException if both email and handle are missing.
   * @throws NotFoundException if the user is not found.
   */
  @Post('roles')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get user profile and roles for Auth0 Rules/Actions.',
    description: describeAccess({
      summary:
        'Returns a simplified profile/role payload used by Auth0 Rules and Actions. Intended for server-to-server calls without a bearer token.',
      jwt: 'Not required (used by Auth0).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiConsumes('application/x-www-form-urlencoded')
  @ApiBody({
    description: 'Form data: email, handle',
    schema: {
      type: 'object',
      properties: { email: { type: 'string' }, handle: { type: 'string' } },
    },
  })
  @ApiResponse({ status: HttpStatus.OK, description: 'User profile and roles' })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Missing email or handle',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async auth0Roles(
    @Body() rolesData: { email?: string; handle?: string },
  ): Promise<any> {
    this.logger.log(
      `Auth0 Roles request: ${rolesData?.email || rolesData?.handle}`,
    );
    const key = rolesData.email || rolesData.handle;
    if (!key) {
      throw new BadRequestException('Either email or handle is required.');
    }
    return this.authFlowService.getUserProfileForAuth0(key);
  }

  /**
   * Handles password changes initiated by Auth0's post-password-reset flow.
   *
   * @param changePasswordData - An object containing email and new password.
   * @returns A success message indicating the password was changed.
   * @throws BadRequestException if email or new password is missing or invalid.
   * @throws ForbiddenException if password change is not allowed (e.g., SSO user).
   * @throws NotFoundException if the user is not found.
   */
  @Post('changePassword')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'Change password for Auth0 Action (typically called by Auth0 post-password-reset flow).',
    description: describeAccess({
      summary:
        'Allows Auth0 post-password-reset flows to set a new password for a member.',
      jwt: 'Not required (used by Auth0).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiConsumes('application/x-www-form-urlencoded')
  @ApiBody({
    description: 'Form data: email, password (new)',
    schema: {
      type: 'object',
      properties: { email: { type: 'string' }, password: { type: 'string' } },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Password changed successfully',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Missing parameters or invalid password',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Password change not allowed (e.g., SSO user)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async auth0ChangePassword(
    @Body() changePasswordData: { email?: string; password?: string },
  ): Promise<{ message: string }> {
    this.logger.log(
      `Auth0 Change Password request: ${changePasswordData?.email}`,
    );
    if (!changePasswordData?.email || !changePasswordData?.password) {
      throw new BadRequestException('Email and new password are required.');
    }
    return this.authFlowService.changePasswordFromAuth0(
      changePasswordData.email,
      changePasswordData.password,
    );
  }

  // --- Password/Activation Flows (Public) ---

  /**
   * Activates a new user account using the provided OTP (One-Time Password) and resend token.
   * This endpoint is part of the user registration flow, verifying the user's identity
   * and enabling their account for access.
   *
   * @param activateUserDto - Data transfer object containing activation parameters:
   *                          - userId: The unique identifier of the user to activate.
   *                          - otp: The one-time password sent to the user's email/mobile.
   *                          - resendToken: A token generated during initial registration
   *                                         to authorize activation attempts.
   *
   * @returns A UserResponseDto containing the activated user's details upon success.
   *
   * @throws BadRequestException If the provided input is invalid (e.g., missing fields).
   * @throws ForbiddenException If the resend token is invalid or mismatched.
   * @throws NotFoundException If the specified user is not found in the system.
   * @throws GoneException If the OTP or resend token has expired.
   */
  @Put('activate')
  @ApiOperation({
    summary: 'Activate a new user account using OTP and a resend token.',
    description: describeAccess({
      summary:
        'Activates a pending user by validating an OTP and resend token issued during registration.',
      jwt: 'Not required (public endpoint).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiBody({ type: DTOs.ActivateUserBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User activated successfully',
    type: DTOs.UserResponseDto,
  }) // Assuming it returns the user
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input, OTP, or token',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (e.g., token mismatch)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({ status: HttpStatus.GONE, description: 'Token or OTP expired' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async activateUser(
    @Body() activateUserDto: DTOs.ActivateUserBodyDto,
  ): Promise<DTOs.UserResponseDto> {
    this.checkParam(activateUserDto);
    this.logger.log(
      `Attempting to activate user: ${activateUserDto.param.userId}`,
    );
    // other validations in activateUser()
    const activatedUser =
      await this.authFlowService.activateUser(activateUserDto);
    // Ensure mapUserToDto can handle the potentially different structure returned by activateUser
    // or that activateUser returns a structure compatible with UserModel for mapUserToDto
    if (!activatedUser || typeof activatedUser.message === 'string') {
      // Handle cases where it might return a message object
      // If it's a message like "already active", we might not have a full user model to map.
      // For now, assuming successful activation returns a user model compatible object.
      // Consider throwing an exception or returning a different DTO for non-user responses.
      if (activatedUser && activatedUser.user)
        return mapUserToDto(activatedUser.user); // If it's {message, user}
      throw new BadRequestException(
        activatedUser?.message || 'Activation did not return a user object.',
      );
    }
    return mapUserToDto(activatedUser);
  }

  /**
   * Resends the activation email/OTP to a user's registered email address using a valid resend token.
   * This endpoint allows users who did not receive the initial activation email to request a new one,
   * provided they have a valid, unexpired resend token.
   *
   * @param resendActivationDto - Data transfer object containing:
   *                              - userId: The ID of the user awaiting activation.
   *                              - resendToken: A token authorizing the resend request,
   *                                             typically generated during registration.
   *
   * @returns A success message indicating the email was resent.
   *
   * @throws BadRequestException If the input is invalid (e.g., missing userId or token).
   * @throws ForbiddenException If the resend token is invalid or mismatched.
   * @throws NotFoundException If the user associated with the ID is not found.
   * @throws GoneException If the resend token has expired.
   */
  @Post('resendActivationEmail')
  @ApiOperation({
    summary: 'Resend activation email/OTP using a resend token.',
    description: describeAccess({
      summary:
        'Triggers another activation email/OTP for a pending user when provided a valid resend token.',
      jwt: 'Not required (public endpoint).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiBody({ type: DTOs.UserOtpDto }) // UserOtpDto contains userId and resendToken for this flow
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Activation email resent successfully',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input or token',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (e.g., token mismatch)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({ status: HttpStatus.GONE, description: 'Token expired' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async resendActivationEmail(
    @Body() resendActivationDto: DTOs.ActivateUserBodyDto,
  ): Promise<{ message: string }> {
    this.checkParam(resendActivationDto);
    this.logger.log(
      `Attempting to resend activation email for user: ${resendActivationDto.param.userId}`,
    );
    return this.authFlowService.requestResendActivation(
      resendActivationDto.param,
    );
  }

  // --- Profile Updates (Require Auth) ---

  /**
   * Updates a user's handle (username) in the system. This endpoint is restricted to administrators
   * due to the sensitive nature of handle changes, which may impact user authentication and references.
   *
   * @param resourceId - The ID of the user whose handle is to be updated.
   * @param updateHandleDto - Data transfer object containing the new handle:
   *                          - handle: The desired new handle for the user.
   * @param req - The HTTP request containing authentication details of the administrator.
   *
   * @returns A UserResponseDto reflecting the updated user profile with the new handle.
   *
   * @throws BadRequestException If the new handle is missing or invalid.
   * @throws UnauthorizedException If the request lacks valid authentication.
   * @throws ForbiddenException If the requester is not an administrator.
   * @throws NotFoundException If the target user is not found.
   * @throws ConflictException If the new handle is already in use by another user.
   */
  @Patch(':resourceId/handle')
  @UseGuards(RolesGuard)
  @Roles(ADMIN_ROLE)
  @ApiOperation({
    summary: 'Update user handle (Admin only).',
    description: describeAccess({
      summary:
        'Changes the handle for a user and triggers related downstream updates.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: 'Not supported; use an administrator JWT.',
    }),
  })
  @ApiParam({ name: 'resourceId', description: 'User ID' })
  @ApiBody({ type: DTOs.UpdateHandleBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Handle updated',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input or handle format',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (Admin role required)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Handle already exists',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async updateHandle(
    @Param('resourceId') resourceId: string,
    @Body() updateHandleDto: DTOs.UpdateHandleBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      parseInt(resourceId),
      MachineScopes.updateScopes,
    );
    this.logger.log(
      `Admin ${authUser.userId} attempting to update handle for user ${resourceId}`,
    );
    if (!updateHandleDto.param?.handle) {
      throw new BadRequestException('Handle parameter is required.');
    }
    const updatedUser = await this.userService.updateHandle(
      resourceId,
      updateHandleDto.param.handle,
      authUser,
    );
    return mapUserToDto(updatedUser);
  }

  /**
   * Updates a user's primary email address in the system. This endpoint is restricted to administrators
   * and initiates the email verification process for the new address. The updated email is marked as
   * unverified until the user confirms it via the verification link sent to the new address.
   *
   * @param resourceId - The ID of the user whose email is to be updated.
   * @param updateEmailDto - Data transfer object containing the new email:
   *                         - email: The desired new primary email address.
   * @param req - The HTTP request containing authentication details of the administrator.
   *
   * @returns A UserResponseDto reflecting the updated user profile with the new email.
   *
   * @throws BadRequestException If the new email is missing, invalid, or malformed.
   * @throws UnauthorizedException If the request lacks valid authentication.
   * @throws ForbiddenException If the requester is not an administrator.
   * @throws NotFoundException If the target user is not found.
   * @throws ConflictException If the new email is already registered to another account.
   */
  @Patch(':resourceId/email')
  @UseGuards(RolesGuard)
  @Roles(ADMIN_ROLE)
  @ApiOperation({
    summary:
      'Update user primary email (Admin only). This will set the new email to unverified and trigger verification.',
    description: describeAccess({
      summary:
        'Changes the primary email for a user and sends verification to the new address.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: 'Not supported; use an administrator JWT.',
    }),
  })
  @ApiParam({ name: 'resourceId', description: 'User ID' })
  @ApiBody({ type: DTOs.UpdateEmailBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Primary email update process initiated',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input or email format',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (Admin role required)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Email already in use by another account',
  })
  async updatePrimaryEmail(
    @Param('resourceId', ParseIntPipe) resourceId: number,
    @Body() updateEmailDto: DTOs.UpdateEmailBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      resourceId,
      MachineScopes.updateScopes,
    );
    this.logger.log(
      `Admin ${authUser.userId} attempting to update primary email for user ${resourceId}`,
    );
    this.checkParam(updateEmailDto);
    if (!updateEmailDto.param.email) {
      // other validations for email done in updatePrimaryEmail()
      throw new BadRequestException('email parameter is required.');
    }
    const updatedUser = await this.userService.updatePrimaryEmail(
      resourceId + '',
      updateEmailDto.param.email,
      authUser,
    );
    return mapUserToDto(updatedUser);
  }

  /**
   * Generates a one-time token for sensitive operations like email updates.
   * This token serves as an additional security layer, requiring the user to authenticate
   * with their password before performing actions that affect critical account information.
   *
   * @param tokenData - An object containing:
   *                  - userId: The ID of the user requesting the token.
   *                  - password: The user's current password for authentication.
   *
   * @returns A OneTimeTokenResponseDto containing the generated token and its expiration details.
   *
   * @throws BadRequestException If userId or password is missing.
   * @throws UnauthorizedException If the provided credentials are invalid.
   * @throws ForbiddenException If the user account is inactive or disabled.
   * @throws NotFoundException If the specified user does not exist.
   */
  @Post('oneTimeToken') // Form data expected as per Java UserResource
  @ApiOperation({
    summary:
      'Request a one-time token for email update, requires user credentials.',
    description: describeAccess({
      summary:
        'Generates a one-time token after validating the member password. Designed for client-side flows; no bearer token is required.',
      jwt: 'Not required; the endpoint uses submitted credentials.',
      m2m: 'Not applicable.',
    }),
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: { userId: { type: 'string' }, password: { type: 'string' } },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'One-time token generated',
    type: DTOs.OneTimeTokenResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Missing userId or password',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid credentials',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'User account not active',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getOneTimeToken(
    @Body() tokenData: { userId: string; password?: string },
  ): Promise<DTOs.OneTimeTokenResponseDto> {
    this.logger.log(
      `Requesting one-time token for user ID: ${tokenData?.userId}`,
    );
    if (!tokenData?.userId || !tokenData?.password) {
      throw new BadRequestException('Both userId and password are required.');
    }
    const token = await this.authFlowService.generateOneTimeToken(
      tokenData.userId,
      tokenData.password,
    );
    return { token };
  }

  /**
   * This endpoint is used to update email of a specified user (only) in the
   * registration flow.
   * A bearer token is needed in Authorization header, which is created by
   * getOneTimeToken().
   *  Updates a user's primary email address using a one-time token for authentication.
   * This endpoint is part of a two-step verification process, allowing users to change
   * their email after successfully obtaining a one-time token via `getOneTimeToken()`.
   *
   * @param resourceId - The ID of the user whose email is being updated.
   * @param email - The new email address to set for the user.
   * @param req - The HTTP request containing the one-time token in the Authorization header.
   *
   * @returns A success message confirming the email update.
   *
   * @throws BadRequestException If the email format is invalid or the token is malformed.
   * @throws UnauthorizedException If the token is missing or invalid.
   * @throws ForbiddenException If the token is expired, already used, or mismatched.
   * @throws NotFoundException If the user is not found.
   * @throws ConflictException If the new email is already associated with another account.
   */
  @Post(':resourceId/email/:email')
  @ApiOperation({
    summary: 'Update user primary email using a one-time token.',
    description: describeAccess({
      summary:
        'Consumes a one-time token generated via `oneTimeToken` to update the user\'s primary email.',
      jwt: 'Not supported; supply the one-time token in the Authorization header instead.',
      m2m: 'Not applicable.',
    }),
  })
  @ApiParam({ name: 'resourceId', type: 'string', description: 'User ID' })
  @ApiParam({ name: 'email', type: 'string', description: 'New email address' })
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer token (the one-time token)',
    required: true,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Email updated successfully',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input or token format',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'One-time token missing or invalid',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Token subject mismatch or already used',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'New email already in use by another account',
  })
  @ApiResponse({
    status: HttpStatus.GONE,
    description: 'One-time token expired',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.OK) // Changed from previous 204 to allow message body
  async updateEmailWithOneTimeToken(
    @Param('resourceId') resourceId: string,
    @Param('email') email: string,
    @Req() req: Request,
  ): Promise<{ message: string }> {
    this.logger.log(
      `Updating email for user ${resourceId} to ${email} using one-time token.`,
    );
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
      throw new UnauthorizedException(
        'Bearer one-time token is required in Authorization header.',
      );
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
      throw new UnauthorizedException('One-time token is missing.');
    }
    await this.authFlowService.updateEmailWithOneTimeToken(
      resourceId,
      email,
      token,
    );
    return { message: 'Email updated successfully.' };
  }

  /**
   * Updates the status of a user account. This endpoint is restricted to administrators.
   *
   * @param resourceId - The ID of the user whose status is to be updated.
   * @param updateStatusDto - Data transfer object containing the new status.
   * @param req - The request object containing authentication information.
   * @returns A UserResponseDto reflecting the updated user profile with the new status.
   * @throws BadRequestException If the status parameter is missing or invalid.
   * @throws UnauthorizedException If the request lacks valid authentication.
   * @throws ForbiddenException If the requester is not an administrator.
   * @throws NotFoundException If the target user is not found.
   */
  @Patch(':resourceId/status')
  @UseGuards(RolesGuard)
  @Roles(ADMIN_ROLE)
  @ApiOperation({
    summary: 'Update user status (Admin only).',
    description: describeAccess({
      summary: 'Changes the activation status for the specified user.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: 'Not supported; use an administrator JWT.',
    }),
  })
  @ApiParam({ name: 'resourceId', description: 'User ID' })
  @ApiBody({ type: DTOs.UpdateStatusBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Status updated',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid status code',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (Admin role required)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async updateStatus(
    @Param('resourceId', ParseIntPipe) resourceId: number,
    @Query('comment') comment: string,
    @Body() updateStatusDto: DTOs.UpdateStatusBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      resourceId,
      MachineScopes.updateScopes,
    );
    this.logger.log(
      `Admin ${authUser.userId} attempting to update status for user ${resourceId}`,
    );
    this.checkParam(updateStatusDto);
    if (!updateStatusDto.param.status) {
      throw new BadRequestException('Status parameter is required.');
    }
    // other validations done ins updateStatus()
    const updatedUser = await this.userService.updateStatus(
      resourceId + '',
      updateStatusDto.param.status,
      authUser,
      comment,
    );
    return mapUserToDto(updatedUser);
  }

  // --- Roles ---

  /**
   * Updates the primary role for the currently authenticated user.
   * This endpoint allows users to set their primary role from their existing roles.
   *
   * @param req - The request object containing authentication information.
   * @param updatePrimaryRoleDto - Data transfer object containing the new primary role.
   * @returns A success message indicating the primary role was updated.
   * @throws BadRequestException If the primary role name is missing or invalid.
   * @throws UnauthorizedException If the request lacks valid authentication.
   * @throws ForbiddenException If the role is not assignable or not owned by the user.
   * @throws NotFoundException If the specified role is not found.
   */
  @Post('updatePrimaryRole')
  @UseGuards(AuthRequiredGuard)
  @ApiOperation({
    summary: 'Update the primary role for the authenticated user (Self only).',
    description: describeAccess({
      summary:
        'Sets which of the caller\'s roles is marked as primary. Only the user themselves may invoke it.',
      jwt: 'Requires a JWT for the member making the request.',
      m2m: 'Not supported.',
    }),
  })
  @ApiBody({ type: DTOs.UpdatePrimaryRoleBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Primary role updated successfully.',
    schema: { type: 'object', properties: { message: { type: 'string' } } },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input or role name.',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (e.g., role not assignable or not owned by user)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Role not found.' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async updatePrimaryRole(
    @Req() req: Request,
    @Body() updatePrimaryRoleDto: DTOs.UpdatePrimaryRoleBodyDto,
  ): Promise<{ message: string }> {
    const authUser = getAuthenticatedUser(req);
    // Permission check is implicitly self-service here as it uses authUser.userId
    this.logger.log(
      `User ${authUser.userId} attempting to update primary role to: ${updatePrimaryRoleDto.param?.primaryRole}`,
    );
    if (!updatePrimaryRoleDto.param?.primaryRole) {
      throw new BadRequestException('Primary role name is required in param.');
    }
    await this.userService.updatePrimaryRole(
      parseInt(authUser.userId, 10),
      updatePrimaryRoleDto.param.primaryRole,
      parseInt(authUser.userId, 10),
    );
    return { message: 'Primary role updated successfully.' };
  }

  // --- 2FA / DICE Endpoints ---

  /**
   * Retrieves the 2FA (Two-Factor Authentication) status for a user, including MFA and DICE settings.
   * Accessible by the user themselves or administrators.
   *
   * @param resourceId - The ID of the user whose 2FA status is being retrieved.
   * @param req - The request object containing authentication information.
   * @returns A User2faDto containing the user's 2FA configuration and status.
   * @throws BadRequestException If the request parameters are invalid.
   * @throws UnauthorizedException If the request lacks valid authentication.
   * @throws ForbiddenException If the requester is not authorized to access the information.
   */
  @Get(':resourceId/2fa')
  @UseGuards(SelfOrAdminGuard)
  @SelfOrAdmin('resourceId')
  @ApiOperation({
    summary: "Get user's 2FA status (MFA and DICE).",
    description: describeAccess({
      summary: 'Retrieves MFA and DICE settings for the target user.',
      jwt: 'Requires the `administrator` role or a JWT for the user being queried.',
      m2m: 'Not supported.',
    }),
  })
  @ApiParam({
    name: 'resourceId',
    description: 'User ID (string representation of number)',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '2FA status',
    type: DTOs.User2faDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad Request' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getUser2faStatus(
    @Param('resourceId') resourceId: string,
    @Req() req: Request,
  ): Promise<DTOs.User2faDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(authUser, true, resourceId);
    this.logger.log(
      `Getting 2FA status for user: ${resourceId} by ${authUser.userId}`,
    );
    return this.twoFactorAuthService.getUser2faStatus(resourceId);
  }

  /**
   * Updates the 2FA (Two-Factor Authentication) status for a user, including MFA and DICE settings.
   * Accessible by the user themselves or administrators.
   *
   * @param resourceId - The ID of the user whose 2FA status is being updated.
   * @param updateUser2faDto - Data transfer object containing the new 2FA settings.
   * @param req - The request object containing authentication information.
   * @returns A User2faDto reflecting the updated 2FA configuration.
   * @throws BadRequestException If the request body is missing or invalid.
   * @throws UnauthorizedException If the request lacks valid authentication.
   * @throws ForbiddenException If the requester is not authorized to modify the settings.
   */
  @Patch(':resourceId/2fa')
  @UseGuards(SelfOrAdminGuard)
  @SelfOrAdmin('resourceId')
  @ApiOperation({
    summary: "Update user's 2FA status (MFA and DICE).",
    description: describeAccess({
      summary:
        'Enables or disables MFA/DICE for the specified user.',
      jwt: 'Requires the `administrator` role or a JWT for the user being updated.',
      m2m: 'Not supported.',
    }),
  })
  @ApiParam({
    name: 'resourceId',
    description: 'User ID (string representation of number)',
  })
  @ApiBody({ type: DTOs.UpdateUser2faBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '2FA status updated',
    type: DTOs.User2faDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad Request' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async updateUser2faStatus(
    @Param('resourceId') resourceId: string,
    @Body() updateUser2faDto: DTOs.UpdateUser2faBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.User2faDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(authUser, true, resourceId);
    this.logger.log(
      `Updating 2FA status for user: ${resourceId} by ${authUser.userId}`,
    );
    if (!updateUser2faDto.param)
      throw new BadRequestException('Request param body is required.');
    return this.twoFactorAuthService.updateUser2faStatus(
      resourceId,
      updateUser2faDto.param,
      authUser,
    );
  }

  /**
   * Sends a 2FA One-Time Password (OTP) to a user for the login flow.
   * This is part of the two-factor authentication process after partial authentication.
   *
   * @param sendOtpDto - Data transfer object containing the user ID.
   * @returns A UserOtpResponseDto containing a resend token and status information.
   * @throws BadRequestException If the user ID is missing.
   * @throws NotFoundException If the specified user is not found.
   */
  @Post('sendOtp') // 2FA OTP for login flow - requires partial auth state (user identified)
  @ApiOperation({
    summary: 'Send 2FA OTP for a partially authenticated user.',
    description: describeAccess({
      summary:
        'Issues a 2FA OTP during the login flow once the user has partially authenticated.',
      jwt: 'Not required; this endpoint is used within the login flow.',
      m2m: 'Not applicable.',
    }),
  })
  @ApiBody({
    type: DTOs.SendOtpBodyDto,
    description: 'Requires userId of the user who needs OTP for 2FA.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '2FA OTP sent, returns resend token.',
    type: DTOs.UserOtpResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad Request' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Not Found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async sendOtp(
    @Body() sendOtpDto: DTOs.SendOtpBodyDto,
  ): Promise<DTOs.UserOtpResponseDto> {
    this.logger.log(`Sending 2FA OTP for user: ${sendOtpDto.param?.userId}`);
    this.checkParam(sendOtpDto);
    if (!sendOtpDto.param.userId) {
      throw new BadRequestException('userId is required');
    }
    // How to get authContext or ensure this is called in a valid state needs consideration
    // For now, assuming userId is trusted from a prior step (e.g. after password auth before full login)
    return this.twoFactorAuthService.sendOtpFor2fa(
      sendOtpDto.param.userId.toString(),
    );
  }

  /**
   * Resends the 2FA OTP email using a valid resend token.
   * This allows users to request a new OTP if the previous one expired or was not received.
   *
   * @param resendOtpDto - Data transfer object containing the resend token.
   * @returns A success message indicating the OTP was resent.
   * @throws BadRequestException If the resend token is missing.
   * @throws NotFoundException If the token is invalid or expired.
   */
  @Post('/resendOtpEmail') // 2FA Resend OTP
  @ApiOperation({
    summary: 'Resend 2FA OTP email using a resend token.',
    description: describeAccess({
      summary:
        'Resends the 2FA OTP email when provided a valid resend token from the login flow.',
      jwt: 'Not required; used during the login flow.',
      m2m: 'Not applicable.',
    }),
  })
  @ApiBody({ type: DTOs.ResendOtpEmailBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '2FA OTP resent successfully.',
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad Request' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Not Found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async resendOtpEmail(
    @Body() resendOtpDto: DTOs.ResendOtpEmailBodyDto,
  ): Promise<string> {
    this.logger.log(`Resending 2FA OTP email.`);
    this.checkParam(resendOtpDto);
    if (!resendOtpDto.param.userId) {
      throw new BadRequestException('userId is required');
    }
    if (!resendOtpDto.param.resendToken) {
      throw new BadRequestException('resendToken is required');
    }
    return this.twoFactorAuthService.resendOtpEmailFor2fa(
      resendOtpDto.param.userId,
      resendOtpDto.param.resendToken,
    );
  }

  @Post('checkOtp')
  @ApiOperation({
    summary: 'Check 2FA OTP and complete login.',
    description: describeAccess({
      summary:
        'Validates the provided 2FA OTP and finalizes the login process.',
      jwt: 'Not required; used during the login flow.',
      m2m: 'Not applicable.',
    }),
  })
  @ApiBody({ type: DTOs.CheckOtpBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description:
      'OTP verified, returns login completion details (e.g. user/JWTs).',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'OTP invalid or expired, or missing params.',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Not Found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async checkOtp(
    @Body() checkOtpDto: DTOs.CheckOtpBodyDto,
  ): Promise<DTOs.UserOtpResponseDto> {
    this.logger.log(`Checking 2FA OTP for user: ${checkOtpDto.param?.userId}`);
    this.checkParam(checkOtpDto);
    if (!checkOtpDto.param.userId) {
      throw new BadRequestException('userId is required');
    }
    if (!checkOtpDto.param.otp) {
      throw new BadRequestException('otp is required');
    }
    return this.twoFactorAuthService.checkOtp(
      checkOtpDto.param.userId,
      checkOtpDto.param.otp,
    );
  }

  // --- Other Endpoints ---
  /**
   * Retrieves the list of achievements earned by a user. This endpoint is restricted to administrators.
   *
   * @param resourceId - The ID of the user whose achievements are being retrieved.
   * @param req - The request object containing authentication information.
   * @returns An array of AchievementDto objects representing the user's achievements.
   * @throws UnauthorizedException If the request lacks valid authentication.
   * @throws ForbiddenException If the requester is not an administrator.
   */
  @Get(':resourceId/achievements')
  @UseGuards(RolesGuard)
  @Roles(ADMIN_ROLE)
  @ApiOperation({
    summary: 'Get achievements for a user (Admin only).',
    description: describeAccess({
      summary: 'Returns the achievements associated with the target user.',
      jwt: 'Requires a JWT with the `administrator` role.',
      m2m: 'Not supported; use an administrator JWT.',
    }),
  })
  @ApiParam({
    name: 'resourceId',
    description: 'User ID (string representation of number)',
  })
  @ApiQuery({
    name: 'selector',
    type: String,
    required: false,
    description: 'Comma-separated list of fields to include in the response',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of user achievements',
    type: [DTOs.AchievementDto],
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async getAchievements(
    @Param('resourceId') resourceId: string,
    @Req() req: Request,
    @Query('selector') selector?: string, // Optional selector query param
  ): Promise<DTOs.AchievementDto[]> {
    const authUser = getAuthenticatedUser(req);
    this.checkResourceIdAndAccess(
      authUser,
      true,
      resourceId,
      MachineScopes.readScopes,
    );
    this.logger.log(
      `Admin ${authUser.userId} getting achievements for user: ${resourceId}`,
    );
    return this.userService.getAchievements(parseInt(resourceId, 10), selector);
  }

  /**
   * Resets a user's password using a reset token.
   * This endpoint allows users to set a new password after verifying their identity through a reset token,
   * typically sent via email during the password recovery process.
   * @param passUserDto The passwod reset data transfer object.
   * @returns user details
   * @throws BadRequestException If the input is invalid (e.g., missing userId, token, or new password).
   * @throws NotFoundException If the user associated with the ID is not found.
   * @throws UnauthorizedException If the reset token is invalid or expired.
   * @throws InternalServerErrorException For any other server-side errors.
   */
  @Put('resetPassword')
  @ApiOperation({
    summary: 'Resets user password',
    description: describeAccess({
      summary:
        'Completes the password reset flow using an emailed reset token and new password.',
      jwt: 'Not required; the reset token in the payload authorizes the operation.',
      m2m: 'Not applicable.',
    }),
  })
  @ApiBody({ type: DTOs.ResetPasswordBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Password reset successfully',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User not found',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  @HttpCode(HttpStatus.OK)
  async resetPassword(
    @Body() passUserDto: DTOs.ResetPasswordBodyDto,
  ): Promise<DTOs.UserResponseDto> {
    this.checkParam(passUserDto);
    this.logger.log(`Resetting password for: ${passUserDto.param.handle}`);
    const user = await this.authFlowService.resetPassword(passUserDto);
    return mapUserToDto(user);
  }

  @Post('resendEmail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'API to resend activation email. This is used in Auth0 password change flow.',
  })
  @ApiConsumes('application/x-www-form-urlencoded')
  @ApiBody({
    description: 'Form data: email, handle',
    schema: {
      type: 'object',
      properties: { email: { type: 'string' }, handle: { type: 'string' } },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Email resent successfully',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Missing or invalid parameters',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error.',
  })
  async resendEmail(
    @Body() resendData: { email?: string; handle?: string },
  ): Promise<DTOs.UserResponseDto> {
    this.logger.log('Resend email request');
    if (!resendData?.email && !resendData?.handle) {
      throw new BadRequestException('email/handle is required');
    }
    // only one is typically expected, either handle or email
    const user = await this.userService.resendEmail(
      resendData.email,
      resendData.handle,
    );
    return mapUserToDto(user);
  }
}
