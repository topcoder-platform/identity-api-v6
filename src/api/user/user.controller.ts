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
  Headers,
  NotFoundException,
  Inject,
  HttpException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { UserService } from './user.service';
import { UserProfileService } from './user-profile.service';
import { AuthFlowService } from './auth-flow.service';
import { TwoFactorAuthService } from './two-factor-auth.service';
import { ValidationService } from './validation.service';
import { AuthenticatedUser } from '../../core/auth/jwt.strategy'; // For type hints
import { RoleService } from '../role/role.service'; // If needed directly
import * as DTOs from '../../dto/user/user.dto'; // Import all user DTOs
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiParam,
  ApiBody,
  ApiHeader,
  ApiConsumes,
  ApiBearerAuth,
} from '@nestjs/swagger'; // For Swagger documentation
import { CacheInterceptor } from '@nestjs/cache-manager'; // For caching responses
import { ValidationExceptionFilter } from '../../shared/filters/validation-exception.filter';
import { checkAdminOrScope } from '../../shared/auth/auth.helpers'; // Import helper
import { AuthGuard } from '@nestjs/passport';
import { PrismaClient as PrismaClientCommonOltp } from '@prisma/client-common-oltp'; // Import PrismaClient
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module'; // Import injection token
import { ValidationResponseDto } from '../../dto/user/user.dto';

// Helper function for manual auth checks (Example)
function checkPermission(
  user: AuthenticatedUser | undefined,
  requiredUserId?: number | string,
  isAdminRequired: boolean = false,
  allowedScopes?: string[],
) {
  if (!user) {
    throw new ForbiddenException('Authentication required.');
  }
  const userIdNum =
    typeof requiredUserId === 'string'
      ? parseInt(requiredUserId, 10)
      : requiredUserId;
  const isSelf =
    userIdNum !== undefined &&
    !isNaN(userIdNum) &&
    user.userId === userIdNum.toString();

  if (isAdminRequired && !user.isAdmin) {
    throw new ForbiddenException('Admin privileges required.');
  }

  // Log values just before the critical check for the 403
  this.logger.debug(
    `[checkPermission] About to check non-admin resource access. ` +
      `isAdminRequired: ${isAdminRequired}, requiredUserId: ${requiredUserId}(${typeof requiredUserId}), ` +
      `isSelf: ${isSelf}, user.isAdmin: ${user.isAdmin}, user.userId: ${user.userId}`,
  );

  if (
    !isAdminRequired &&
    requiredUserId !== undefined &&
    !isSelf &&
    !user.isAdmin
  ) {
    // If targeting specific user, allow only self or admin
    throw new ForbiddenException('Permission denied to access this resource.');
  }
  if (
    allowedScopes &&
    !user.scopes?.some((scope) => allowedScopes.includes(scope))
  ) {
    if (!user.isAdmin) {
      // Admins bypass scope checks in this example
      throw new ForbiddenException(
        `Missing required scope(s): ${allowedScopes.join(', ')}`,
      );
    }
  }
  // Add more granular checks if needed
}

// Helper function to map UserModel to UserResponseDto
function mapUserToDto(user: any): DTOs.UserResponseDto {
  if (!user) return null;
  const dto = new DTOs.UserResponseDto();
  dto.id = user.user_id.toString(); // Changed from Number(user.user_id)
  dto.handle = user.handle;
  dto.firstName = user.first_name;
  dto.lastName = user.last_name;
  dto.status = user.status;
  // Map other fields as needed from UserModel to UserResponseDto
  dto.createdAt = user.create_date?.toISOString();
  dto.updatedAt = user.modify_date?.toISOString();
  // ... map other fields defined in UserResponseDto
  return dto;
}

// Define the helper function, similar to how it was in AuthorizationController
function getAuthenticatedUser(req: Request): AuthenticatedUser {
  const user = req.user;
  const logger = new Logger('getAuthenticatedUser'); // It's a global helper, so create a local logger.
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
  if (!user.userId || !user.handle || !user.roles || !user.scopes) {
    throw new InternalServerErrorException(
      'Authenticated user object is incomplete.',
    );
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
    @Inject(PRISMA_CLIENT_COMMON_OLTP)
    private readonly prismaOltp: PrismaClientCommonOltp, // Inject PrismaClient
  ) {}

  private checkPermission(
    user: AuthenticatedUser | undefined,
    requiredUserId?: number | string,
    isAdminRequired: boolean = false,
    allowedScopes?: string[],
  ) {
    this.logger.debug(
      `[UserController.checkPermission] Entry. User: ${JSON.stringify(user)}, requiredUserId: ${requiredUserId}, isAdminRequired: ${isAdminRequired}, allowedScopes: ${JSON.stringify(allowedScopes)}`,
    );
    if (!user) {
      this.logger.warn(
        `[UserController.checkPermission] User object is undefined. Throwing ForbiddenException.`,
      );
      throw new ForbiddenException('Authentication required.');
    }
    const userIdNum =
      typeof requiredUserId === 'string'
        ? parseInt(requiredUserId, 10)
        : requiredUserId;
    const isSelf =
      userIdNum !== undefined &&
      !isNaN(userIdNum) &&
      user.userId === userIdNum.toString();

    if (isAdminRequired && !user.isAdmin) {
      throw new ForbiddenException('Admin privileges required.');
    }

    this.logger.debug(
      `[checkPermission] About to check non-admin resource access. ` +
        `isAdminRequired: ${isAdminRequired}, requiredUserId: ${requiredUserId}(${typeof requiredUserId}), ` +
        `isSelf: ${isSelf}, user.isAdmin: ${user.isAdmin}, user.userId: ${user.userId}`,
    );

    if (
      !isAdminRequired &&
      requiredUserId !== undefined &&
      !isSelf &&
      !user.isAdmin
    ) {
      throw new ForbiddenException(
        'Permission denied to access this resource.',
      );
    }
    if (
      allowedScopes &&
      !user.scopes?.some((scope) => allowedScopes.includes(scope))
    ) {
      if (!user.isAdmin) {
        throw new ForbiddenException(
          `Missing required scope(s): ${allowedScopes.join(', ')}`,
        );
      }
    }
  }

  // --- Public Endpoints (No Auth Required) ---

  @Get('resetToken')
  @ApiOperation({
    summary:
      'Generates a password reset token and sends it via email (Simulated)',
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
  @ApiResponse({ status: HttpStatus.OK, description: 'Reset token sent (simulated)' })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Email or handle is required, or invalid input',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  async getResetToken(
    @Query('email') email?: string,
    @Query('handle') handle?: string,
    @Query('resetPasswordUrlPrefix') resetPasswordUrlPrefix?: string,
  ): Promise<{ message: string }> {
    this.logger.log(
      `Initiating password reset request for email: ${email}, handle: ${handle}`,
    );
    if (!email && !handle) {
      throw new BadRequestException(
        'Either email or handle query param is required.',
      );
    }

    await this.authFlowService.initiatePasswordReset(
      email || handle,
      resetPasswordUrlPrefix,
    );
    return { message: 'Password reset token has been sent (simulated).' };
  }

  @Get('validateHandle')
  @ApiOperation({ summary: 'Validate if a user handle is available' })
  @ApiQuery({ name: 'handle', required: true, type: String })
  @ApiResponse({ status: HttpStatus.OK, type: DTOs.ValidationResponseDto })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  async validateHandle(
    @Query('handle') handle: string,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(`Validating handle: ${handle}`);
    if (!handle) {
      throw new BadRequestException('Handle query parameter is required.');
    }
    return this.validationService.validateHandle(handle);
  }

  @Get('validateEmail')
  @ApiOperation({ summary: 'Validate if an email address is available' })
  @ApiQuery({ name: 'email', required: true, type: String })
  @ApiResponse({ status: HttpStatus.OK, type: DTOs.ValidationResponseDto })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  async validateEmail(
    @Query('email') email: string,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(`Validating email: ${email}`);
    if (!email) {
      throw new BadRequestException('Email query parameter is required.');
    }
    return this.validationService.validateEmail(email);
  }

  @Get('validateSocial')
  @ApiOperation({
    summary: 'Validate social provider and user ID availability',
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
  }) // Update Swagger DTO if wrapped
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input or unsupported provider.',
  }) // Update Swagger DTO if wrapped
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

  @Get()
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Find users based on query parameters' })
  @ApiQuery({ name: 'handle', required: false, type: String })
  @ApiQuery({ name: 'email', required: false, type: String })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Default 20',
  })
  @ApiQuery({
    name: 'offset',
    required: false,
    type: Number,
    description: 'Default 0',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of users found',
    type: [DTOs.UserResponseDto],
  })
  async findUsers(
    @Query() query: DTOs.UserSearchQueryDto,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto[]> {
    // Log the Authorization header
    this.logger.debug(
      `[findUsers] Incoming Request Headers: ${JSON.stringify(req.headers)}`,
    );
    const authUser = req.user; // This should now be populated by the guard if auth succeeds
    // Check if authUser is populated after the guard
    if (!authUser) {
      this.logger.error(
        '[findUsers] AuthGuard ran, but req.user is still undefined!',
      );
      // This case should ideally be caught by the guard itself, but good to check.
      throw new UnauthorizedException(
        'User context not available after authentication guard.',
      );
    }
    this.logger.debug(
      `[findUsers] req.user object after AuthGuard: ${JSON.stringify(authUser)}`,
    );
    this.checkPermission(authUser, undefined, true); // Admin required
    this.logger.log('Finding users with query:', query);
    const users = await this.userService.findUsers(query);
    return users.map(mapUserToDto);
  }

  @Get(':resourceId')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Get a specific user by ID' })
  @ApiParam({ name: 'resourceId', type: Number })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User found',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  async findUserById(
    @Param('resourceId') resourceId: string,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto> {
    const authUser = req.user;
    const idNum = parseInt(resourceId, 10);
    if (isNaN(idNum)) {
      throw new BadRequestException('Invalid user ID format.');
    }
    this.checkPermission(authUser, idNum); // Call as method
    this.logger.log(`Finding user by ID: ${idNum}`);
    const user = await this.userService.findUserById(idNum);
    return mapUserToDto(user);
  }

  @Post()
  @ApiOperation({
    summary:
      'Register a new user (Placeholder - actual registration flow might be different)',
  })
  @ApiBody({ type: DTOs.CreateUserBodyDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'User created',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Handle or email already exists' })
  @HttpCode(HttpStatus.CREATED)
  async registerUser(
    @Body() createUserDto: DTOs.CreateUserBodyDto,
  ): Promise<DTOs.UserResponseDto> {
    this.logger.log(`Registering new user: ${createUserDto.param.handle}`);
    const user = await this.userService.registerUser(createUserDto);
    return mapUserToDto(user);
  }

  @Patch(':resourceId')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Update basic user information' })
  @ApiParam({ name: 'resourceId', type: Number })
  @ApiBody({ type: DTOs.UpdateUserBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User updated',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  async updateBasicInfo(
    @Param('resourceId') resourceId: string,
    @Body() updateUserDto: DTOs.UpdateUserBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto> {
    const authUser = req.user;
    this.checkPermission(authUser, resourceId); // Call as method
    this.logger.log(`Updating user: ${resourceId}`);
    const user = await this.userService.updateBasicInfo(
      resourceId,
      updateUserDto,
      authUser,
    );
    return mapUserToDto(user);
  }

  @Delete(':resourceId')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({
    summary: 'Delete a user - NOT IMPLEMENTED as per legacy system.',
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
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden (Admin role required)' })
  @HttpCode(HttpStatus.NOT_IMPLEMENTED) // Set default status code
  async deleteUser(
    @Param('resourceId') resourceId: string,
    @Req() req: Request,
  ): Promise<void> {
    const authUser = getAuthenticatedUser(req);
    // Still perform admin check, as only admins would know it's not implemented
    this.checkPermission(authUser, undefined, true);
    this.logger.warn(
      `Admin ${authUser.userId} attempted to access DELETE /users/${resourceId}, which is not implemented.`,
    );
    throw new HttpException('Not Implemented', HttpStatus.NOT_IMPLEMENTED);
  }

  // --- SSO Login Endpoints ---

  @Post(':userId/SSOUserLogin')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Link an SSO profile to a user (Admin only).' })
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
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden (Admin role required)' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User or SSO Provider not found' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'SSO profile already linked' })
  async createSSOUserLogin(
    @Param('userId', ParseIntPipe) userId: number,
    @Body() createSSODto: DTOs.CreateUpdateSSOBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, undefined, true); // Call as method
    this.logger.log(
      `Admin ${authUser.userId} creating SSO login for user: ${userId}, provider: ${createSSODto.param?.provider}`,
    );
    if (!createSSODto.param) {
      throw new BadRequestException('Request body param is required.');
    }
    return this.userProfileService.createSSOUserLogin(
      userId,
      createSSODto.param,
      authUser.userId,
    );
  }

  @Put(':userId/SSOUserLogin') // Using provider and ssoUserId from body to identify the record
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({
    summary: 'Update an existing SSO profile linked to a user (Admin only).',
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
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden (Admin role required)' })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User, SSO Provider, or specific SSO link not found',
  })
  async updateSSOUserLogin(
    @Param('userId', ParseIntPipe) userId: number,
    @Body() updateSSODto: DTOs.CreateUpdateSSOBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, userId, false); // Call as method
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
      authUser.userId.toString(),
    );
  }

  @Delete(':userId/SSOUserLogin')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Delete an SSO login link for a user' })
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
  @ApiQuery({
    name: 'ssoUserId',
    type: String,
    required: true,
    description: 'User ID from the external SSO provider',
  })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
    description: 'SSO login link deleted successfully',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Missing required parameters or provider not found',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User or SSO link not found' })
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
    this.checkPermission(authUser, userId, false); // Call as method

    const { provider: providerNameQuery, providerId, ssoUserId } = query;

    if (!ssoUserId) {
      throw new BadRequestException('ssoUserId query parameter is required.');
    }

    let providerName = providerNameQuery;

    this.logger.log(
      `User ${authUser.userId} deleting SSO login for user: ${userId}, providerNameQuery: ${providerNameQuery}, providerId: ${providerId}, ssoUserId: ${ssoUserId}`,
    );

    if (!providerName && providerId) {
      this.logger.debug(
        `Provider name not given, looking up by providerId: ${providerId}`,
      );
      const providerRecord =
        await this.prismaOltp.sso_login_provider.findUnique({
          where: { sso_login_provider_id: providerId },
        });
      if (!providerRecord) {
        throw new BadRequestException(
          `SSO Provider with ID ${providerId} not found.`,
        );
      }
      providerName = providerRecord.name;
      this.logger.debug(
        `Found provider name: ${providerName} for ID: ${providerId}`,
      );
    } else if (!providerName && !providerId) {
      throw new BadRequestException(
        'Either provider name or providerId must be specified.',
      );
    }

    // Ensure target user exists
    const targetUser = await this.userService.findUserById(userId);
    if (!targetUser) {
      throw new NotFoundException(`User with ID ${userId} not found.`);
    }

    await this.userProfileService.deleteSSOUserLogin(
      userId,
      providerName,
      ssoUserId,
      authUser.userId.toString(),
    );
  }

  @Get(':userId/SSOUserLogins')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({
    summary: 'Get all SSO profiles linked to a user (Admin only).',
  })
  @ApiParam({ name: 'userId', description: 'Numeric User ID', type: Number })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of linked SSO profiles',
    type: [DTOs.UserProfileDto],
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden (Admin role required)' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  async getSSOUserLogins(
    @Param('userId', ParseIntPipe) userId: number,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto[]> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, undefined, true); // Call as method
    this.logger.log(
      `Admin ${authUser.userId} getting SSO logins for user: ${userId}`,
    );
    return this.userProfileService.findSSOUserLoginsByUserId(userId);
  }

  // --- External Profiles (e.g. Topcoder, GitHub, etc. - Generic handling) ---
  @Post(':resourceId/profiles')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({
    summary: 'Add an external profile (social, etc.) to a user (Admin only).',
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
  @HttpCode(HttpStatus.CREATED)
  async addExternalProfile(
    @Param('resourceId', ParseIntPipe) resourceId: number,
    @Body() createProfileDto: DTOs.CreateProfileBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, undefined, true); // Call as method
    this.logger.log(
      `Admin ${authUser.userId} adding profile for user: ${resourceId}, provider: ${createProfileDto.param?.provider}`,
    );
    if (!createProfileDto.param)
      throw new BadRequestException('Profile data is required.');
    return this.userProfileService.addExternalProfile(
      resourceId,
      createProfileDto.param,
      authUser.userId,
    );
  }

  @Get(':userId/profiles')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({
    summary:
      'Get all external profiles (SSO, social, etc.) for a user (Admin or self).',
    description: 'If not admin, only allowed for own userId.',
  })
  @ApiParam({ name: 'userId', description: 'Numeric User ID', type: Number })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of external profiles',
    type: [DTOs.UserProfileDto],
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  async getAllExternalProfiles(
    @Param('userId', ParseIntPipe) userId: number,
    @Req() req: Request,
  ): Promise<DTOs.UserProfileDto[]> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, userId.toString()); // Call as method
    this.logger.log(
      `${authUser.isAdmin ? 'Admin' : 'User'} ${authUser.userId} getting all profiles for user: ${userId}`,
    );
    return this.userProfileService.findAllUserProfiles(userId);
  }

  @Delete(':resourceId/profiles/:providerName')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({
    summary:
      'Delete all external profiles for a user under a specific provider (Admin only).',
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
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User or profile not found' })
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteExternalProfile(
    @Param('resourceId', ParseIntPipe) resourceId: number,
    @Param('providerName') providerName: string,
    @Req() req: Request,
  ): Promise<void> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, undefined, true); // Call as method
    this.logger.log(
      `Admin ${authUser.userId} deleting profiles for user: ${resourceId}, provider: ${providerName}`,
    );
    await this.userProfileService.deleteExternalProfile(
      resourceId,
      providerName,
    );
  }

  // --- Authentication/Session Related (Mostly for Auth0 Custom DB/Rules/Actions) ---

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Authenticate user for Auth0 Custom Database script.',
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
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Missing parameters' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Invalid credentials' })
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

  @Post('roles')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get user profile and roles for Auth0 Rules/Actions.',
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
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Missing email or handle' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
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

  @Post('changePassword')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'Change password for Auth0 Action (typically called by Auth0 post-password-reset flow).',
  })
  @ApiConsumes('application/x-www-form-urlencoded')
  @ApiBody({
    description: 'Form data: email, password (new)',
    schema: {
      type: 'object',
      properties: { email: { type: 'string' }, password: { type: 'string' } },
    },
  })
  @ApiResponse({ status: HttpStatus.OK, description: 'Password changed successfully' })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Missing parameters or invalid password',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Password change not allowed (e.g., SSO user)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
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

  // @Post('resetPassword')
  // @ApiOperation({ summary: 'Reset user password using a valid reset token' })
  // @ApiBody({ type: DTOs.ResetPasswordBodyDto })
  // @ApiResponse({
  //   status: HttpStatus.OK,
  //   description: 'Password has been reset successfully.',
  // })
  // @ApiResponse({
  //   status: HttpStatus.BAD_REQUEST,
  //   description: 'Invalid input, token, or password format.',
  // })
  // @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Invalid or expired reset token.' })
  // @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found.' })
  // async resetPassword(
  //   @Body() resetPasswordDto: DTOs.ResetPasswordBodyDto,
  // ): Promise<{ message: string }> {
  //   this.logger.log(`Attempting to reset password.`);
  //   // The DTO structure is { param: { handleOrEmail?, credential: { resetToken, password } } }
  //   // AuthFlowService.resetPassword expects { handleOrEmail?, resetToken, newPassword }
  //   if (
  //     !resetPasswordDto.param?.credential?.resetToken ||
  //     !resetPasswordDto.param?.credential?.password
  //   ) {
  //     throw new BadRequestException(
  //       'Reset token and new password are required within credential parameter.',
  //     );
  //   }
  //   await this.authFlowService.resetPassword({
  //     handleOrEmail:
  //       resetPasswordDto.param.handle || resetPasswordDto.param.email, // Use handle or email from param
  //     resetToken: resetPasswordDto.param.credential.resetToken,
  //     newPassword: resetPasswordDto.param.credential.password,
  //   });
  //   return { message: 'Password has been reset successfully.' };
  // }

  @Put('activate')
  @ApiOperation({
    summary: 'Activate a new user account using OTP and a resend token.',
  })
  @ApiBody({ type: DTOs.ActivateUserBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User activated successfully',
    type: DTOs.UserResponseDto,
  }) // Assuming it returns the user
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input, OTP, or token' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden (e.g., token mismatch)' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({ status: HttpStatus.GONE, description: 'Token or OTP expired' })
  async activateUser(
    @Body() activateUserDto: DTOs.ActivateUserBodyDto,
  ): Promise<DTOs.UserResponseDto> {
    this.logger.log(
      `Attempting to activate user: ${activateUserDto.param.userId}`,
    );
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

  @Post('resendActivationEmail')
  @ApiOperation({
    summary: 'Resend activation email/OTP using a resend token.',
  })
  @ApiBody({ type: DTOs.UserOtpDto }) // UserOtpDto contains userId and resendToken for this flow
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Activation email resent successfully',
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input or token' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden (e.g., token mismatch)' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({ status: HttpStatus.GONE, description: 'Token expired' })
  async resendActivationEmail(
    @Body() resendActivationDto: DTOs.UserOtpDto,
  ): Promise<{ message: string }> {
    this.logger.log(
      `Attempting to resend activation email for user: ${resendActivationDto.userId}`,
    );
    return this.authFlowService.requestResendActivation(resendActivationDto);
  }

  // --- Profile Updates (Require Auth) ---

  @Patch(':resourceId/handle')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Update user handle (Admin only).' })
  @ApiParam({ name: 'resourceId', description: 'User ID' })
  @ApiBody({ type: DTOs.UpdateHandleBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Handle updated',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input or handle format' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden (Admin role required)' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Handle already exists' })
  async updateHandle(
    @Param('resourceId') resourceId: string,
    @Body() updateHandleDto: DTOs.UpdateHandleBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, undefined, true); // Call as method
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

  @Patch(':resourceId/email')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({
    summary:
      'Update user primary email (Admin only). This will set the new email to unverified and trigger verification.',
  })
  @ApiParam({ name: 'resourceId', description: 'User ID' })
  @ApiBody({ type: DTOs.UpdateEmailBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Primary email update process initiated',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input or email format' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden (Admin role required)' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Email already in use by another account',
  })
  async updatePrimaryEmail(
    @Param('resourceId') resourceId: string,
    @Body() updateEmailDto: DTOs.UpdateEmailBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, undefined, true); // Call as method
    this.logger.log(
      `Admin ${authUser.userId} attempting to update primary email for user ${resourceId}`,
    );
    if (!updateEmailDto.param?.email) {
      throw new BadRequestException('email parameter is required.');
    }
    const updatedUser = await this.userService.updatePrimaryEmail(
      resourceId,
      updateEmailDto.param.email,
      authUser,
    );
    return mapUserToDto(updatedUser);
  }

  @Post('oneTimeToken') // Form data expected as per Java UserResource
  @ApiOperation({
    summary:
      'Request a one-time token for email update, requires user credentials.',
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
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Missing userId or password' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Invalid credentials' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'User account not active' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
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

  @Post(':resourceId/email/:email')
  @ApiOperation({
    summary: 'Update user primary email using a one-time token.',
  })
  @ApiParam({ name: 'resourceId', type: 'string', description: 'User ID' })
  @ApiParam({ name: 'email', type: 'string', description: 'New email address' })
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer token (the one-time token)',
    required: true,
  })
  @ApiResponse({ status: HttpStatus.OK, description: 'Email updated successfully' })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input or token format' })
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
  @ApiResponse({ status: HttpStatus.GONE, description: 'One-time token expired' })
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

  @Patch(':resourceId/status')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Update user status (Admin only).' })
  @ApiParam({ name: 'resourceId', description: 'User ID' })
  @ApiBody({ type: DTOs.UpdateStatusBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Status updated',
    type: DTOs.UserResponseDto,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid status code' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Forbidden (Admin role required)' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'User not found' })
  async updateStatus(
    @Param('resourceId') resourceId: string,
    @Body() updateStatusDto: DTOs.UpdateStatusBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.UserResponseDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, undefined, true); // Call as method
    this.logger.log(
      `Admin ${authUser.userId} attempting to update status for user ${resourceId}`,
    );
    if (!updateStatusDto.param?.status) {
      throw new BadRequestException('Status parameter is required.');
    }
    const updatedUser = await this.userService.updateStatus(
      resourceId,
      updateStatusDto.param.status,
      authUser,
    );
    return mapUserToDto(updatedUser);
  }

  // --- Roles ---

  @Post('updatePrimaryRole')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({
    summary: 'Update the primary role for the authenticated user (Self only).',
  })
  @ApiBody({ type: DTOs.UpdatePrimaryRoleBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Primary role updated successfully.',
    schema: { type: 'object', properties: { message: { type: 'string' } } },
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input or role name.' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Forbidden (e.g., role not assignable or not owned by user)',
  })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Role not found.' })
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

  @Get(':resourceId/2fa')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: "Get user's 2FA status (MFA and DICE)." })
  @ApiParam({
    name: 'resourceId',
    description: 'User ID (string representation of number)',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '2FA status',
    type: DTOs.User2faDto,
  })
  async getUser2faStatus(
    @Param('resourceId') resourceId: string,
    @Req() req: Request,
  ): Promise<DTOs.User2faDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, resourceId); // Call as method
    this.logger.log(
      `Getting 2FA status for user: ${resourceId} by ${authUser.userId}`,
    );
    return this.twoFactorAuthService.getUser2faStatus(resourceId);
  }

  @Patch(':resourceId/2fa')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: "Update user's 2FA status (MFA and DICE)." })
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
  async updateUser2faStatus(
    @Param('resourceId') resourceId: string,
    @Body() updateUser2faDto: DTOs.UpdateUser2faBodyDto,
    @Req() req: Request,
  ): Promise<DTOs.User2faDto> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, resourceId); // Call as method
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

  @Get(':resourceId/diceConnection')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Get/Initiate DICE connection (Self only).' })
  @ApiParam({
    name: 'resourceId',
    description: 'User ID (string representation of number)',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'DICE connection details/status',
    type: DTOs.DiceConnectionResponseDto,
  })
  async getDiceConnection(
    @Param('resourceId') resourceId: string,
    @Req() req: Request,
  ): Promise<DTOs.DiceConnectionResponseDto> {
    const authUser = getAuthenticatedUser(req);
    // Explicit self-check as per migration doc
    if (authUser.userId !== resourceId)
      throw new ForbiddenException(
        'Cannot access DICE connection for another user.',
      );
    this.logger.log(
      `Getting DICE connection for user: ${resourceId} (self-initiated)`,
    );
    return this.twoFactorAuthService.getDiceConnection(resourceId, authUser);
  }

  @Post('dice-status') // Webhook from DICE - requires separate auth (e.g. API Key)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Webhook endpoint for DICE to post status updates.',
    description: 'Requires specific API key auth.',
  })
  @ApiHeader({
    name: 'x-api-key',
    description: 'API Key for DICE webhook validation',
    required: true,
  })
  @ApiBody({ type: DTOs.DiceStatusWebhookBodyDto })
  @ApiResponse({ status: HttpStatus.OK, description: 'Webhook received' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Invalid API Key' })
  async handleDiceWebhook(
    @Body() diceStatusDto: DTOs.DiceStatusWebhookBodyDto,
    @Headers('x-api-key') apiKey: string,
  ): Promise<{ message: string }> {
    this.logger.log(`Received DICE webhook status: ${diceStatusDto.event}`);
    // const isValid = await this.twoFactorAuthService.isValidDiceApiKey(apiKey); // Service method needed
    // if (!isValid) throw new UnauthorizedException('Invalid API Key for DICE webhook');
    return this.twoFactorAuthService.handleDiceWebhook(diceStatusDto);
  }

  @Post('sendOtp') // 2FA OTP for login flow - requires partial auth state (user identified)
  @ApiOperation({ summary: 'Send 2FA OTP for a partially authenticated user.' })
  @ApiBody({
    type: DTOs.SendOtpBodyDto,
    description: 'Requires userId of the user who needs OTP for 2FA.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '2FA OTP sent, returns resend token.',
    type: DTOs.UserOtpResponseDto,
  })
  async sendOtp(
    @Body() sendOtpDto: DTOs.SendOtpBodyDto,
  ): Promise<DTOs.UserOtpResponseDto> {
    this.logger.log(`Sending 2FA OTP for user: ${sendOtpDto.param?.userId}`);
    if (!sendOtpDto.param?.userId)
      throw new BadRequestException('UserId required in param.');
    // How to get authContext or ensure this is called in a valid state needs consideration
    // For now, assuming userId is trusted from a prior step (e.g. after password auth before full login)
    return this.twoFactorAuthService.sendOtpFor2fa(
      sendOtpDto.param.userId.toString(),
    );
  }

  @Post('/resendOtpEmail') // 2FA Resend OTP
  @ApiOperation({ summary: 'Resend 2FA OTP email using a resend token.' })
  @ApiBody({ type: DTOs.ResendOtpEmailBodyDto })
  @ApiResponse({ status: HttpStatus.OK, description: '2FA OTP resent successfully.' })
  async resendOtpEmail(
    @Body() resendOtpDto: DTOs.ResendOtpEmailBodyDto,
  ): Promise<{ message: string }> {
    this.logger.log(`Resending 2FA OTP email.`);
    if (!resendOtpDto.param?.resendToken)
      throw new BadRequestException('Resend token required in param.');
    return this.twoFactorAuthService.resendOtpEmailFor2fa(
      resendOtpDto.param.resendToken,
    );
  }

  @Post('checkOtp') // 2FA Check OTP - requires partial auth state
  @ApiOperation({ summary: 'Check 2FA OTP and complete login.' })
  @ApiBody({ type: DTOs.CheckOtpBodyDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description:
      'OTP verified, returns login completion details (e.g. user/JWTs).',
  }) // Actual type depends on what AuthFlowService.completeLoginAfter2fa returns
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'OTP invalid or expired, or missing params.',
  })
  async checkOtp(@Body() checkOtpDto: DTOs.CheckOtpBodyDto): Promise<any> {
    this.logger.log(`Checking 2FA OTP for user: ${checkOtpDto.param?.userId}`);
    if (!checkOtpDto.param?.userId || !checkOtpDto.param?.otp)
      throw new BadRequestException('UserId and OTP required in param.');
    // Needs authContext or similar to know which user's login to complete
    return this.twoFactorAuthService.checkOtpAndCompleteLogin(
      checkOtpDto.param.userId.toString(),
      checkOtpDto.param.otp,
    );
  }

  // --- Other Endpoints ---
  @Get(':resourceId/achievements')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Get achievements for a user (Admin only).' })
  @ApiParam({
    name: 'resourceId',
    description: 'User ID (string representation of number)',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of user achievements',
    type: [DTOs.AchievementDto],
  })
  async getAchievements(
    @Param('resourceId') resourceId: string,
    @Req() req: Request,
  ): Promise<DTOs.AchievementDto[]> {
    const authUser = getAuthenticatedUser(req);
    this.checkPermission(authUser, undefined, true); // Call as method
    this.logger.log(
      `Admin ${authUser.userId} getting achievements for user: ${resourceId}`,
    );
    return this.userService.getAchievements(parseInt(resourceId, 10));
  }

  // TODO: Add self-service endpoints like updateMyMaritalStatus, updateMyHomeAddress etc. as per Java resource if needed.
  // These would not be admin-only.
}
