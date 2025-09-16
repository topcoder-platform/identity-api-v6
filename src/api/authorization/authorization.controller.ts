import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiConsumes,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { AuthorizationService } from './authorization.service';
import { Request, Response } from 'express';
import {
  AuthorizationCreateRequest,
  AuthorizationForm,
  AuthorizationResponse,
  GetTokenQueryDto,
  ValidateClientQueryDto,
} from '../../dto/authorization/authorization.dto';
// import { AuthGuard } from '@nestjs/passport';
import { AuthRequiredGuard } from '../../auth/guards/auth-required.guard';
import { Constants } from '../../core/constant/constants';

@ApiTags('authorizations')
@Controller('authorizations')
export class AuthorizationController {
  constructor(private readonly service: AuthorizationService) {}

  /**
   * User login redirection endpoint.
   * Generates a 302 Found response to redirect the user to the Auth0 authentication URL.
   * @param req Express request object
   * @param res Express response object
   * @param nextParam Optional parameter to override the default redirect URI
   * @returns Promise<void>
   */
  @Get('login')
  @HttpCode(HttpStatus.FOUND)
  @ApiOperation({
    summary: 'User Login. Will return a 302 response with redirect url.',
  })
  @ApiQuery({
    name: 'next',
    description: 'Hack parameter. Use this to override redirect uri',
    required: false,
  })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'redirect user to Auth0 URL',
  })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  async loginRedirect(
    @Req() req: Request,
    @Res() res: Response,
    @Query('next') nextParam?: string,
  ) {
    await this.service.loginRedirect(req, res, nextParam);
  }

  /**
   * Exchanges an authorization code for an access token.
   * Redirects the user to the Topcoder URL after token retrieval.
   * @param req Express request object
   * @param res Express response object
   * @param dto Query parameters for token retrieval
   * @returns Promise<void>
   */
  @Get()
  @HttpCode(HttpStatus.FOUND)
  @ApiOperation({
    summary: 'Get the access token by the authorization code and redirect url',
  })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'redirect user to topcoder URL',
  })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  async getTokenByAuthorizationCode(
    @Req() req: Request,
    @Res() res: Response,
    @Query() dto: GetTokenQueryDto,
  ) {
    await this.service.getTokenByAuthorizationCode(req, res, dto);
  }

  /**
   * Creates a new authorization record.
   * Handles both JSON and form-urlencoded content types.
   * @param req Express request object
   * @param res Express response object
   * @param body Request body containing authorization data
   * @returns Promise<AuthorizationResponse>
   */
  @Post()
  @ApiOperation({ summary: 'create authorization' })
  @ApiConsumes('application/json', 'application/x-www-form-urlencoded')
  @ApiResponse({
    status: HttpStatus.CREATED,
    type: AuthorizationResponse,
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad Request' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal Server Error',
  })
  async createObject(
    @Req() req: Request,
    @Res() res: Response,
    @Body() body: AuthorizationCreateRequest | AuthorizationForm,
  ) {
    const contentType = req.headers['content-type'];
    let ret: AuthorizationResponse;
    if (contentType?.includes('application/x-www-form-urlencoded')) {
      ret = await this.handleCreateForm(body as AuthorizationForm);
    } else {
      ret = await this.handleCreateRequest(
        req,
        res,
        body as AuthorizationCreateRequest,
      );
    }
    res.json(ret);
  }

  /**
   * Deletes an authorization token by target ID.
   * Requires JWT authentication.
   * @param targetId Unique identifier of the target to delete
   * @param req Express request object
   * @param res Express response object
   * @returns Promise<void>
   */
  @Delete('/:targetId')
  @UseGuards(AuthRequiredGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Delete access token and refresh token' })
  @ApiParam({
    name: 'targetId',
    description: 'target id',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'operation successful',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal Server Error',
  })
  async deleteObject(
    @Param('targetId') targetId: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    await this.service.deleteObject(targetId, req, res);
    res.json({});
  }

  /**
   * Deletes the authorization token of the currently logged-in user.
   * Requires JWT authentication and uses a default target ID.
   * @param req Express request object
   * @param res Express response object
   * @returns Promise<void>
   */
  @Delete()
  @UseGuards(AuthRequiredGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Delete access token of logged in user' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'operation successful',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal Server Error',
  })
  async deleteToken(@Req() req: Request, @Res() res: Response) {
    await this.service.deleteObject(Constants.defaultTargetId, req, res);
    res.json({});
  }

  /**
   * Validates a client based on client ID and redirect URI.
   * @param dto Query parameters containing client validation data
   * @returns Promise<string> Validation result message
   */
  @Get('/validateClient')
  @ApiOperation({ summary: 'Validate client with client id and redirect url' })
  @ApiResponse({
    status: HttpStatus.OK,
    type: String,
    example: 'Valid client',
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Bad Request' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal Server Error',
  })
  async validateClient(@Query() dto: ValidateClientQueryDto) {
    return await this.service.validateClient(dto);
  }

  /**
   * Retrieves an authorization object by resource ID.
   * Handles both Appirio Service Platform JWT and Auth0 JWT tokens.
   * @param req Express request object
   * @param res Express response object
   * @param targetId Resource ID of the authorization object
   * @param fields Optional fields to include in the response
   * @returns Promise<AuthorizationResponse> Authorization object response
   */
  @Get(':resourceId')
  @ApiOperation({
    summary:
      'Returns ASP token from given Authorization Bearer header. Bearer can hold either of 2 token, (a) Appirio Service Platform JWT or (b) Auth0 JWT',
  })
  @ApiParam({
    name: 'resourceId',
    description: 'target id',
    required: true,
    example: '1',
  })
  @ApiQuery({
    name: 'fields',
    description: 'fields you want in response',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    type: AuthorizationResponse,
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal Server Error',
  })
  async getObject(
    @Req() req: Request,
    @Res() res: Response,
    @Param('resourceId') targetId: string,
    @Query('fields') fields?: string,
  ) {
    res.json(await this.service.getObject(targetId, req, res, fields));
  }

  /**
   * Handles form-based authorization creation.
   * @param data Authorization form data
   * @returns Promise<AuthorizationResponse> Created authorization response
   */
  private async handleCreateForm(
    data: AuthorizationForm,
  ): Promise<AuthorizationResponse> {
    return await this.service.createObjectForm(data);
  }

  /**
   * Handles JSON-based authorization creation.
   * @param req Express request object
   * @param res Express response object
   * @param data Authorization creation request data
   * @returns Promise<AuthorizationResponse> Created authorization response
   */
  private async handleCreateRequest(
    req: Request,
    res: Response,
    data: AuthorizationCreateRequest,
  ): Promise<AuthorizationResponse> {
    return await this.service.createObject(req, res, data.param);
  }
}
