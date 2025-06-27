import { Body, Controller, Delete, Get, HttpCode, Param, Post, Query, Req, Res, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiConsumes, ApiOperation, ApiParam, ApiQuery, ApiResponse, ApiTags } from "@nestjs/swagger";
import { AuthorizationService } from "./authorization.service";
import { Request, Response } from 'express';
import { AuthorizationCreateRequest, AuthorizationForm, AuthorizationResponse, GetTokenQueryDto, ValidateClientQueryDto } from "../../dto/authorization/authorization.dto";
import { AuthGuard } from "@nestjs/passport";

@ApiTags('groups')
@Controller('authorizations')
export class AuthorizationController {

  constructor(private readonly service: AuthorizationService) {}

  @Get('login')
  @HttpCode(302)
  @ApiOperation({
    summary: 'User Login. Will return a 302 response with redirect url.'
  })
  @ApiQuery({
    name: 'next',
    description: 'Hack parameter. Use this to override redirect uri',
    required: false
  })
  @ApiResponse({
    status: 302,
    description: 'redirect user to Auth0 URL'
  })
  @ApiResponse({status: 500, description: 'Internal Server Error'})
  async loginRedirect(
    @Req() req: Request,
    @Res() res: Response,
    @Query('next') nextParam?: string
  ) {
    await this.service.loginRedirect(req, res, nextParam);
  }

  @Get()
  @HttpCode(302)
  @ApiOperation({
    summary: 'Get the access token by the authorization code and redirect url'
  })
  @ApiResponse({
    status: 302,
    description: 'redirect user to topcoder URL'
  })
  @ApiResponse({status: 500, description: 'Internal Server Error'})
  async getTokenByAuthorizationCode(
    @Req() req: Request,
    @Res() res: Response,
    @Query() dto: GetTokenQueryDto
  ) {
    await this.service.getTokenByAuthorizationCode(req, res, dto);
  }


  @Post()
  @ApiOperation({ summary: 'create authorization' })
  @ApiConsumes('application/json', 'application/x-www-form-urlencoded')
  @ApiResponse({
    status: 201,
    type: AuthorizationResponse
  })
  @ApiResponse({ status: 400, description: 'Bad Request'})
  @ApiResponse({ status: 401, description: 'Unauthorized'})
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  async createObject(
    @Req() req: Request,
    @Res() res: Response,
    @Body() body: AuthorizationCreateRequest | AuthorizationForm
  ) {
    const contentType = req.headers['content-type'];
    let ret: AuthorizationResponse;
    if (contentType?.includes('application/x-www-form-urlencoded')) {
      ret = await this.handleCreateForm(body as AuthorizationForm);
    } else {
      ret = await this.handleCreateRequest(req, res, body as AuthorizationCreateRequest);
    }
    res.json(ret);
  }

  @Delete('/:targetId')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Delete access token and refresh token' })
  @ApiParam({
    name: 'targetId',
    description: 'target id'
  })
  @ApiResponse({
    status: 200, description: 'operation successful'
  })
  @ApiResponse({ status: 401, description: 'Unauthorized'})
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  async deleteObject(
    @Param('targetId') targetId: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    await this.service.deleteObject(targetId, req, res);
    res.json({});
  }

  @Delete()
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Delete access token of logged in user' })
  @ApiResponse({
    status: 200, description: 'operation successful'
  })
  @ApiResponse({ status: 401, description: 'Unauthorized'})
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  async deleteToken(
    @Req() req: Request,
    @Res() res: Response,
  ) {
    await this.service.deleteObject('1', req, res);
    res.json({});
  }

  @Get('/validateClient')
  @ApiOperation({ summary: 'Validate client with client id and redirect url' })
  @ApiResponse({
    status: 200,
    type: String,
    example: 'Valid client'
  })
  @ApiResponse({ status: 400, description: 'Bad Request'})
  @ApiResponse({ status: 401, description: 'Unauthorized'})
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  async validateClient(
    @Query() dto: ValidateClientQueryDto
  ) {
    return await this.service.validateClient(dto);
  }

  @Get(':resourceId')
  @ApiOperation({ summary: 'Returns ASP token from given Authorization Bearer header. Bearer can hold either of 2 token, (a) Appirio Service Platform JWT or (b) Auth0 JWT' })
  @ApiParam({
    name: 'resourceId',
    description: 'target id',
    required: true,
    example: '1'
  })
  @ApiQuery({
    name: 'fields',
    description: 'fields you want in response'
  })
  @ApiResponse({
    status: 200, type: AuthorizationResponse
  })
  @ApiResponse({ status: 401, description: 'Unauthorized'})
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  async getObject(
    @Req() req: Request,
    @Res() res: Response,
    @Param('resourceId') targetId: string,
    @Query('fields') fields?: string,
  ) {
    res.json(await this.service.getObject(targetId, req, res, fields));
  }

  private async handleCreateForm(data: AuthorizationForm): Promise<AuthorizationResponse> {
    return await this.service.createObjectForm(data);
  }

  private async handleCreateRequest(
    req: Request, 
    res: Response,
    data: AuthorizationCreateRequest
  ): Promise<AuthorizationResponse> {
    return await this.service.createObject(req, res, data.param);
  }
}

