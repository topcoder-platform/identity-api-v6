import {
  Controller,
  Get,
  Query,
  Logger,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiQuery } from '@nestjs/swagger';
import { IdentityProviderService } from './identity-provider.service';
import {
  IdentityProviderDto,
  IdentityProviderQueryDto,
  SsoLoginProviderDto,
} from './identity-provider.dto';
import {
  BaseResponse,
  createBaseResponse,
} from '../../shared/util/responseBuilder';
import { describeAccess } from '../../shared/swagger/access-description.util';

@ApiTags('identity-providers')
@Controller('identityproviders')
export class IdentityProviderController {
  private readonly logger = new Logger(IdentityProviderController.name);

  constructor(
    private readonly identityProviderService: IdentityProviderService,
  ) {}

  /**
   * Return Identity Provider of a user
   * @param query Query parameters containing handle or email
   * @returns IdentityProviderDto
   */
  @Get()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Fetch identity provider information for a user',
    description: describeAccess({
      summary:
        'Returns identity provider information for a user identified by handle or email.',
      jwt: 'Not required (public endpoint).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiQuery({
    name: 'handle',
    required: false,
    type: String,
    description: 'User handle to search for',
  })
  @ApiQuery({
    name: 'email',
    required: false,
    type: String,
    description: 'User email to search for',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Identity provider information retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        version: { type: 'string' },
        result: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            status: { type: 'number' },
            metadata: { type: 'object' },
            content: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                type: { type: 'string' },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Bad request - handle or email required',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async fetchProviderInfo(
    @Query() query: IdentityProviderQueryDto,
  ): Promise<BaseResponse<IdentityProviderDto>> {
    this.logger.log('fetchProviderInfo called');

    const { handle, email } = query;

    const result = await this.identityProviderService.fetchProviderInfo(
      handle,
      email,
    );
    return createBaseResponse(result);
  }

  /**
   * Return list of SSO login providers
   */
  @Get('sso-providers')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'List SSO login providers',
    description: describeAccess({
      summary: 'Returns all SSO providers from the database.',
      jwt: 'Not required (public endpoint).',
      m2m: 'Not applicable.',
    }),
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of SSO providers',
    type: [SsoLoginProviderDto],
  })
  async listSsoProviders(): Promise<SsoLoginProviderDto[]> {
    this.logger.log('listSsoProviders called');
    return this.identityProviderService.listSsoLoginProviders();
  }
}
