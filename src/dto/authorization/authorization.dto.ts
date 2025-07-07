import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform, Type } from 'class-transformer';
import {
  IsNotEmpty,
  IsOptional,
  IsString,
  ValidateNested,
} from 'class-validator';

export class GetTokenQueryDto {
  @ApiProperty({
    name: 'code',
    description: 'authorization code',
  })
  @IsOptional()
  @IsString()
  code?: string;

  @ApiProperty({
    name: 'redirectUrl',
    description: 'Redirect Url',
  })
  @IsOptional()
  @IsString()
  redirectUrl?: string;

  @ApiProperty({
    name: 'state',
    description: 'state string generated in login request',
  })
  @IsOptional()
  @IsString()
  state?: string;

  @ApiPropertyOptional({
    name: 'error',
    description: 'error message from auth0 if any',
  })
  @IsOptional()
  @IsString()
  error?: string;
}

export class Auth0Credential {
  id_token: string;
  access_token: string;
  refresh_token: string | null;
  token_type: string;
  expires_in: number;
}

export class AuthorizationCreateDto {
  @ApiPropertyOptional({ description: 'authorization id' })
  @IsString()
  @IsOptional()
  id?: string;

  @ApiProperty({
    description: 'token',
  })
  @IsOptional()
  @IsString()
  token?: string;

  @ApiProperty({
    description: 'refresh token',
  })
  @IsOptional()
  @IsString()
  refreshToken?: string;

  @ApiProperty({
    description: 'target',
  })
  @IsOptional()
  @IsString()
  target?: string;

  @ApiProperty({
    description: 'external token',
  })
  @IsOptional()
  @IsString()
  externalToken?: string;

  @ApiPropertyOptional({
    name: 'zendesk jwt',
    description: 'jwt to access zendesk',
  })
  @IsOptional()
  @IsString()
  zendeskJwt?: string;
}

export class AuthorizationCreateRequest {
  @ApiProperty({
    description: 'request parameter',
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => AuthorizationCreateDto)
  param?: AuthorizationCreateDto;
}

export class AuthorizationForm {
  @ApiProperty({
    description: 'client id',
  })
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => {
    value.trim();
  })
  clientId: string;

  @ApiProperty({
    description: 'client secret',
  })
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => {
    value.trim();
  })
  secret: string;
}

export class AuthorizationResponse extends AuthorizationCreateDto {
  @ApiProperty({ description: 'authorization modifiedBy' })
  modifiedBy?: string;
  @ApiProperty({ description: 'authorization modifiedAt' })
  modifiedAt?: Date;
  @ApiProperty({ description: 'authorization createdBy' })
  createdBy?: string;
  @ApiProperty({ description: 'authorization createdAt' })
  createdAt?: Date;
}

export class ValidateClientQueryDto {
  @ApiProperty({
    name: 'clientId',
    description: 'client id',
    required: true,
  })
  @IsString()
  @IsNotEmpty()
  clientId: string;

  @ApiProperty({
    name: 'redirectUrl',
    description: 'Redirect Url',
    required: true,
  })
  @IsString()
  @IsNotEmpty()
  redirectUrl: string;

  @ApiPropertyOptional({
    name: 'scope',
    description: 'This parameter is not used for now',
  })
  @IsOptional()
  @IsString()
  scope?: string;
}
