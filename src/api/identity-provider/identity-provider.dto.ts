import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNumber, IsOptional, IsString } from 'class-validator';

// --- IdentityProvider Response DTO ---

export class IdentityProviderDto {
  @ApiPropertyOptional({
    description: 'Name of the identity provider',
    example: 'ldap',
  })
  @IsString()
  name: string;

  @ApiPropertyOptional({
    description: 'Type of the identity provider',
    example: 'default',
  })
  @IsString()
  type: string;
}

// --- Query Parameters DTO ---

export class IdentityProviderQueryDto {
  @ApiPropertyOptional({
    description: 'Filter by handle',
    example: 'johndoe',
  })
  @IsOptional()
  @IsString()
  handle?: string;

  @ApiPropertyOptional({
    description: 'Filter by email',
    example: 'john@example.com',
  })
  @IsOptional()
  @IsString()
  email?: string;
}

// --- SSO Providers List DTO ---

export class SsoLoginProviderDto {
  @ApiProperty({ description: 'Provider id', example: 102 })
  @IsNumber()
  ssoLoginProviderId: number;

  @ApiProperty({ description: 'Provider name', example: 'okta-customer' })
  @IsString()
  name: string;

  @ApiProperty({ description: 'Provider type', example: 'samlp' })
  @IsString()
  type: string;
}
