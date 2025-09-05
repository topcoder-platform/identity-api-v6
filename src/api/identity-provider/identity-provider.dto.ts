import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional } from 'class-validator';

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
