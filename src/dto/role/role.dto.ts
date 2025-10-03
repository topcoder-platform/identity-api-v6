import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
  IsInt,
  IsOptional,
  IsDateString,
  IsArray,
  ValidateNested,
  IsPositive,
  IsIn,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';
import { MemberInfoResponseDto } from '../member/member.dto';
import { Constants } from '../../core/constant/constants';

// Input DTO for the nested 'param' object in POST/PUT requests, matching swagger Role definition
class RoleParamDto {
  @ApiProperty({
    description: 'The name of the role',
    example: 'Administrator',
    maxLength: 45,
    minLength: 3,
  })
  @IsNotEmpty()
  @IsString()
  @MaxLength(45)
  @MinLength(3)
  roleName: string;

  // Note: The old API definition includes 'subjects' here, but Java code suggests
  // assignments are handled separately. Keeping roleName only for compatibility.
}

// DTO for POST /roles request body, matching swagger NewRoleBodyParam
export class CreateRoleBodyDto {
  @ApiProperty({ type: RoleParamDto })
  @IsNotEmpty()
  @ValidateNested()
  @Type(() => RoleParamDto)
  param: RoleParamDto;
}

// DTO for PUT /roles/{roleId} request body, matching swagger NewRoleBodyParam
export class UpdateRoleBodyDto {
  @ApiProperty({ type: RoleParamDto })
  @IsNotEmpty()
  @ValidateNested()
  @Type(() => RoleParamDto)
  param: RoleParamDto;
}

// Response DTO matching swagger RoleResponse definition
export class RoleResponseDto {
  @ApiProperty({ description: 'Role ID', example: 123 })
  @IsInt()
  @IsPositive()
  id: number;

  @ApiProperty({
    description: 'Creation timestamp',
    example: '2023-01-01T12:00:00.000Z',
  })
  @IsDateString()
  createdAt: string;

  @ApiProperty({
    description: 'ID of the user who created the role',
    example: 1001,
  })
  @IsInt() // Assuming integer based on swagger format: integer
  createdBy: number;

  @ApiProperty({
    description: 'Last update timestamp',
    example: '2023-01-02T15:30:00.000Z',
  })
  @IsDateString()
  updatedAt: string;

  @ApiProperty({
    description: 'ID of the user who last updated the role',
    example: 1002,
  })
  @IsInt() // Assuming integer based on updatedBy type in swagger
  updatedBy: number;

  @ApiProperty({
    description: 'The name of the role',
    example: 'Administrator',
  })
  @IsString()
  roleName: string;

  @ApiPropertyOptional({
    description:
      'List of subjects assigned to the role (included based on `fields` query)',
    type: () => [MemberInfoResponseDto],
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => MemberInfoResponseDto)
  subjects?: MemberInfoResponseDto[];
}

// Represents a RoleAssignment record, useful for responses
export class RoleAssignmentResponseDto {
  @ApiProperty({ description: 'Assignment ID', example: 1 })
  @IsInt()
  @IsPositive()
  id: number;

  @ApiProperty({ description: 'Role ID', example: 101 })
  @IsInt()
  @IsPositive()
  roleId: number;

  @ApiProperty({ description: 'Subject ID (User/Group ID)', example: 12345 })
  @IsInt()
  @IsPositive()
  subjectId: number;

  @ApiProperty({ description: 'Subject Type (1=User, 2=Group)', example: 1 })
  @IsInt()
  @IsIn([1, 2])
  subjectType: number;

  @ApiProperty({
    description: 'Creation timestamp',
    example: '2023-01-01T12:00:00.000Z',
  })
  @IsDateString()
  createdAt: string;

  @ApiProperty({
    description: 'ID of the user who created the assignment',
    example: 1001,
  })
  @IsInt()
  createdBy: number;

  @ApiProperty({
    description: 'Last update timestamp',
    example: '2023-01-02T15:30:00.000Z',
  })
  @IsDateString()
  modifiedAt: string;

  @ApiProperty({
    description: 'ID of the user who last updated the assignment',
    example: 1002,
  })
  @IsInt()
  modifiedBy: number;
}

// Query params for listing role members (subjects)
export class RoleMembersQueryDto {
  @ApiPropertyOptional({ description: 'Filter by numeric user id', example: 12345 })
  @IsOptional()
  @IsInt()
  @Type(() => Number)
  userId?: number;

  @ApiPropertyOptional({ description: 'Filter by Topcoder handle (exact match)', example: 'someuser' })
  @IsOptional()
  @IsString()
  userHandle?: string;

  @ApiPropertyOptional({ description: 'Filter by email (exact match)', example: 'user@example.com' })
  @IsOptional()
  @IsString()
  email?: string;

  @ApiPropertyOptional({ description: 'Page number (starts at 1)', example: 1 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Type(() => Number)
  page?: number = 1;

  @ApiPropertyOptional({ description: 'Items per page', example: 25 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Type(() => Number)
  perPage?: number = Constants.defaultPageSize;
}

// --- NEW DTO ---
export class RoleQueryDto {
  @ApiPropertyOptional({
    description:
      "Filter criteria (e.g., 'subjectId=12345'). Used by findAll to get roles for a specific subject.",
    example: 'subjectId=12345',
  })
  @IsOptional()
  @IsString()
  filter?: string;

  // Add other potential query params like 'selector' if needed
  @ApiPropertyOptional({
    description: "Comma-separated list of fields to include (e.g., 'subjects')",
    example: 'subjects',
  })
  @IsOptional()
  @IsString()
  selector?: string;
}
