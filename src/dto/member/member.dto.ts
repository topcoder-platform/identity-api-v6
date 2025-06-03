import { ApiProperty } from '@nestjs/swagger';
import { IsInt, IsString, IsEmail } from 'class-validator';

// Interface defining the shape of member info
export interface MemberInfoDto {
  userId: number;
  handle: string;
  email: string;
  // Add other relevant fields from the actual Member API response if needed
}

// Class implementing the interface, suitable for use in Swagger/validation decorators
export class MemberInfoResponseDto implements MemberInfoDto {
  @ApiProperty({ description: 'User ID', example: 12345 })
  @IsInt()
  userId: number;

  @ApiProperty({ description: 'User handle', example: 'user123' })
  @IsString()
  handle: string;

  @ApiProperty({ description: 'User email', example: 'user123@example.com' })
  @IsEmail()
  email: string;
}
