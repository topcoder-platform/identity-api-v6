import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsNotEmpty,
  IsDefined,
  ValidateNested,
  IsOptional,
  IsString,
} from 'class-validator';
import { IsInt } from 'class-validator';
import { MembershipType } from '../../api/group/membership-type.enum';

export class GroupMembershipResponseDto {
  id: number;
  groupId: number;
  memberId: number;
  membershipType: string;
  createdBy: number;
  createdAt: Date;
  modifiedBy: number;
  modifiedAt: Date;
}

export class GroupMemberDto {
  @ApiProperty({
    description: 'The ID of the group.',
    example: 10,
  })
  @IsNotEmpty()
  @IsInt()
  groupId: number;

  @ApiProperty({
    description: 'The name of the group.',
    example: 'Admin Group',
  })
  @IsOptional()
  @IsString()
  groupName?: string;

  @ApiProperty({
    description: 'The ID of the member (user or another group) to add.',
    example: 101,
  })
  @IsNotEmpty()
  @IsInt()
  memberId: number;

  @ApiProperty({
    description: 'The type of membership (e.g., "user" or "group").',
    example: 'user',
  })
  @IsOptional()
  @IsString()
  membershipType?: MembershipType | string;

  createdBy: String;
  createdAt: Date;
}

export class GroupMemberBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => GroupMemberDto) // Contains userId
  param: GroupMemberDto;
}

export class GroupMembershipBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => GroupMembershipResponseDto) // Contains userId
  param: GroupMembershipResponseDto;
}
