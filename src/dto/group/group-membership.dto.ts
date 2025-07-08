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
  @ApiProperty({ name: 'id', description: 'membership id', type: Number })
  id: number;
  @ApiProperty({ name: 'groupId', description: 'groupId', type: Number })
  groupId: number;
  @ApiProperty({ name: 'memberId', description: 'memberId', type: Number })
  memberId: number;
  @ApiProperty({
    name: 'membershipType',
    description: 'membershipType',
    type: Number,
  })
  membershipType: string;
  @ApiProperty({ name: 'createdBy', description: 'createdBy', type: Number })
  createdBy: number;
  @ApiProperty({ name: 'createdAt', description: 'createdAt', type: Date })
  createdAt: Date;
  @ApiProperty({ name: 'modifiedBy', description: 'modifiedBy', type: Number })
  modifiedBy: number;
  @ApiProperty({ name: 'modifiedAt', description: 'modifiedAt', type: Date })
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

  createdBy: string;
  createdAt: Date;
}

export class GroupMemberBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => GroupMemberDto) // Contains userId
  @ApiProperty({
    name: 'param',
    description: 'request parameters',
    type: GroupMemberDto,
  })
  param: GroupMemberDto;
}

export class GroupMembershipBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => GroupMembershipResponseDto) // Contains userId
  @ApiProperty({
    name: 'param',
    description: 'request parameters',
    type: GroupMembershipResponseDto,
  })
  param: GroupMembershipResponseDto;
}
