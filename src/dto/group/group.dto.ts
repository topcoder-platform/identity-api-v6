import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsInt,
  IsOptional,
  IsString,
  ValidateNested,
  IsDefined,
  IsNotEmpty,
  IsNumber,
  Length,
} from 'class-validator';
import { Type } from 'class-transformer';

export class GroupDto {
  @IsOptional()
  @IsInt()
  @ApiPropertyOptional({ name: 'id', description: 'group id', type: 'number' })
  id?: number;

  @IsString()
  @Length(2, 50, {
    message: 'Length of Name in character should be between 2 and 50',
  })
  @ApiProperty({ name: 'name', description: 'group name', type: String })
  name: string;

  @IsOptional()
  @IsString()
  @Length(2, 50, {
    message: 'Length of Name in character should be between 2 and 50',
  })
  @ApiPropertyOptional({
    name: 'description',
    description: 'group description',
    type: String,
  })
  description?: string;

  @IsOptional()
  @IsBoolean()
  @ApiPropertyOptional({
    name: 'privateGroup',
    description: 'is private group?',
    type: Boolean,
  })
  privateGroup?: boolean = true;

  @IsOptional()
  @IsBoolean()
  @ApiPropertyOptional({
    name: 'selfRegister',
    description: 'Can user self register this group?',
    type: Boolean,
  })
  selfRegister?: boolean = false;

  @IsOptional()
  @IsInt()
  createdBy?: string;

  @IsOptional()
  @Type(() => Date)
  createdAt?: Date;

  @IsOptional()
  @IsInt()
  modifiedBy?: string;

  @IsOptional()
  @Type(() => Date)
  modifiedAt?: Date;
}

export class GroupBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => GroupDto)
  @ApiProperty({ name: 'param', description: 'request params' })
  param: GroupDto;
}

export class GroupResponseDto {
  @ApiProperty({ name: 'id', description: 'group id', type: Number })
  id: number;
  @ApiProperty({ name: 'name', description: 'group name', type: String })
  name: string;
  @ApiPropertyOptional({
    name: 'description',
    description: 'group description',
    type: String,
  })
  description?: string;
  @ApiProperty({
    name: 'privateGroup',
    description: 'Is this group private?',
    type: Boolean,
  })
  privateGroup: boolean;
  @ApiProperty({
    name: 'selfRegister',
    description: 'Can user self register this group?',
    type: Boolean,
  })
  selfRegister: boolean;
  @ApiPropertyOptional({
    name: 'createdBy',
    description: 'createdBy',
    type: Number,
  })
  createdBy?: number;
  @ApiProperty({ name: 'createdAt', description: 'createdAt', type: Date })
  createdAt?: Date;
  @ApiProperty({ name: 'modifiedBy', description: 'modifiedBy', type: Number })
  modifiedBy?: number;
  @ApiProperty({ name: 'modifiedAt', description: 'modifiedAt', type: Date })
  modifiedAt?: Date;
  @ApiPropertyOptional({
    name: 'parentGroup',
    description: 'parent group if any',
    type: GroupResponseDto,
  })
  parentGroup?: GroupResponseDto;
  @ApiProperty({
    name: 'subGroups',
    description: 'sub Groups if any',
    type: [GroupResponseDto],
  })
  subGroups?: GroupResponseDto[];
}

export class SecurityGroups {
  @IsNumber({}, { message: 'ID must be a number' })
  @ApiProperty({ name: 'id', type: Number, description: 'security group id' })
  id: number;

  @IsNotEmpty({ message: 'Name is mandatory' })
  @Length(2, 50, {
    message: 'Length of Name should be between 2 and 50 characters',
  })
  @ApiProperty({
    name: 'name',
    type: String,
    description: 'security group name',
  })
  name: string;

  @IsNumber({}, { message: 'Create User ID must be a number' })
  @ApiProperty({
    name: 'createuserId',
    type: Number,
    description: 'security group create user Id',
  })
  createuserId: number;
}

export class SecurityBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => SecurityGroups)
  @ApiProperty({
    name: 'param',
    type: SecurityGroups,
    description: 'request params',
  })
  param: SecurityGroups;
}

export class SecurityGroupsResponseDto {
  @ApiProperty({
    name: 'securityGroups',
    type: SecurityGroups,
    description: 'security group data',
  })
  securityGroups: SecurityGroups;
}
