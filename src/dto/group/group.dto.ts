import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsInt,
  IsOptional,
  IsString,
  MaxLength,
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
  id?: number;

  @IsString()
  @Length(2, 50, {
    message: 'Length of Name in character should be between 2 and 50',
  })
  name: string;

  @IsOptional()
  @IsString()
  @Length(2, 50, {
    message: 'Length of Name in character should be between 2 and 50',
  })
  description?: string;

  @IsOptional()
  @IsBoolean()
  privateGroup?: boolean = true;

  @IsOptional()
  @IsBoolean()
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
  param: GroupDto;
}

export class GroupResponseDto {
  id: number;
  name: string;
  description?: string;
  privateGroup: boolean;
  selfRegister: boolean;
  createdBy?: number;
  createdAt?: Date;
  modifiedBy?: number;
  modifiedAt?: Date;
  parentGroup?: GroupResponseDto;
  subGroups?: GroupResponseDto[];
}

export class SecurityGroups {
  @IsNumber({}, { message: 'ID must be a number' })
  id: number;

  @IsNotEmpty({ message: 'Name is mandatory' })
  @Length(2, 50, {
    message: 'Length of Name should be between 2 and 50 characters',
  })
  name: string;

  @IsNumber({}, { message: 'Create User ID must be a number' })
  createuserId: number;
}

export class SecurityBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => SecurityGroups)
  param: SecurityGroups;
}

export class SecurityGroupsResponseDto {
  securityGroups: SecurityGroups;
}
