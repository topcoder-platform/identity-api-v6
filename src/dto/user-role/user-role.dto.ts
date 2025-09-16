import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsInt, IsPositive } from 'class-validator';

export class ModifyUserRoleDto {
  @ApiProperty({
    description: 'Role identifier to assign to the user',
    example: 1,
  })
  @IsInt()
  @IsPositive()
  @Type(() => Number)
  roleId: number;
}
