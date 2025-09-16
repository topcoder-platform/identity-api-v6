import { SetMetadata } from '@nestjs/common';

export const SELF_OR_ADMIN_PARAM_KEY = 'selfOrAdmin:paramKeys';

// Provide one or more param names that can hold the target user id.
// If omitted, defaults to ['resourceId','userId']
export const SelfOrAdmin = (...paramKeys: string[]) =>
  SetMetadata(
    SELF_OR_ADMIN_PARAM_KEY,
    paramKeys && paramKeys.length ? paramKeys : ['resourceId', 'userId'],
  );
