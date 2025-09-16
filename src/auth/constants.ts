export const SCOPES = {
  WRITE_ROLES: 'write:roles',
  READ_ROLES: 'read:roles',
  ALL_ROLES: 'all:roles',
  CREATE_ROLE: 'create:role',
  UPDATE_ROLE: 'update:role',
  DELETE_ROLE: 'delete:role',
  READ_USERS_ROLE: 'read:usersRole',
  CREATE_USERS_ROLE: 'create:usersRole',
  UPDATE_USERS_ROLE: 'update:usersRole',
  DELETE_USERS_ROLE: 'delete:usersRole',
  ALL_USERS_ROLE: 'all:usersRole',
  READ_TOPGEAR_USER_ROLES: 'read:topgear-user-roles',
  WRITE_TOPGEAR_USER_ROLES: 'write:topgear-user-roles',
  ALL_TOPGEAR_USER_ROLES: 'all:topgear-user-roles',
  READ_USER: 'read:user',
  ALL_USERS: 'all:user',
};

export const ADMIN_ROLE = process.env.ADMIN_ROLE_NAME || 'administrator';
export const COPILOT_ROLE = 'Copilot';
