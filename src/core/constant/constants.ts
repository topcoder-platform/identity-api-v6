export const Constants = {
  memberGroupMembershipType: 1,
  subGroupMembershipType: 2,

  memberGroupMembershipName: 'user',
  subGroupMembershipName: 'group',

  AdminRoles: ['administrator'],

  // default values in authorization service
  defaultTargetId: '1',
  defaultRedirectUrl: 'https://www.topcoder.com',
  defaultAuthStateLength: 12,

  // default subjectType in roleAssignment for members
  memberSubjectType: 1,

  // auth0 token "sub" field prefix
  auth0SubPrefix: 'auth0|',

  // flag to remember token. Search request header with this key.
  rememberMeFlag: 'rememberme',

  // jwt digest algorithm. Can be HS256 or RS256.
  jwtRs256Algorithm: 'RS256',
  jwtHs256Algorithm: 'HS256',

  // cookie names used to set token and sso
  tcJwtCookieName: 'tcjwt',
  tcSsoCookieName: 'tcsso',
  tcV3JwtCookieName: 'v3jwt',

  // default page size
  defaultPageSize: 20,

  // values used in email table
  primaryEmailFlag: 1,
  standardEmailType: 1,
  verifiedEmailStatus: 1,
  unverifiedEmailStatus: 2,

  // prisma error code
  prismaUniqueConflictcode: 'P2002',
  prismaNotFoundCode: 'P2025',

  // password validation
  MAX_LENGTH_PASSWORD: 64,
  MIN_LENGTH_PASSWORD: 8,
  PASSWORD_HAS_LETTER_REGEX: /[A-Za-z]/,
  PASSWORD_HAS_SYMBOL_REGEX: /\\p{P}/,
  PASSWORD_HAS_DIGIT_REGEX: /\d/,

  ALPHABET_ALPHA_EN: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',

  ALPHABET_DIGITS_EN: '0123456789',

  MIN_LENGTH_HANDLE: 3,
  MAX_LENGTH_HANDLE: 64,

  HANDLE_PUNCTUATION: '-_.{}[]',

  MAX_LENGTH_FIRST_NAME: 64,
  MAX_LENGTH_LAST_NAME: 64,
  MAX_LENGTH_EMAIL: 100,

  // user_group_xref
  DEFAULT_CREATE_USER_ID: 1,
  DEFAULT_SECURITY_STATUS_ID: 1,
};

export const MachineScopes = {
  readScopes: ['read:user_profiles', 'all:user_profiles'],
  createScopes: ['create:user_profiles', 'all:user_profiles'],
  deleteScopes: ['delete:user_profiles', 'all:user_profiles'],
  updateScopes: ['update:user_profiles', 'all:user_profiles'],
};

export enum DefaultGroups {
  MANAGER = 2,
  CODERS = 10,
  LEVEL_TWO_ADMINS = 14,
  ANONYMOUS = 2000118,
}
