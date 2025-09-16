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

  MAX_LENGTH_PASSWORD: 64,

  MIN_LENGTH_PASSWORD: 8,

  ALPHABET_ALPHA_EN: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',

  ALPHABET_DIGITS_EN: '0123456789',

  MIN_LENGTH_HANDLE: 3,
  MAX_LENGTH_HANDLE: 64,

  HANDLE_PUNCTUATION: '-_.{}[]',
};
