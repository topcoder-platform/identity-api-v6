/** Legacy member workflow/fixture payload type; never used to validate credentials. */
export interface JwtPayload {
  // Common
  iss?: string;
  sub?: string;
  aud?: string | string[];
  iat?: number;
  exp?: number;
  gty?: string;
  // From HS256 examples
  userId?: string;
  roles?: string[];
  handle?: string;
  email?: string;
  jti?: string;
  // From RS256 examples (Auth0)
  azp?: string;
  scope?: string;
  permissions?: string[];
}

/** Identity API view of a shared-core principal. Member IDs retain the existing
 * string representation; service identities never receive a member ID or roles.
 * Optional kind/payload support internal member workflows, not token validation.
 */
export interface AuthenticatedUser {
  kind?: 'user' | 'service';
  userId?: string;
  clientId?: string;
  roles: string[];
  scopes: string[];
  isAdmin: boolean;
  isMachine: boolean;
  handle?: string;
  email?: string;
  payload?: JwtPayload;
}
