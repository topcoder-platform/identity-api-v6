// src/core/constants/provider-type.enum.ts
export enum ProviderId {
  FACEBOOK = 1,
  GOOGLE = 2,
  TWITTER = 3,
  GITHUB = 4,
  SFDC = 5, // Assuming SFDC maps to a specific string like 'salesforce' if needed for comparison
  OKTA = 6,
  DRIBBBLE = 10,
  BEHANCE = 11,
  STACKOVERFLOW = 12,
  LINKEDIN = 13,
  BITBUCKET = 14,
  LDAP = 101,
  SAMLP = 102,
  ADFS = 103,
  AUTH0 = 200,
}

export interface ProviderDetails {
  id: ProviderId;
  key: string; // The string identifier like 'google-oauth2'
  isSocial: boolean;
  isEnterprise: boolean;
  nameKey?: string; // Java code had 'screen_name', 'username'
}

export const ProviderTypes: Record<string, ProviderDetails> = {
  facebook: {
    id: ProviderId.FACEBOOK,
    key: 'facebook',
    isSocial: true,
    isEnterprise: false,
  },
  'okta-customer':{
    id: ProviderId.OKTA,
    key: 'okta-customer',
    isSocial: false,
    isEnterprise: true,
  },
  'google-oauth2': {
    id: ProviderId.GOOGLE,
    key: 'google-oauth2',
    isSocial: true,
    isEnterprise: false,
  },
  google: {
    id: ProviderId.GOOGLE,
    key: 'google-oauth2',
    isSocial: true,
    isEnterprise: false,
  }, // Alias
  twitter: {
    id: ProviderId.TWITTER,
    key: 'twitter',
    isSocial: true,
    isEnterprise: false,
    nameKey: 'screen_name',
  },
  github: {
    id: ProviderId.GITHUB,
    key: 'github',
    isSocial: true,
    isEnterprise: false,
  },
  sfdc: {
    id: ProviderId.SFDC,
    key: 'sfdc',
    isSocial: true,
    isEnterprise: false,
  }, // Salesforce
  dribbble: {
    id: ProviderId.DRIBBBLE,
    key: 'dribbble',
    isSocial: true,
    isEnterprise: false,
    nameKey: 'username',
  },
  behance: {
    id: ProviderId.BEHANCE,
    key: 'behance',
    isSocial: true,
    isEnterprise: false,
    nameKey: 'username',
  },
  stackoverflow: {
    id: ProviderId.STACKOVERFLOW,
    key: 'stackoverflow',
    isSocial: true,
    isEnterprise: false,
    nameKey: 'username',
  },
  linkedin: {
    id: ProviderId.LINKEDIN,
    key: 'linkedin',
    isSocial: true,
    isEnterprise: false,
  },
  bitbucket: {
    id: ProviderId.BITBUCKET,
    key: 'bitbucket',
    isSocial: true,
    isEnterprise: false,
    nameKey: 'username',
  },
  ad: { id: ProviderId.LDAP, key: 'ad', isSocial: false, isEnterprise: true }, // LDAP
  samlp: {
    id: ProviderId.SAMLP,
    key: 'samlp',
    isSocial: false,
    isEnterprise: true,
  },
  adfs: {
    id: ProviderId.ADFS,
    key: 'adfs',
    isSocial: false,
    isEnterprise: true,
  },
  // Topcoder SSO shorthand used in some payloads
  tc: {
    id: ProviderId.SAMLP,
    key: 'tc',
    isSocial: false,
    isEnterprise: true,
  },
  auth0: {
    id: ProviderId.AUTH0,
    key: 'auth0',
    isSocial: false,
    isEnterprise: false,
  },
};

export function getProviderDetails(
  providerKey: string,
): ProviderDetails | undefined {
  return ProviderTypes[providerKey.toLowerCase()];
}
