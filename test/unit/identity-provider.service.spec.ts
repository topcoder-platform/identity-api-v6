import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, Logger } from '@nestjs/common';
import { IdentityProviderService } from '../../src/api/identity-provider/identity-provider.service';

describe('IdentityProviderService', () => {
  let service: IdentityProviderService;
  let mockPrismaClient: any;

  beforeEach(async () => {
    // Create mock Prisma client
    mockPrismaClient = {
      user_sso_login: {
        findFirst: jest.fn(),
      },
      user_social_login: {
        findFirst: jest.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IdentityProviderService,
        {
          provide: 'PRISMA_CLIENT',
          useValue: mockPrismaClient,
        },
      ],
    }).compile();

    service = module.get<IdentityProviderService>(IdentityProviderService);

    // Mock logger to avoid console output during tests
    jest.spyOn(Logger.prototype, 'log').mockImplementation();
    jest.spyOn(Logger.prototype, 'error').mockImplementation();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('fetchProviderInfo', () => {
    it('should throw BadRequestException when neither handle nor email is provided', async () => {
      await expect(service.fetchProviderInfo()).rejects.toThrow(
        new BadRequestException('handle or email required'),
      );
    });

    it('should throw BadRequestException when both handle and email are empty strings', async () => {
      await expect(service.fetchProviderInfo('', '')).rejects.toThrow(
        new BadRequestException('handle or email required'),
      );
    });

    it('should return SSO provider by SSO userId when found', async () => {
      const mockResult = {
        sso_login_provider: {
          name: 'okta',
          type: 'OIDC',
        },
      };

      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(mockResult) // First call for SSO userId
        .mockResolvedValueOnce(null); // Second call for SSO email

      const result = await service.fetchProviderInfo('sso_user_001');

      expect(result).toEqual({
        name: 'okta',
        type: 'OIDC',
      });
      expect(mockPrismaClient.user_sso_login.findFirst).toHaveBeenCalledTimes(
        1,
      );
    });

    it('should return SSO provider by SSO email when SSO userId not found', async () => {
      const mockResult = {
        sso_login_provider: {
          name: 'azure-ad',
          type: 'SAML',
        },
      };

      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockResolvedValueOnce(mockResult) // Second call for SSO email
        .mockResolvedValueOnce(null); // Third call for SSO handle

      const result = await service.fetchProviderInfo('user@example.com');

      expect(result).toEqual({
        name: 'azure-ad',
        type: 'SAML',
      });
      expect(mockPrismaClient.user_sso_login.findFirst).toHaveBeenCalledTimes(
        2,
      );
    });

    it('should return SSO provider by TC handle when previous methods fail', async () => {
      const mockResult = {
        sso_login_provider: {
          name: 'ping-identity',
          type: 'OIDC',
        },
      };

      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockResolvedValueOnce(null) // Second call for SSO email
        .mockResolvedValueOnce(mockResult) // Third call for SSO handle
        .mockResolvedValueOnce(null); // Fourth call for social userId

      const result = await service.fetchProviderInfo('testuser');

      expect(result).toEqual({
        name: 'ping-identity',
        type: 'OIDC',
      });
      expect(mockPrismaClient.user_sso_login.findFirst).toHaveBeenCalledTimes(
        3,
      );
    });

    it('should return social provider by social userId when SSO methods fail', async () => {
      const mockResult = {
        social_login_provider: {
          name: 'google',
        },
      };

      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockResolvedValueOnce(null) // Second call for SSO email
        .mockResolvedValueOnce(null); // Third call for SSO handle

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(
        mockResult,
      ); // Call for social userId

      const result = await service.fetchProviderInfo('social_user_001');

      expect(result).toEqual({
        name: 'google',
        type: 'social',
      });
      expect(mockPrismaClient.user_sso_login.findFirst).toHaveBeenCalledTimes(
        3,
      );
      expect(
        mockPrismaClient.user_social_login.findFirst,
      ).toHaveBeenCalledTimes(1);
    });

    it('should return default provider when no matches found with handle', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockResolvedValueOnce(null) // Second call for SSO email
        .mockResolvedValueOnce(null); // Third call for SSO handle

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null); // Call for social userId

      const result = await service.fetchProviderInfo('nonexistent_user');

      expect(result).toEqual({
        name: 'ldap',
        type: 'default',
      });
    });

    it('should return social provider by email when email parameter is provided', async () => {
      const mockResult = {
        social_login_provider: {
          name: 'github',
        },
      };

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(
        mockResult,
      );

      const result = await service.fetchProviderInfo(
        undefined,
        'user@example.com',
      );

      expect(result).toEqual({
        name: 'github',
        type: 'social',
      });
      expect(
        mockPrismaClient.user_social_login.findFirst,
      ).toHaveBeenCalledTimes(1);
    });

    it('should return default provider when email parameter provided but no social match found', async () => {
      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      const result = await service.fetchProviderInfo(
        undefined,
        'nonexistent@example.com',
      );

      expect(result).toEqual({
        name: 'ldap',
        type: 'default',
      });
    });

    it('should handle null provider names in SSO provider by userId', async () => {
      const mockResult = {
        sso_login_provider: {
          name: null,
          type: 'OIDC',
        },
      };

      mockPrismaClient.user_sso_login.findFirst.mockResolvedValueOnce(
        mockResult,
      );

      const result = await service.fetchProviderInfo('sso_user_001');

      expect(result).toEqual({
        name: null,
        type: 'OIDC',
      });
    });

    it('should handle null provider names in SSO provider by email', async () => {
      const mockResult = {
        sso_login_provider: {
          name: null,
          type: 'SAML',
        },
      };

      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockResolvedValueOnce(mockResult); // Second call for SSO email

      const result = await service.fetchProviderInfo('user@example.com');

      expect(result).toEqual({
        name: null,
        type: 'SAML',
      });
    });

    it('should handle null provider names in SSO provider by handle', async () => {
      const mockResult = {
        sso_login_provider: {
          name: null,
          type: 'OIDC',
        },
      };

      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockResolvedValueOnce(null) // Second call for SSO email
        .mockResolvedValueOnce(mockResult); // Third call for SSO handle

      const result = await service.fetchProviderInfo('testuser');

      expect(result).toEqual({
        name: null,
        type: 'OIDC',
      });
    });

    it('should handle null provider names in social provider by userId', async () => {
      const mockResult = {
        social_login_provider: {
          name: null,
        },
      };

      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockResolvedValueOnce(null) // Second call for SSO email
        .mockResolvedValueOnce(null); // Third call for SSO handle

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(
        mockResult,
      );

      const result = await service.fetchProviderInfo('social_user_001');

      expect(result).toEqual({
        name: null,
        type: 'social',
      });
    });

    it('should handle null provider names in social provider by email', async () => {
      const mockResult = {
        social_login_provider: {
          name: null,
        },
      };

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(
        mockResult,
      );

      const result = await service.fetchProviderInfo(
        undefined,
        'user@example.com',
      );

      expect(result).toEqual({
        name: 'unknown',
        type: 'social',
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle database error in getSSOProviderByUserId and return null', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockRejectedValueOnce(new Error('Database connection failed'))
        .mockResolvedValueOnce(null) // Second call for SSO email
        .mockResolvedValueOnce(null); // Third call for SSO handle

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      const result = await service.fetchProviderInfo('sso_user_001');

      expect(result).toEqual({
        name: 'ldap',
        type: 'default',
      });
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        'Error getting SSO provider by userId: Database connection failed',
      );
    });

    it('should handle database error in getSSOProviderByEmail and return null', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockRejectedValueOnce(new Error('Database connection failed'))
        .mockResolvedValueOnce(null); // Third call for SSO handle

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      const result = await service.fetchProviderInfo('user@example.com');

      expect(result).toEqual({
        name: 'ldap',
        type: 'default',
      });
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        'Error getting SSO provider by email: Database connection failed',
      );
    });

    it('should handle database error in getSSOProviderByHandle and return null', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockResolvedValueOnce(null) // Second call for SSO email
        .mockRejectedValueOnce(new Error('Database connection failed'));

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      const result = await service.fetchProviderInfo('testuser');

      expect(result).toEqual({
        name: 'ldap',
        type: 'default',
      });
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        'Error getting SSO provider by handle: Database connection failed',
      );
    });

    it('should handle database error in getSocialProviderByUserId and return null', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null) // First call for SSO userId
        .mockResolvedValueOnce(null) // Second call for SSO email
        .mockResolvedValueOnce(null); // Third call for SSO handle

      mockPrismaClient.user_social_login.findFirst.mockRejectedValueOnce(
        new Error('Database connection failed'),
      );

      const result = await service.fetchProviderInfo('social_user_001');

      expect(result).toEqual({
        name: 'ldap',
        type: 'default',
      });
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        'Error getting social provider by userId: Database connection failed',
      );
    });

    it('should handle database error in getSocialProviderByUserEmail and return null', async () => {
      mockPrismaClient.user_social_login.findFirst.mockRejectedValueOnce(
        new Error('Database connection failed'),
      );

      const result = await service.fetchProviderInfo(
        undefined,
        'user@example.com',
      );

      expect(result).toEqual({
        name: 'ldap',
        type: 'default',
      });
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        'Error getting social provider by email: Database connection failed',
      );
    });

    it('should handle multiple database errors and return default provider', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockRejectedValueOnce(new Error('SSO database error'))
        .mockRejectedValueOnce(new Error('SSO database error'))
        .mockRejectedValueOnce(new Error('SSO database error'));

      mockPrismaClient.user_social_login.findFirst.mockRejectedValueOnce(
        new Error('Social database error'),
      );

      const result = await service.fetchProviderInfo('test_user');

      expect(result).toEqual({
        name: 'ldap',
        type: 'default',
      });
      expect(Logger.prototype.error).toHaveBeenCalledTimes(4);
    });
  });

  describe('Query Parameters', () => {
    it('should call findFirst with correct parameters for SSO userId query', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      await service.fetchProviderInfo('sso_user_001');

      expect(mockPrismaClient.user_sso_login.findFirst).toHaveBeenNthCalledWith(
        1,
        {
          where: {
            sso_user_id: 'sso_user_001',
          },
          select: {
            sso_login_provider: {
              select: {
                name: true,
                type: true,
              },
            },
          },
        },
      );
    });

    it('should call findFirst with correct parameters for SSO email query', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      await service.fetchProviderInfo('user@example.com');

      expect(mockPrismaClient.user_sso_login.findFirst).toHaveBeenNthCalledWith(
        2,
        {
          where: {
            email: {
              equals: 'user@example.com',
              mode: 'insensitive',
            },
            sso_login_provider: {
              identify_email_enabled: true,
            },
          },
          select: {
            sso_login_provider: {
              select: {
                name: true,
                type: true,
              },
            },
          },
        },
      );
    });

    it('should call findFirst with correct parameters for SSO handle query', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      await service.fetchProviderInfo('testuser');

      expect(mockPrismaClient.user_sso_login.findFirst).toHaveBeenNthCalledWith(
        3,
        {
          where: {
            user: {
              handle: 'testuser',
            },
            sso_login_provider: {
              identify_handle_enabled: true,
            },
          },
          select: {
            sso_login_provider: {
              select: {
                name: true,
                type: true,
              },
            },
          },
        },
      );
    });

    it('should call findFirst with correct parameters for social userId query', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      await service.fetchProviderInfo('social_user_001');

      expect(mockPrismaClient.user_social_login.findFirst).toHaveBeenCalledWith(
        {
          where: {
            social_user_name: 'social_user_001',
          },
          select: {
            social_login_provider: {
              select: {
                name: true,
              },
            },
          },
        },
      );
    });

    it('should call findFirst with correct parameters for social email query', async () => {
      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      await service.fetchProviderInfo(undefined, 'user@example.com');

      expect(mockPrismaClient.user_social_login.findFirst).toHaveBeenCalledWith(
        {
          where: {
            social_email: {
              equals: 'user@example.com',
              mode: 'insensitive',
            },
          },
          select: {
            social_login_provider: {
              select: {
                name: true,
              },
            },
          },
        },
      );
    });
  });

  describe('Logging', () => {
    it('should log when fetchProviderInfo is called', async () => {
      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      await service.fetchProviderInfo('test_user');

      expect(Logger.prototype.log).toHaveBeenCalledWith(
        'fetchProviderInfo called',
      );
      expect(Logger.prototype.log).toHaveBeenCalledWith('handle: test_user');
    });

    it('should log email parameter when provided', async () => {
      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(null);

      await service.fetchProviderInfo(undefined, 'user@example.com');

      expect(Logger.prototype.log).toHaveBeenCalledWith(
        'fetchProviderInfo called',
      );
      expect(Logger.prototype.log).toHaveBeenCalledWith(
        'email: user@example.com',
      );
    });
  });

  describe('Edge Cases', () => {
    it('should handle undefined provider name in SSO result', async () => {
      const mockResult = {
        sso_login_provider: {
          name: undefined,
          type: 'OIDC',
        },
      };

      mockPrismaClient.user_sso_login.findFirst.mockResolvedValueOnce(
        mockResult,
      );

      const result = await service.fetchProviderInfo('sso_user_001');

      expect(result).toEqual({
        name: undefined,
        type: 'OIDC',
      });
    });

    it('should handle undefined provider name in social result', async () => {
      const mockResult = {
        social_login_provider: {
          name: undefined,
        },
      };

      mockPrismaClient.user_sso_login.findFirst
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(
        mockResult,
      );

      const result = await service.fetchProviderInfo('social_user_001');

      expect(result).toEqual({
        name: undefined,
        type: 'social',
      });
    });

    it('should handle empty string provider name in SSO result', async () => {
      const mockResult = {
        sso_login_provider: {
          name: '',
          type: 'OIDC',
        },
      };

      mockPrismaClient.user_sso_login.findFirst.mockResolvedValueOnce(
        mockResult,
      );

      const result = await service.fetchProviderInfo('sso_user_001');

      expect(result).toEqual({
        name: '',
        type: 'OIDC',
      });
    });

    it('should handle empty string provider name in social result', async () => {
      const mockResult = {
        social_login_provider: {
          name: '',
        },
      };

      mockPrismaClient.user_social_login.findFirst.mockResolvedValueOnce(
        mockResult,
      );

      const result = await service.fetchProviderInfo(
        undefined,
        'user@example.com',
      );

      expect(result).toEqual({
        name: 'unknown',
        type: 'social',
      });
    });
  });
});
