import { ZendeskAuthPlugin } from './zendesk.service';
import { ConfigurationService } from '../../config/configuration.service';
import { AuthorizationResponse } from '../../dto/authorization/authorization.dto';
import { CommonUtils } from '../../shared/util/common.utils';
import { v4 as uuidv4 } from 'uuid';

jest.mock('../../shared/util/common.utils');
jest.mock('uuid');

describe('ZendeskAuthPlugin', () => {
  let plugin: ZendeskAuthPlugin;
  let mockConfigService;
  const mockJwt = 'mock.jwt.token';

  beforeEach(() => {
    jest.clearAllMocks();
    mockConfigService = {
      getZendesk: jest.fn().mockReturnValue({
        secret: 'test-secret',
        idPrefix: 'dev'
      })
    };

    // Mock CommonUtils methods
    (CommonUtils.parseJWTClaims as jest.Mock).mockImplementation((token) => {
      if (token === 'valid-token') {
        return { userId: '123', email: 'user@example.com', handle: 'testuser' };
      }
      return {};
    });
    (CommonUtils.generateJwt as jest.Mock).mockReturnValue(mockJwt);

    // Mock uuid
    (uuidv4 as jest.Mock).mockReturnValue('mock-uuid');

    plugin = new ZendeskAuthPlugin(mockConfigService as ConfigurationService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('process', () => {
    it('should return original auth when missing required claims', async () => {
      (CommonUtils.parseJWTClaims as jest.Mock).mockReturnValueOnce({});
      const authResponse: AuthorizationResponse = { token: 'invalid-token' };

      const result = await plugin.process(authResponse);

      expect(result).toBe(authResponse);
      expect(result.zendeskJwt).toBeUndefined();
    });

    it('should generate Zendesk JWT when all required claims are present', async () => {
      const authResponse: AuthorizationResponse = { token: 'valid-token' };

      const result = await plugin.process(authResponse);

      expect(result).toEqual({
        token: 'valid-token',
        zendeskJwt: mockJwt
      });
      expect(CommonUtils.generateJwt).toHaveBeenCalledWith(
        {
          external_id: 'dev:123',
          name: 'testuser.dev',
          email: 'user@example.com.dev',
          jti: 'mock-uuid',
          iat: Math.floor(Date.now() / 1000)
        },
        'test-secret',
        { algorithm: 'HS256' }
      );
    });

    it('should use production format when idPrefix indicates production', async () => {
      mockConfigService.getZendesk.mockReturnValueOnce({
        secret: 'prod-secret',
        idPrefix: 'prod'
      });
      const authResponse: AuthorizationResponse = { token: 'valid-token' };

      plugin = new ZendeskAuthPlugin(mockConfigService as ConfigurationService);

      const result = await plugin.process(authResponse);

      expect(CommonUtils.generateJwt).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'testuser',
          email: 'user@example.com'
        }),
        'prod-secret',
        { algorithm: 'HS256' }
      );
    });

    it('should not modify original auth object properties', async () => {
      const authResponse: AuthorizationResponse = { 
        token: 'valid-token',
        refreshToken: 'refresh-token',
      };

      const result = await plugin.process(authResponse);

      expect(result.token).toBe('valid-token');
      expect(result.refreshToken).toBe('refresh-token');
      expect(result.zendeskJwt).toBe(mockJwt);
    });
  });
});
