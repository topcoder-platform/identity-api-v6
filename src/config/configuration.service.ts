import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";


@Injectable()
export class ConfigurationService {

  constructor(private readonly configService: ConfigService) {}

  getCommon() {
    const issuerValue = this.configService.get<string>('VALID_ISSUERS', '');
    const issuers = issuerValue.split(',').map(t => t.trim());
    return {
      authSecret: this.configService.get<string>('AUTH_SECRET'),
      authDomain: this.configService.get<string>('AUTH_DOMAIN'),
      jwtExpirySeconds: 43200,
      validIssuers: issuers
    };
  }

  getAuthorizationService() {
    return {
      cookieExpirySeconds: this.configService.get<number>('COOKIE_EXPIRY_SECONDS', 7776000)
    };
  }

  getServiceAccounts() {
    return [{
      clientId: this.configService.get<string>('SERVICEACC01_CID'),
      secret: this.configService.get<string>('SERVICEACC01_SECRET'),
      contextUserId: this.configService.get<string>('SERVICEACC01_UID'),
    }, {
      clientId: this.configService.get<string>('SERVICEACC02_CID'),
      secret: this.configService.get<string>('SERVICEACC02_SECRET'),
      contextUserId: this.configService.get<string>('SERVICEACC02_UID'),
    }]
  }

  getAuthStore() {
    // Can also be { type: 'memory' }
    return {
      type: 'redis',
      spec: {
        host: this.configService.get<string>('REDIS_HOST'),
        port: this.configService.get<number>('REDIS_PORT'),
        expirySeconds: 7776000
      }
    }
  }

  getAuth0() {
    return {
      auth0: {
        domain: this.configService.get<string>('AUTH0_DOMAIN'),
        clientId: this.configService.get<string>('AUTH0_CLIENT_ID'),
        clientSecret: this.configService.get<string>('AUTH0_CLIENT_SECRET'),
        nonInteractiveClientId: 
        this.configService.get<string>('AUTH0_NONINTERACTIVE_ID', ''),
        nonInteractiveClientSecret: 
        this.configService.get<string>('AUTH0_NONINTERACTIVE_ID_SECRET', '')
      },

      auth0New: {
        domain: this.configService.get<string>('AUTH0_NEW_DOMAIN'),
        clientId: this.configService.get<string>('AUTH0_NEW_CLIENT_ID'),
        clientSecret: this.configService.get<string>('AUTH0_NEW_CLIENT_SECRET'),
        nonInteractiveClientId: this.configService.get<string>('AUTH0_NEW_NONINTERACTIVE_ID', ''),
        nonInteractiveClientSecret: this.configService.get<string>('AUTH0_NEW_NONINTERACTIVE_ID_SECRET', '')
      }
    };
  }

  getZendesk() {
    return {
      secret: this.configService.get<string>('ZENDESK_SECRET'),
      idPrefix: this.configService.get<string>('ZENDESK_PREFIX')
    }
  }
}
