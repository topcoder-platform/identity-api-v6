import { v4 as uuidv4 } from 'uuid';
import { ConfigurationService } from "../../config/configuration.service";
import { AuthorizationResponse } from "../../dto/authorization/authorization.dto";
import { CommonUtils } from "../../shared/util/common.utils";
import { Injectable } from '@nestjs/common';

@Injectable()
export class ZendeskAuthPlugin {

  private readonly secret: string;
  private readonly idPrefix: string;

  constructor(private readonly config: ConfigurationService) {
    const conf = this.config.getZendesk();
    this.secret = conf.secret;
    this.idPrefix = conf.idPrefix;
  }

  async process(auth: AuthorizationResponse): Promise<AuthorizationResponse> {
    const decoded = CommonUtils.parseJWTClaims(auth.token);
    const { userId, email, handle } = decoded;
    if (userId == null || handle == null || email == null) {
      return auth;
    }
    // generate token
    const payload = {
      external_id: this.createExternalId(userId),
      name: this.decorateForTest(handle),
      email: this.decorateForTest(email),
      jti: uuidv4(),
      iat: Math.floor(Date.now() / 1000)
    }
    const zendeskJwt = CommonUtils.generateJwt(payload, this.secret, {
      algorithm: 'HS256'
    });
    auth.zendeskJwt = zendeskJwt;
    return auth;
  }

  private createExternalId(id: string): string {
    return this.idPrefix + ':' + id;
  }

  private decorateForTest(value: string): string {
    return (this.isProduction(this.idPrefix)) ?
        value :
        value + "." + this.idPrefix;
  }

  private isProduction(idPrefix: string): boolean {
    if(idPrefix==null)
      return true;
    const lower = idPrefix.toLowerCase();
    return !lower.includes("dev") && ! lower.includes("qa"); 
  }
}
