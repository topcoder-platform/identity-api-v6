import { HttpService } from '@nestjs/axios';
import * as jwt from 'jsonwebtoken';
import {
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { firstValueFrom } from 'rxjs';
import { Auth0Credential } from 'src/dto/authorization/authorization.dto';
import { CommonUtils } from '../util/common.utils';
import { ConfigurationService } from '../../config/configuration.service';
import { Constants } from '../../core/constant/constants';

@Injectable()
export class Auth0Service {
  private readonly logger: Logger = new Logger(Auth0Service.name);

  readonly clientId: string;
  readonly clientSecret: string;
  private readonly nonInteractiveClientId: string;
  private readonly nonInteractiveClientSecret: string;
  readonly domain: string;

  constructor(
    private readonly config: ConfigurationService,
    private readonly httpService: HttpService,
  ) {
    this.clientId = this.config.getAuth0().auth0.clientId;
    this.clientSecret = this.config.getAuth0().auth0.clientSecret;
    this.domain = this.config.getAuth0().auth0.domain;
  }

  /**
   * Get auth0 credential with auth code
   * @param code auth code
   * @param redirectUrl redirect url
   * @returns auth0 credential
   */
  async getToken(code: string, redirectUrl: string): Promise<Auth0Credential> {
    const url = `https://${this.domain}/oauth/token`;
    return await this.postAuth0Request(url, {
      client_id: this.clientId,
      client_secret: this.clientSecret,
      redirect_uri: redirectUrl,
      code,
      grant_type: 'authorization_code',
      scope: 'openid offline_access',
    });
  }

  /**
   * Get the new access token by refresh token.
   * @param refreshToken refresh token
   * @returns auth0 credential with new token
   */
  async refreshToken(refreshToken: string): Promise<Auth0Credential> {
    const url = `https://${this.domain}/oauth/token`;
    return await this.postAuth0Request(url, {
      client_id: this.clientId,
      client_secret: this.clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    });
  }

  /**
   * Verify token and return decoded if OK.
   * @param auth0Token auth0 token
   * @returns decoded payload
   */
  async verifyToken(auth0Token: string): Promise<Record<string, any>> {
    try {
      const secretBuffer = Buffer.from(this.clientSecret, 'base64');

      const decoded = jwt.verify(auth0Token, secretBuffer, {
        algorithms: [Constants.jwtHs256Algorithm],
      });
      return Promise.resolve(decoded as Record<string, any>);
    } catch (error) {
      // will never catch the exp here as the token is deem valid at the step
      this.logger.warn('Error parsing auth0 token', error);
      return Promise.resolve({});
    }
  }

  /**
   * Revoke refresh token
   * @param token access token
   * @param refreshToken refresh token
   */
  async revokeRefreshToken(token: string, refreshToken: string) {
    const userId = this.getUserIdFromToken(token);
    const url = `https://${this.domain}/api/users/${userId}/refresh_tokens/${refreshToken}`;
    const response = await firstValueFrom(
      this.httpService.delete(url, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }),
    );
    if (response.status !== (HttpStatus.OK as number)) {
      throw new Error(
        `Got unexpected response from remote service. ${response.status}`,
      );
    }
  }

  /**
   * Send POST request to Auth0 and get credentials.
   * @param url url to request.
   * @param params parameters
   * @returns auth0 credential with tokens
   */
  private async postAuth0Request(
    url: string,
    params,
  ): Promise<Auth0Credential> {
    try {
      this.logger.debug(`Sending Auth0 request with url: ${url}`);
      const response = await firstValueFrom(this.httpService.post(url, params));
      if (!response.data || response.status !== (HttpStatus.OK as number)) {
        throw new Error(
          `Got unexpected response from remote service. ${response.status}`,
        );
      }
      this.logger.debug(`Got Auth0 response content: ${response.data}`);
      return response.data as Auth0Credential;
    } catch (error) {
      this.logger.warn(error);
      throw new InternalServerErrorException(
        'Got unexpected response from remote service.',
      );
    }
  }

  /**
   * Parse user id from jwt token
   * @param token jwt token
   * @returns user id
   */
  private getUserIdFromToken(token: string) {
    const claims = CommonUtils.parseJWTClaims(token);
    let userId = claims['user_id'];
    if (userId == null) {
      userId = claims['sub'];
    }
    return String(userId);
  }
}
