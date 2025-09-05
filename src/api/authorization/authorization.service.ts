import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { Cache } from 'cache-manager';
import { v4 as uuidv4 } from 'uuid';
import { format } from 'date-fns-tz';
import { Auth0Service } from '../../shared/auth0/auth0.service';
import {
  Auth0Credential,
  AuthorizationCreateDto,
  AuthorizationForm,
  AuthorizationResponse,
  GetTokenQueryDto,
  ValidateClientQueryDto,
} from '../../dto/authorization/authorization.dto';
import { UserService } from '../user/user.service';
import { CommonUtils } from '../../shared/util/common.utils';
import { AuthDataStore } from './auth-data-store.service';
import { ZendeskAuthPlugin } from './zendesk.service';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { PrismaClient } from '@prisma/client';
import { UserProfileHelper } from './user-profile.helper';
import { ProviderTypes } from '../../core/constant/provider-type.enum';
import { ConfigurationService } from '../../config/configuration.service';
import { Constants } from '../../core/constant/constants';

const tcRedirectDomains = [
  'topcoder-dev.com',
  'topcoder-qa.com',
  'topcoder.com',
];

const AUTH0_STATE_CACHE_PREFIX_KEY: string = 'AUTH0_STATES_CACHE_PREFIX_KEY';

const MAX_COOKIE_EXPIRY_SECONDS = 90 * 24 * 3600; // 90d

const AUTH_REFRESH_LOG_DATE_FORMAT = 'yyyy-MM-dd_HH:mm:ss';

const AUTH_REFRESH_LOG_KEY_PREFIX = 'identity:';
const AUTH_REFRESH_LOG_KEY_DELIM = ',';

@Injectable()
export class AuthorizationService {
  private readonly logger = new Logger(AuthorizationService.name);

  private readonly cookieExpirySeconds: number;

  constructor(
    private readonly config: ConfigurationService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    private readonly auth0: Auth0Service,
    private readonly userService: UserService,
    private readonly authDataStore: AuthDataStore,
    private readonly zendeskPlugin: ZendeskAuthPlugin,
    @Inject(PRISMA_CLIENT)
    private readonly prismaClient: PrismaClient,
    private readonly userProfileHelper: UserProfileHelper,
  ) {
    this.cookieExpirySeconds =
      this.config.getAuthorizationService().cookieExpirySeconds;
  }

  /**
   * Redirect user to auth0 login page
   * @param req request
   * @param res response
   * @param nextParam next parameter in request
   * @returns void
   */
  async loginRedirect(req: Request, res: Response, nextParam?: string) {
    const domain = this.auth0.domain;
    const clientId = this.auth0.clientId;
    const redirectUri = req.hostname;
    let protocol = req.secure ? 'https' : 'http';
    if (
      redirectUri != null &&
      tcRedirectDomains.some((t) => redirectUri.includes(t))
    ) {
      protocol = 'https';
    }
    let redirectUrl = req.headers['referer'];
    if (nextParam) {
      redirectUrl = nextParam;
    }
    if (!CommonUtils.validateString(redirectUrl)) {
      redirectUrl = Constants.defaultRedirectUrl;
    }
    const state = Buffer.from(
      CommonUtils.generateAlphaNumericString(Constants.defaultAuthStateLength),
    ).toString('base64');

    await this.cacheManager.set(AUTH0_STATE_CACHE_PREFIX_KEY + state, state);

    const returlUrl =
      `https://${domain}/authorize?client_id=${clientId}` +
      `&redirect_uri=${protocol}://${redirectUri}/v6/authorizations?redirectUrl=${redirectUrl}` +
      `&audience=${protocol}://${redirectUri}/v6&scope=openid profile offline_access` +
      `&response_type=code&state=${state}` +
      `&prompt=none`;
    // set response
    res.redirect(302, returlUrl);
    return;
  }

  /**
   * Get token by authorization code and redirect url.
   * @param req request
   * @param res response
   * @param dto query dto
   */
  async getTokenByAuthorizationCode(
    req: Request,
    res: Response,
    dto: GetTokenQueryDto,
  ) {
    if (dto.error && dto.error === 'login_required') {
      const domain = this.auth0.domain;
      const clientId = this.auth0.clientId;
      const redirectUri = req.hostname;
      let protocol = req.secure ? 'https' : 'http';
      if (
        redirectUri != null &&
        tcRedirectDomains.some((t) => redirectUri.includes(t))
      ) {
        protocol = 'https';
      }
      const resultUrl =
        `https://${domain}/authorize?client_id=${clientId}` +
        `&redirect_uri=${protocol}://${redirectUri}/v6/authorizations?redirectUrl=${dto.redirectUrl}` +
        `&audience=${protocol}://${redirectUri}/v6&scope=openid profile offline_access` +
        `&response_type=code&state=${dto.state}`;
      res.redirect(resultUrl);
      return;
    }
    if (dto.code == null || dto.code.trim().length === 0) {
      throw new BadRequestException(
        'The authorization code should be non-null and non-empty string',
      );
    }
    if (dto.redirectUrl == null || dto.redirectUrl.trim().length === 0) {
      throw new BadRequestException(
        'The redirect url code should be non-null and non-empty string',
      );
    }
    if (dto.state == null || dto.state.trim().length === 0) {
      throw new BadRequestException(
        'The state code should be non-null and non-empty string',
      );
    }
    const cachedState = await this.cacheManager.get<string>(
      AUTH0_STATE_CACHE_PREFIX_KEY + dto.state,
    );
    if (cachedState == null) {
      throw new ForbiddenException('The state code is not found.');
    }

    const credential: Auth0Credential = await this.auth0.getToken(
      dto.code,
      dto.redirectUrl,
    );

    await this.cacheManager.set(
      credential.access_token,
      credential.refresh_token,
    );

    credential.refresh_token = null;

    const cookieOptions = { maxAge: this.cookieExpirySeconds };
    res.cookie(Constants.tcJwtCookieName, credential.id_token, cookieOptions);
    res.cookie(
      Constants.tcV3JwtCookieName,
      credential.access_token,
      cookieOptions,
    );
    const userId = this.extractUserIdFromToken(credential.access_token);
    const token = await this.userService.generateSSOToken(userId);
    res.cookie(Constants.tcSsoCookieName, token, cookieOptions);

    await this.cacheManager.del(AUTH0_STATE_CACHE_PREFIX_KEY + dto.state);
    res.redirect(dto.redirectUrl);
    return credential;
  }

  /**
   * Create authorization with request param
   * @param req request
   * @param dto request param
   * @returns authorization created
   */
  async createObject(
    req: Request,
    res: Response,
    dto: AuthorizationCreateDto,
  ): Promise<AuthorizationResponse> {
    let auth: AuthorizationResponse = { ...dto };
    let isRs256Token: boolean = false;
    if (dto == null) {
      const authCode = this.getAuthorizationParam('Auth0Code', req);
      CommonUtils.validateStringThrow(authCode);
      auth = await this.createAuthorization(authCode, req);
    } else {
      CommonUtils.validateStringThrow(dto.externalToken);
      if (auth.id == null) {
        auth.id = String(CommonUtils.hashCode(auth));
      }
      const header = CommonUtils.parseJWTHeader(auth.externalToken);
      if (header['alg'] === Constants.jwtRs256Algorithm) {
        isRs256Token = true;
        const refreshToken = dto.refreshToken;
        const cred = await this.auth0.refreshToken(refreshToken);
        await this.cacheManager.del(auth.externalToken);
        await this.cacheManager.set(cred.access_token, refreshToken);
        auth.token = cred.access_token;
      } else {
        auth.token = await this.createJWTToken(dto.externalToken);
      }
      auth.target = Constants.defaultTargetId;
    }

    await this.addZendeskInfo(auth);
    await this.updateLastLoginDate(auth);
    await this.processTCCookies(auth, req, res, isRs256Token);
    await this.authDataStore.put(auth);
    return auth;
  }

  /**
   * Create object with request form data.
   * @param form request form data
   * @returns AuthorizationResponse
   */
  async createObjectForm(
    form: AuthorizationForm,
  ): Promise<AuthorizationResponse> {
    const serviceAccounts = this.config.getServiceAccounts();
    const account = serviceAccounts.find(
      (t) => t.clientId === form.clientId && t.secret === form.secret,
    );
    if (account == null) {
      throw new UnauthorizedException('Unauthorized');
    }
    let auth = null;
    try {
      auth = await this.createSystemUserAuthorization(account.contextUserId);

      await this.updateLastLoginDate(auth);

      await this.authDataStore.put(auth);
    } catch (error) {
      this.logger.error(error);
      throw new Error(error);
    }
    return auth as AuthorizationResponse;
  }

  /**
   * Delete cookie and auth store.
   * @param targetId target id
   * @param req request
   * @param res response
   */
  async deleteObject(
    targetId: string,
    req: Request,
    res: Response,
  ): Promise<void> {
    const token = this.getAuthorizationParam('Bearer', req);
    if (token == null || token.length === 0) {
      throw new UnauthorizedException('Unauthorized');
    }
    // delete cookie
    this.deleteTCCookies(res);

    const auth = await this.authDataStore.get(token, targetId);
    if (auth == null) {
      return;
    }
    await this.authDataStore.delete(token, targetId);
    if (auth.refreshToken != null) {
      try {
        await this.auth0.revokeRefreshToken(
          auth.externalToken,
          auth.refreshToken,
        );
      } catch (e) {
        this.logger.warn('Failed to revoke refresh token.', e);
      }
    }
    return;
  }

  /**
   * Returns ASP token from given Authorization Bearer header.
   * Bearer can hold either of 2 token, (a) Appirio Service Platform JWT or (b) Auth0 JWT
   * @param targetId target id
   * @param req request
   * @param res response
   * @param fields fields you want in response
   * @return authorization response
   */
  async getObject(
    targetId: string,
    req: Request,
    res: Response,
    fields?: string,
  ): Promise<AuthorizationResponse> {
    const token = this.getAuthorizationParam('Bearer', req);
    if (token == null || token.length === 0) {
      throw new UnauthorizedException('Unauthorized');
    }
    const sameDomain = this.isIssuerSameDomain(token);
    let auth = null;
    if (sameDomain) {
      // verify token
      const verified = await this.verifyJwtToken(token);
      if (!verified) {
        throw new UnauthorizedException('Invalid token');
      }
      auth = await this.authDataStore.get(token, targetId);
      if (auth == null) {
        throw new UnauthorizedException('Unauthorized');
      }
      // create new token
      try {
        const newToken = await this.createJWTToken(auth.externalToken);
        if (newToken == null) {
          throw new Error('Failed to create JWT token.');
        }
        auth.token = newToken;
      } catch (e) {
        if (e?.name === 'TokenExpiredError') {
          auth.token = await this.refresh(auth.refreshToken);
        } else {
          throw e;
        }
      }
      await this.authDataStore.put(auth);
    } else {
      const cred = new Auth0Credential();
      cred.id_token = token;
      cred.token_type = 'Bearer';
      auth = await this.createCredentialAuthorization(cred);
    }

    await this.processTCCookies(auth, req, res, false);
    // filter result
    if (fields && fields.trim().length > 0) {
      const keys = fields.split(',');
      return CommonUtils.pick(auth, keys);
    }
    return auth as AuthorizationResponse;
  }

  /**
   * Validate client
   * @param dto query dto
   */
  async validateClient(dto: ValidateClientQueryDto): Promise<string> {
    const client = await this.prismaClient.client.findUnique({
      where: { clientId: dto.clientId },
    });
    if (client == null) {
      throw new UnauthorizedException('Unknown Client ID');
    }
    const allUri = client.redirectUri;
    if (allUri == null || allUri.length === 0) {
      throw new UnauthorizedException('Unregistered URI to redirect');
    }
    const uriList = allUri.split(',');
    if (!uriList.includes(dto.redirectUrl)) {
      throw new UnauthorizedException('Unregistered URI to redirect');
    }
    return 'Valid client';
  }

  /**
   * Refresh to get new token
   * @param refreshToken refresh token
   * @returns new token
   */
  private async refresh(refreshToken: string): Promise<string> {
    if (refreshToken == null) {
      throw new Error('refreshToken must be specified.');
    }
    const auth = await this.auth0.refreshToken(refreshToken);
    if (auth == null || auth.id_token == null) {
      throw new Error(
        `Failed to refresh token. refresh-token: ${refreshToken}`,
      );
    }
    return await this.createJWTToken(auth.id_token);
  }

  /**
   * Check token issuer from same domain
   * @param token access token
   * @returns true if issuer is from same domain
   */
  private isIssuerSameDomain(token: string): boolean {
    const decoded = CommonUtils.parseJWTClaims(token);
    // check iss field and domain
    const issValue = CommonUtils.createIssuerFor(
      this.config.getCommon().authDomain,
    );
    return decoded['iss']?.toLowerCase() === issValue.toLowerCase();
  }

  /**
   * Verify token
   * @param token access token
   * @returns true if OK
   */
  private async verifyJwtToken(token: string): Promise<boolean> {
    const validIssuers = this.config.getCommon().validIssuers;
    const secret = this.config.getCommon().authSecret;
    try {
      await CommonUtils.verifyJwtToken(token, validIssuers, secret);
    } catch (e) {
      if (e?.name === 'TokenExpiredError') {
        // ignore this error
        return true;
      }
      this.logger.warn(`Failed to verify token.`, e);
      return false;
    }
    return true;
  }

  /**
   * Clear response cookie
   * @param res response
   */
  private deleteTCCookies(res: Response) {
    res.cookie(Constants.tcJwtCookieName, null);
    res.cookie(Constants.tcSsoCookieName, null);
  }

  /**
   * Update user's last login date
   * @param auth authorization
   */
  private async updateLastLoginDate(auth: AuthorizationResponse) {
    if (auth == null) {
      throw new Error('auth must be specified.');
    }
    const userId = this.extractUserId(auth);
    if (userId == null) {
      return;
    }
    await this.prismaClient.user.update({
      where: { user_id: userId },
      data: { last_login: new Date() },
    });
  }

  /**
   * Add zendesk jwt to user authorization.
   * @param auth authorization
   */
  private async addZendeskInfo(auth: AuthorizationResponse) {
    if (auth == null) {
      return;
    }
    await this.zendeskPlugin.process(auth);
  }

  /**
   * Set cookie for authorization
   * @param auth authorization
   * @param req request
   * @param res response
   * @param isRs256Token token is RS256 type
   */
  private async processTCCookies(
    auth: AuthorizationResponse,
    req: Request,
    res: Response,
    isRs256Token: boolean,
  ) {
    const rememberMe: boolean = this.getRememberMe(req);
    let maxAge = this.cookieExpirySeconds;
    if (rememberMe) {
      maxAge = MAX_COOKIE_EXPIRY_SECONDS;
    }
    const cookieOptions = { maxAge };
    res.cookie(
      Constants.tcJwtCookieName,
      isRs256Token ? auth.token : auth.externalToken,
      cookieOptions,
    );
    if (auth.token != null) {
      const userId = this.extractUserId(auth);
      res.cookie(
        Constants.tcSsoCookieName,
        this.userService.generateSSOToken(userId),
        cookieOptions,
      );
    }
    return Promise.resolve();
  }

  /**
   * Get remember me flag from request
   * @param req request
   * @returns remember me flag
   */
  private getRememberMe(req: Request) {
    if (req.cookies) {
      Object.entries(req.cookies).forEach(([name, value]) => {
        if (name.toLowerCase() === Constants.rememberMeFlag) {
          return Boolean(value);
        }
      });
    }
    return false;
  }

  /**
   * Create AuthorizationResponse with auth code.
   * @param authCode auth code
   * @param req request
   * @returns AuthorizationResponse
   */
  private async createAuthorization(
    authCode: string,
    req: Request,
  ): Promise<AuthorizationResponse> {
    try {
      const cred = await this.auth0.getToken(
        authCode,
        this.createRedirectURL(req),
      );
      return await this.createCredentialAuthorization(cred);
    } catch (error) {
      this.logger.error('Error to create authorization.', error);
      throw error;
    }
  }

  /**
   * Create AuthorizationResponse with system user id.
   * @param systemUserId system user id
   * @returns AuthorizationResponse
   */
  private async createSystemUserAuthorization(
    systemUserId: string,
  ): Promise<AuthorizationResponse> {
    if (systemUserId == null) {
      throw new Error('systemUserId must be specified.');
    }
    const auth = new AuthorizationResponse();
    auth.id = String(CommonUtils.hashCode(auth));
    const issuer = CommonUtils.createIssuerFor(
      this.config.getCommon().authDomain,
    );
    const currentSeconds = Math.floor(Date.now() / 1000);
    const expSeconds =
      currentSeconds + this.config.getCommon().jwtExpirySeconds;
    const roles = await this.getRoleNames(parseInt(systemUserId));
    const payload = {
      userId: systemUserId,
      roles,
      iss: issuer,
      iat: currentSeconds,
      exp: expSeconds,
      jti: uuidv4(),
    };
    const options = {
      algorithm: Constants.jwtHs256Algorithm,
    };
    const token = CommonUtils.generateJwt(
      payload,
      this.config.getCommon().authSecret,
      options,
    );
    auth.token = token;
    auth.target = Constants.defaultTargetId;
    return auth;
  }

  /**
   * Create AuthorizationResponse with Auth0Credential
   * @param cred Auth0 Credential
   * @returns AuthorizationResponse
   */
  private async createCredentialAuthorization(
    cred: Auth0Credential,
  ): Promise<AuthorizationResponse> {
    const auth0Token = cred.id_token;
    const newToken = await this.createJWTToken(auth0Token);

    const ret = new AuthorizationResponse();
    ret.id = String(CommonUtils.hashCode(ret));
    ret.token = newToken;
    ret.refreshToken = cred.refresh_token;
    ret.externalToken = auth0Token;
    ret.target = Constants.defaultTargetId;
    return ret;
  }

  /**
   * Get redirect url from request header referer.
   * @param req request
   * @returns redirect url
   */
  private createRedirectURL(req: Request) {
    const url = req.originalUrl || req.url;
    const referer = req.headers.referer;

    if (!referer || typeof referer !== 'string' || referer.length === 0) {
      return url;
    }

    try {
      const refererUrl = new URL(referer);
      const currentUrl = new URL(url, `${req.protocol}://${req.get('host')}`);

      return `${refererUrl.protocol}//${currentUrl.host}${currentUrl.pathname}${currentUrl.search}`;
    } catch (e) {
      this.logger.error(
        `Failed to create redirect url. base: ${url}, referer: ${referer}`,
        e,
      );
      return url;
    }
  }

  /**
   * Create jwt token with auth0 token.
   * @param auth0Token auth0 token
   * @returns jwt token
   */
  private async createJWTToken(auth0Token: string): Promise<string> {
    const userId = await this.getUserId(auth0Token);
    const issuer = CommonUtils.createIssuerFor(
      this.config.getCommon().authDomain,
    );
    const currentSeconds = Math.floor(Date.now() / 1000);
    const expSeconds =
      currentSeconds + this.config.getCommon().jwtExpirySeconds;
    const payload = {
      userId: userId,
      email: '',
      handle: '',
      roles: [],
      country: '',
      iss: issuer,
      iat: currentSeconds,
      exp: expSeconds,
      jti: uuidv4(),
    };
    if (userId != null) {
      const user = await this.userService.findUserById(userId);
      if (user == null) {
        throw new NotFoundException('User does not exist');
      }
      if (user.status !== 'A') {
        throw new ForbiddenException('Account Inactive');
      }

      payload.handle = user.handle;
      payload.email = (user as any).primaryEmailAddress;
      payload.roles = await this.getRoleNames(userId);

      await this.storeAuthRefreshLogToCache(userId, user);
    }

    const options = {
      algorithm: Constants.jwtHs256Algorithm,
    };
    return CommonUtils.generateJwt(
      payload,
      this.config.getCommon().authSecret,
      options,
    );
  }

  private async storeAuthRefreshLogToCache(userId: number, user) {
    const dateStr = format(new Date(), AUTH_REFRESH_LOG_DATE_FORMAT, {
      timeZone: 'UTC',
    });
    const key =
      AUTH_REFRESH_LOG_KEY_PREFIX +
      userId +
      AUTH_REFRESH_LOG_KEY_DELIM +
      user.handle;
    try {
      await this.cacheManager.set(key, dateStr);
    } catch (error) {
      this.logger.warn('Failed to store auth refresh log.', error);
    }
  }

  private async getRoleNames(userId: number): Promise<string[]> {
    const assignments = await this.prismaClient.roleAssignment.findMany({
      where: {
        subjectId: userId,
        subjectType: Constants.memberSubjectType,
      },
      include: { role: true },
    });
    return assignments.map((t) => t.role.name);
  }

  private async getUserId(auth0Token: string): Promise<number | null> {
    if (auth0Token == null) {
      throw new Error('auth0Token must be specified.');
    }
    // verify token
    const decoded = await this.auth0.verifyToken(auth0Token);
    // create profile
    const profile = this.userProfileHelper.createProfile(decoded);
    // check provider type
    const providerType = ProviderTypes[profile.providerType];
    if (providerType == null) {
      throw new UnauthorizedException('Unsupported provider.');
    }

    let userId = null;
    try {
      userId = await this.userProfileHelper.getUserIdByProfile(profile);
    } catch (error) {
      this.logger.error(error);
      throw new Error('Received unexpected data from the remote ID provider.');
    }
    if (userId == null) {
      throw new UnauthorizedException('User is not registered');
    }
    return userId as number;
  }

  /**
   * Get user id from authorization
   * @param auth authorization
   * @returns user id
   */
  private extractUserId(auth: AuthorizationResponse): number | null {
    if (auth == null || auth.token == null || auth.token.trim().length === 0) {
      return null;
    }
    return this.extractUserIdFromToken(auth.token);
  }

  /**
   * Get user id from access token
   * @param token access token
   * @returns user id
   */
  private extractUserIdFromToken(token): number | null {
    try {
      const decoded = CommonUtils.parseJWTClaims(token);
      if ('userId' in decoded) {
        return parseInt(decoded['userId']);
      }
      for (const key of Object.keys(decoded)) {
        if (key.endsWith('userId')) {
          return parseInt(decoded[key]);
        }
      }
      // the user id will be stored in sub field
      // see https://auth0.com/docs/api-auth/tutorials/adoption/scope-custom-claims
      const sub = decoded['sub'] as string;
      if (sub != null) {
        return parseInt(sub.substring(Constants.auth0SubPrefix.length));
      }
    } catch (error) {
      this.logger.error(
        `Failed to extract userId from JWT. token: ${token}, `,
        error,
      );
    }
    return null;
  }

  /**
   * Get authorization param from request
   * @param type auth type
   * @param req request
   */
  private getAuthorizationParam(type: string, req: Request) {
    const authHeader = req.headers['authorization'];
    if (!CommonUtils.validateString(authHeader)) {
      return null;
    }
    if (!CommonUtils.validateString(type)) {
      return authHeader;
    }
    if (!authHeader.trim().startsWith(type)) {
      return null;
    }
    return authHeader.substring(type.length).trim();
  }
}
