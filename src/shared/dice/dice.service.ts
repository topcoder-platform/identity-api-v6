import {
  Injectable,
  Inject,
  Logger,
  InternalServerErrorException,
  BadRequestException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { AxiosError } from 'axios';

// Interface for the expected structure of the DICE token response
interface DiceTokenResponse {
  status: string;
  result: {
    token: string;
    expires_at?: string;
  };
}

// Interface for the DICE invitation payload
interface DiceInvitationPayload {
  invitee_name: string;
  auto_accept: boolean;
  auto_offer: boolean;
  send_connection_invite: boolean;
  email: { invitee_email: string };
  invite_modes: string[];
  credential_data: {
    schema_name: string;
    schema_version: string;
    attributes: Array<{ name: string; value: string }>;
  };
}

@Injectable()
export class DiceService {
  private readonly logger = new Logger(DiceService.name);
  private readonly diceApiUrl: string;
  private readonly diceApiKey: string;
  private readonly diceOrgId: string;
  private readonly diceUserId: string; // User ID for invoking DICE APIs
  private readonly tcApiKey: string; // API key to validate incoming webhooks from DICE
  private readonly diceSchemaName: string;
  private readonly diceSchemaVersion: string;

  private static cachedDiceAuthToken: string | null = null;
  private static tokenExpiryTime: Date | null = null;

  constructor(
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
  ) {
    this.diceApiUrl = this.configService.get<string>('DICEAUTH_DICE_API_URL');
    this.diceApiKey = this.configService.get<string>('DICEAUTH_DICE_API_KEY');
    this.diceOrgId = this.configService.get<string>('DICEAUTH_ORG_ID');
    this.diceUserId = this.configService.get<string>('DICEAUTH_USER_ID');
    this.tcApiKey = this.configService.get<string>('DICEAUTH_TC_API_KEY');
    this.diceSchemaName = this.configService.get<string>(
      'DICEAUTH_SCHEMA_NAME',
    );
    this.diceSchemaVersion = this.configService.get<string>(
      'DICEAUTH_SCHEMA_VERSION',
    );

    if (
      !this.diceApiUrl ||
      !this.diceApiKey ||
      !this.diceOrgId ||
      !this.diceUserId ||
      !this.tcApiKey ||
      !this.diceSchemaName ||
      !this.diceSchemaVersion
    ) {
      this.logger.error(
        'DICE service configuration is incomplete. Some environment variables are missing.',
      );
      throw new InternalServerErrorException(
        'DICE service configuration is incomplete.',
      );
    }
  }

  private decodeJwt(token: string): { exp?: number } | null {
    try {
      const payloadBase64 = token.split('.')[1];
      if (!payloadBase64) return null;
      const decodedJson = Buffer.from(payloadBase64, 'base64').toString();
      return JSON.parse(decodedJson);
    } catch (error) {
      this.logger.error('Failed to decode JWT for expiry check', error);
      return null;
    }
  }

  private isTokenExpired(token: string | null): boolean {
    if (!token) return true;
    const decoded = this.decodeJwt(token);
    if (decoded && decoded.exp) {
      // Check if expiry is less than current time + 60s buffer
      return decoded.exp * 1000 < Date.now() + 60000;
    }
    return true; // Treat as expired if no expiry claim or cannot decode
  }

  async getDiceAuthToken(): Promise<string> {
    if (
      DiceService.cachedDiceAuthToken &&
      !this.isTokenExpired(DiceService.cachedDiceAuthToken)
    ) {
      this.logger.debug('Returning cached DICE auth token.');
      return DiceService.cachedDiceAuthToken;
    }

    this.logger.log('Fetching new DICE auth token.');
    const url = `${this.diceApiUrl}/api-token`;
    const requestHeaders = {
      org_id: this.diceOrgId,
      invoked_by: this.diceUserId,
      'x-api-key': this.diceApiKey,
      'Content-Type': 'application/json',
    };

    this.logger.debug(`Attempting to GET DICE auth token from URL: ${url}`);
    this.logger.debug(`Request Headers: ${JSON.stringify(requestHeaders)}`);

    try {
      const response = await firstValueFrom(
        this.httpService.get<DiceTokenResponse>(url, {
          headers: requestHeaders,
        }),
      );

      this.logger.debug(
        `DICE Auth Token API Raw Response Status: ${response.status}`,
      );
      this.logger.debug(
        `DICE Auth Token API Raw Response Headers: ${JSON.stringify(response.headers)}`,
      );
      this.logger.debug(
        `DICE Auth Token API Raw Response Data: ${JSON.stringify(response.data)}`,
      );

      if (response.data && response.data.result && response.data.result.token) {
        DiceService.cachedDiceAuthToken = response.data.result.token;
        const decoded = this.decodeJwt(response.data.result.token);
        if (decoded && decoded.exp) {
          DiceService.tokenExpiryTime = new Date(decoded.exp * 1000);
        } else {
          DiceService.tokenExpiryTime = null; // Unable to determine expiry
        }
        this.logger.log('Successfully fetched and cached new DICE auth token.');
        return DiceService.cachedDiceAuthToken;
      } else {
        this.logger.error(
          'DICE API token response did not contain a token at the expected path (data.result.token). Full response data:',
          response.data,
        );
        throw new InternalServerErrorException(
          'DICE API token response did not contain a token at the expected path.',
        );
      }
    } catch (error) {
      const axiosError = error as AxiosError;
      this.logger.error(
        `Error fetching DICE auth token. Raw Error: ${JSON.stringify(error, Object.getOwnPropertyNames(error))}`,
      );
      if (axiosError.isAxiosError && axiosError.response) {
        this.logger.error(
          `DICE Auth Token API Response Status: ${axiosError.response.status}`,
        );
        this.logger.error(
          `DICE Auth Token API Response Data: ${JSON.stringify(axiosError.response.data)}`,
        );
        this.logger.error(
          `DICE Auth Token API Response Headers: ${JSON.stringify(axiosError.response.headers)}`,
        );
      } else {
        this.logger.error(
          'Error during DICE auth token HTTP request was not a standard AxiosError with a response.',
        );
      }
      // Original stack trace is still valuable
      this.logger.error(
        `Original Error Stack: ${axiosError.stack || error.stack}`,
      );

      throw new InternalServerErrorException(
        'Failed to fetch DICE auth token.',
      );
    }
  }

  async sendDiceInvitation(
    inviteeEmail: string,
    inviteeHandle: string, // Used for dice_display_name
    inviteeFullName: string, // Used for Name attribute
    roles: string[], // For Role attribute
    validTill: string, // For Valid_Till attribute, format "dd-MMM-yyyy HH:mm:ss"
  ): Promise<{ jobId: string; connectionId?: string; shortUrl?: string }> {
    const authToken = await this.getDiceAuthToken();
    const url = `${this.diceApiUrl}/connection/invitation`;

    const payload: DiceInvitationPayload = {
      invitee_name: 'Topcoder', // As per Java code
      auto_accept: true,
      auto_offer: true,
      send_connection_invite: false, // Java code set this to false
      email: { invitee_email: inviteeEmail },
      invite_modes: ['email'],
      credential_data: {
        schema_name: this.diceSchemaName,
        schema_version: this.diceSchemaVersion,
        attributes: [
          { name: 'Name', value: inviteeFullName },
          { name: 'Email', value: inviteeEmail },
          { name: 'Role', value: roles.join(',') },
          { name: 'Valid_Till', value: validTill },
          { name: 'dice_display_name', value: inviteeHandle },
        ],
      },
    };

    this.logger.log(
      `Sending DICE invitation for ${inviteeEmail} with payload: ${JSON.stringify(payload)}`,
    );

    try {
      const response = await firstValueFrom(
        this.httpService.post<{
          jobId: string;
          connectionId?: string;
          shortUrl?: string;
        }>(url, payload, {
          // Define expected response type
          headers: {
            org_id: this.diceOrgId,
            invoked_by: this.diceUserId,
            'x-api-key': this.diceApiKey,
            Authorization: `Bearer ${authToken}`,
            'Content-Type': 'application/json',
          },
        }),
      );
      this.logger.log(
        `DICE invitation sent successfully for ${inviteeEmail}. Job ID: ${response.data.jobId}`,
      );
      return response.data; // Contains jobId, might contain connectionId, shortUrl
    } catch (error) {
      const axiosError = error as AxiosError;
      this.logger.error(
        `Error sending DICE invitation for ${inviteeEmail}: ${axiosError.message}`,
        axiosError.stack,
      );
      if (axiosError.response) {
        this.logger.error(
          `DICE Invitation API Response Status: ${axiosError.response.status}`,
        );
        this.logger.error(
          `DICE Invitation API Response Data: ${JSON.stringify(axiosError.response.data)}`,
        );
      }
      throw new InternalServerErrorException('Failed to send DICE invitation.');
    }
  }

  isValidTopcoderApiKey(apiKey: string): boolean {
    if (!apiKey) return false;
    const isValid = apiKey === this.tcApiKey;
    if (!isValid) {
      this.logger.warn(
        `Invalid TC API Key received for DICE webhook: ${apiKey}`,
      );
    }
    return isValid;
  }
}
