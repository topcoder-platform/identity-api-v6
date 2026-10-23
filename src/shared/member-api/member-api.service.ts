import {
  Injectable,
  Inject,
  Logger,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { auth } from 'tc-core-library-js';
import { MemberInfoDto } from '../../dto/member/member.dto';
import { M2M_AUTH_CLIENT } from './member-api.constants'; // Import M2M client token from constants

const MEMBER_LOOKUP_FIELDS = ['userId', 'handle', 'email'] as const;
const DEFAULT_MEMBER_API_TIMEOUT_MS = 10000;

// Define the interface for the M2M Auth client provided by the module
// (the shared-core provider returned by auth.m2m in member-api.module.ts)
interface M2MAuthClient {
  getMachineToken(): Promise<string>;
}

@Injectable()
export class MemberApiService {
  private readonly logger = new Logger(MemberApiService.name);
  private readonly MEMBER_API_URL: string;
  /** Name of the M2M provider selected by USE_KEYCLOAK, used in failure logs. */
  private readonly m2mProviderName: 'Keycloak' | 'Auth0';

  /**
   * Reads `MEMBER_API_URL` and the `USE_KEYCLOAK` provider choice.
   * @param configService Nest configuration.
   * @param httpService HTTP client for Member API calls.
   * @param m2mAuthClient Shared-core M2M provider from `MemberApiModule`.
   * @throws Error when `MEMBER_API_URL` is missing; TypeError when `USE_KEYCLOAK`
   * is not `true`/`false`.
   */
  constructor(
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
    @Inject(M2M_AUTH_CLIENT) private readonly m2mAuthClient: M2MAuthClient,
  ) {
    this.MEMBER_API_URL = this.configService.get<string>('MEMBER_API_URL');
    if (!this.MEMBER_API_URL) {
      this.logger.error(
        `Required configuration missing for MemberApiService: MEMBER_API_URL`,
      );
      throw new Error(
        'Required configuration missing for MemberApiService: MEMBER_API_URL.',
      );
    }
    this.m2mProviderName = auth.useKeycloak({
      USE_KEYCLOAK: this.configService.get<string>('USE_KEYCLOAK'),
    })
      ? 'Keycloak'
      : 'Auth0';
  }

  /**
   * Gets a cached or new M2M token from the injected persistent provider: a verified
   * Keycloak token when `USE_KEYCLOAK=true`, otherwise an Auth0 token for
   * `AUTH0_CLIENT_ID`/`AUTH0_CLIENT_SECRET`.
   * Takes no parameters; returns a token or null on failure (logging which provider
   * failed, without details), never throws.
   */
  private async getM2mToken(): Promise<string | null> {
    try {
      return await this.m2mAuthClient.getMachineToken();
    } catch {
      this.logger.error(`${this.m2mProviderName} service authentication failed`);
      return null;
    }
  }

  /**
   * Fetches member information for a list of user IDs from the Member API.
   * Handles large lists by batching requests and logs total execution time.
   * The downstream lookup is intentionally restricted to `userId`, `handle`,
   * and `email`, and disables stats expansion because that is all identity uses
   * for role-subject responses.
   *
   * Batching is necessary because the Member API's GET /members endpoint is queried
   * using URL parameters (e.g., ?userIds=1&userIds=2...). Sending a large number
   * of IDs can exceed URL length limits (HTTP 414) or other request size limits
   * (HTTP 413) imposed by intermediate servers or proxies (e.g., Nginx, API Gateway)
   * even if the Member API itself could handle the list. This approach replicates
   * the likely behavior of the previous Java client which abstracted this batching.
   *
   * @param userIds An array of numeric user IDs.
   * @returns A promise resolving to an array of MemberInfoDto.
   * @throws HttpException if M2M token cannot be obtained or a batch API call fails.
   */
  async getUserInfoList(userIds: number[]): Promise<MemberInfoDto[]> {
    const startTime = Date.now(); // Record start time
    if (!userIds || userIds.length === 0) {
      return [];
    }

    const token = await this.getM2mToken();
    if (!token) {
      this.logger.error('Cannot call Member API: Failed to obtain M2M token.');
      throw new HttpException(
        'Internal configuration error: Could not authenticate service.',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    const uniqueUserIds = [...new Set(userIds)]; // Ensure unique IDs
    const batchSize = 50; // Reduced batch size to avoid 413/414 errors
    const allMemberInfo: MemberInfoDto[] = [];
    const totalBatches = Math.ceil(uniqueUserIds.length / batchSize);
    const configuredTimeout = Number(
      this.configService.get<string | number>('HTTP_TIMEOUT') ??
        DEFAULT_MEMBER_API_TIMEOUT_MS,
    );
    const requestTimeout = Number.isFinite(configuredTimeout)
      ? configuredTimeout
      : DEFAULT_MEMBER_API_TIMEOUT_MS;

    this.logger.log(
      `Fetching member info for ${uniqueUserIds.length} unique users in ${totalBatches} batches of ${batchSize}...`,
    );

    for (let i = 0; i < uniqueUserIds.length; i += batchSize) {
      const currentBatchNum = Math.floor(i / batchSize) + 1;
      const batchIds = uniqueUserIds.slice(i, i + batchSize);

      const queryParams = new URLSearchParams();
      if (batchIds.length > 1) {
        batchIds.forEach((id) => queryParams.append('userIds', String(id)));
      } else {
        queryParams.append('userId', String(batchIds[0]));
      }
      queryParams.append('fields', MEMBER_LOOKUP_FIELDS.join(','));
      queryParams.append('includeStats', 'false');

      const apiUrl = `${this.MEMBER_API_URL}?${queryParams.toString()}`;

      // Log base URL and count for the current batch
      this.logger.debug(
        `Calling Member API batch ${currentBatchNum}/${totalBatches}: GET ${this.MEMBER_API_URL} for ${batchIds.length} users.`,
      );

      try {
        const response = await firstValueFrom(
          this.httpService.get<MemberInfoDto[]>(apiUrl, {
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
            timeout: requestTimeout,
          }),
        );

        // Basic validation: Check if response.data is an array
        if (!Array.isArray(response.data)) {
          this.logger.error(
            `Member API batch ${currentBatchNum}/${totalBatches} response is not an array:`,
            response.data,
          );
          throw new Error(
            `Unexpected response format from Member API batch ${currentBatchNum}/${totalBatches}`,
          );
        }

        this.logger.debug(
          `Successfully received data for ${response.data.length} users from Member API batch ${currentBatchNum}/${totalBatches}.`,
        );
        allMemberInfo.push(...response.data);
      } catch (error) {
        this.logger.error(
          `Failed to fetch user info batch ${currentBatchNum}/${totalBatches} from Member API: ${error.message}`,
          error.response?.data, // Log response data if available
          error.stack,
        );
        // Rethrow specific HTTP errors if possible, wrapped in a more general error for batch failure
        const status =
          error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
        const message =
          error.response?.data?.message ||
          `Error fetching data batch from Member API (Status: ${status})`;

        // Stop processing further batches on failure
        throw new HttpException(
          `Failed during Member API batch request ${currentBatchNum}/${totalBatches}: ${message}`,
          status,
        );
      }
    }

    const endTime = Date.now(); // Record end time
    const duration = endTime - startTime; // Calculate duration
    this.logger.log(
      `Successfully fetched and combined info for ${allMemberInfo.length} members from ${totalBatches} batches in ${duration}ms.`,
    );
    return allMemberInfo;
  }

  // --- Optional: Add method to fetch a single user by ID or handle ---
  /*
  async getUserInfoById(userId: number): Promise<MemberInfoDto | null> {
      const results = await this.getUserInfoList([userId]);
      if (results.length > 0) {
          return results[0];
      } else {
          // Handle case where user is not found (might be 404 from API or empty array)
          this.logger.warn(`User with ID ${userId} not found via Member API.`);
          return null; // Or throw NotFoundException
      }
  }
  */
}
