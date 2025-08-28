import {
  Injectable,
  Inject,
  Logger,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { firstValueFrom } from 'rxjs';
import { MemberInfoDto } from '../../dto/member/member.dto';
import { M2M_AUTH_CLIENT } from './member-api.constants'; // Import M2M client token from constants

// Define the interface for the M2M Auth client provided by the module
// Based on the declaration file src/types/tc-core-library-js.d.ts
interface M2MAuthClient {
  getMachineToken(clientId: string, clientSecret: string): Promise<string>;
}

@Injectable()
export class MemberApiService {
  private readonly logger = new Logger(MemberApiService.name);
  private readonly M2M_TOKEN_CACHE_KEY = 'member_api_m2m_token';
  private readonly MEMBER_API_URL: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
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
  }

  /**
   * Gets a valid M2M token for Member API, using the injected M2M client and cache.
   */
  private async getM2mToken(): Promise<string | null> {
    const cachedToken = await this.cacheManager.get<string>(
      this.M2M_TOKEN_CACHE_KEY,
    );
    if (cachedToken) {
      this.logger.debug('Using cached M2M token for Member API.');
      return cachedToken;
    }

    this.logger.log(
      'No cached M2M token found for Member API, fetching new one via m2mAuthClient...',
    );

    const clientId = this.configService.get<string>('AUTH0_CLIENT_ID');
    const clientSecret = this.configService.get<string>('AUTH0_CLIENT_SECRET');

    if (!clientId || !clientSecret) {
      this.logger.error(
        'AUTH0_CLIENT_ID or AUTH0_CLIENT_SECRET missing in config. Cannot fetch M2M token.',
      );
      return null; // Cannot proceed without credentials
    }

    try {
      const newToken = await this.m2mAuthClient.getMachineToken(
        clientId,
        clientSecret,
      );

      if (newToken) {
        const cacheTtlSeconds = this.configService.get<number>(
          'TOKEN_CACHE_TIME',
          23 * 60 * 60, // Default to 23 hours
        );
        const effectiveTtlSeconds = Math.max(60, cacheTtlSeconds - 60); // Cache slightly less

        await this.cacheManager.set(
          this.M2M_TOKEN_CACHE_KEY,
          newToken,
          effectiveTtlSeconds * 1000,
        );
        this.logger.log(
          `Cached new M2M token for Member API for ${effectiveTtlSeconds} seconds.`,
        );
        return newToken;
      } else {
        this.logger.error(
          'm2mAuthClient.getMachineToken returned null/empty token without error.',
        );
        return null;
      }
    } catch (error) {
      this.logger.error(
        `Error fetching M2M token via m2mAuthClient: ${error.message}`,
        error.stack,
      );
      return null; // Return null on fetch failure
    }
  }

  /**
   * Fetches member information for a list of user IDs from the Member API.
   * Handles large lists by batching requests and logs total execution time.
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

    this.logger.log(
      `Fetching member info for ${uniqueUserIds.length} unique users in ${totalBatches} batches of ${batchSize}...`,
    );

    for (let i = 0; i < uniqueUserIds.length; i += batchSize) {
      const currentBatchNum = Math.floor(i / batchSize) + 1;
      const batchIds = uniqueUserIds.slice(i, i + batchSize);

      // Construct query string by repeating the key
      const queryString =
        batchIds.length > 1
          ? batchIds.map((id) => `userIds=${encodeURIComponent(id)}`).join('&')
          : `userId=${encodeURIComponent(batchIds[0])}`;
      const apiUrl = `${this.MEMBER_API_URL}?fields=handle,email,userId&${queryString}`;

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
            // Consider adding a reasonable timeout per batch request
            // timeout: this.configService.get<number>('HTTP_TIMEOUT', 10000),
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
