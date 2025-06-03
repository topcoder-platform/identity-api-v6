import {
  Injectable,
  Inject,
  Logger,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import {
  PrismaClient as PrismaClientCommonOltp,
  Prisma,
} from '@prisma/client-common-oltp';
import { PRISMA_CLIENT_COMMON_OLTP } from '../../shared/prisma/prisma.module';
import * as DTOs from '../../dto/user/user.dto';

// Basic email regex, can be refined
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Basic handle regex: 3-64 chars, alphanumeric, and specific special characters _ . - ` [ ] { }
const HANDLE_REGEX = /^[a-zA-Z0-9\-\[\]_\.`\{\}]{3,64}$/;
// TODO: Add list of reserved handles if necessary
const RESERVED_HANDLES = ['admin', 'support', 'root', 'administrator']; // Example

@Injectable()
export class ValidationService {
  private readonly logger = new Logger(ValidationService.name);

  constructor(
    @Inject(PRISMA_CLIENT_COMMON_OLTP)
    private readonly prismaOltp: PrismaClientCommonOltp,
  ) {}

  async validateHandle(handle: string): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(`Validating handle: ${handle}`);
    if (!handle) {
      throw new BadRequestException('Handle cannot be empty.');
    }
    if (!HANDLE_REGEX.test(handle)) {
      throw new BadRequestException(
        'Handle must be 3-64 characters long and can only contain alphanumeric characters and _.-`[]{} symbols.',
      );
    }
    if (RESERVED_HANDLES.includes(handle.toLowerCase())) {
      throw new BadRequestException(`Handle '${handle}' is reserved.`);
    }

    const existingUser = await this.prismaOltp.user.findFirst({
      where: { handle_lower: handle.toLowerCase() },
    });

    if (existingUser) {
      this.logger.warn(`Validation failed: Handle '${handle}' already exists.`);
      throw new ConflictException(`Handle '${handle}' is already taken.`);
    }
    this.logger.log(`Handle '${handle}' is valid and available.`);
    return { valid: true };
  }

  async validateEmail(email: string): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(`Validating email: ${email}`);
    if (!email) {
      throw new BadRequestException('Email cannot be empty.');
    }
    if (!EMAIL_REGEX.test(email)) {
      throw new BadRequestException('Invalid email format.');
    }

    // Check if email exists in the email table and is associated with a user
    const existingEmailRecord = await this.prismaOltp.email.findFirst({
      where: {
        address: email.toLowerCase(),
        // user_id: { not: null } // Ensures it's linked to a user. If an email can exist unlinked, this check is important.
        // For registration, any email record might be considered a conflict.
        // Let's assume for now that if an email address exists in the table, it's considered taken.
      },
      select: { user_id: true }, // We only need to know if it exists and if it has a user_id
    });

    // If a record for this email address exists AND it has a user_id, it means the email is in use.
    if (existingEmailRecord && existingEmailRecord.user_id !== null) {
      this.logger.warn(
        `Validation failed: Email '${email}' already exists and is associated with user ID: ${existingEmailRecord.user_id}.`,
      );
      throw new ConflictException(`Email '${email}' is already in use.`);
    }

    // If existingEmailRecord is null, or if it exists but user_id is null (orphaned, less likely/problematic for new registration),
    // the email is considered available.
    this.logger.log(`Email '${email}' is valid and available.`);
    return { valid: true };
  }

  async validateSocial(
    provider: string,
    socialUserId: string,
  ): Promise<DTOs.ValidationResponseDto> {
    this.logger.log(
      `Validating social login: provider=${provider}, socialUserId=${socialUserId}`,
    );
    if (!provider || typeof provider !== 'string' || provider.trim() === '') {
      throw new BadRequestException('Provider must be a non-empty string.');
    }
    if (
      !socialUserId ||
      typeof socialUserId !== 'string' ||
      socialUserId.trim() === ''
    ) {
      throw new BadRequestException(
        'Social User ID must be a non-empty string.',
      );
    }

    // Basic validation passed.
    // TODO: Add further validation if needed, e.g., check against known providers, format of socialUserId, or existence in DB.
    this.logger.log(
      `Basic validation for social login (${provider}: ${socialUserId}) passed.`,
    );
    return { valid: true };
  }

  async validateCountry(countryCode: string): Promise<void> {
    this.logger.log(`Validating country: ${countryCode}`);
    if (!countryCode) {
      throw new BadRequestException('Country code cannot be empty.');
    }
    const countryRecord = await this.prismaOltp.country.findUnique({
      where: { country_code: countryCode },
    });
    if (!countryRecord) {
      throw new BadRequestException(
        `Country code '${countryCode}' is not valid.`,
      );
    }
    // Add more specific validation if needed (e.g. participating status)
    this.logger.debug(`Country code '${countryCode}' validated.`);
  }

  // General TODO for porting other validation methods removed, focus is on existing methods.
  // // TODO: Add other specific validation methods as needed from UserResource/DAO
  // // - validateTerm
  // // - validateReferral
  // // - validateUserProfile
}
