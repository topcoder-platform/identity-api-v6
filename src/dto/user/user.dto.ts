import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsString,
  IsEmail,
  IsOptional,
  IsNotEmpty,
  IsBoolean,
  IsObject,
  IsNumber,
  ValidateNested,
  MaxLength,
  MinLength,
  Matches,
  IsArray,
  IsDefined,
  IsUrl,
  Length,
  IsInt,
  Min,
} from 'class-validator';
import { Constants } from '../../core/constant/constants';

// --- Base & Nested DTOs ---

export class CredentialDto {
  @IsString()
  @IsOptional()
  @MinLength(8) // Example validation
  password?: string;

  @IsString()
  @IsOptional()
  currentPassword?: string;

  @IsString()
  @IsOptional()
  resetToken?: string;

  // Add other credential-related fields if needed (activationCode, etc.)
}

export class CountryDto {
  @IsString()
  @IsNotEmpty()
  code: string;

  @IsString()
  @IsOptional()
  name?: string;
}

export class UserProfileDto {
  @IsString()
  @IsNotEmpty()
  provider: string; // e.g., 'github', 'google-oauth2', 'wipro-adfs'

  @IsString()
  @IsNotEmpty()
  userId: string; // The user's ID *within* the provider

  @IsString()
  @IsNotEmpty({ message: 'Profile name cannot be empty' })
  name: string;

  @IsEmail()
  @IsOptional()
  email?: string;

  @IsString()
  @IsOptional()
  providerType?: string; // 'social' or 'enterprise' (derived)

  @IsObject()
  @IsOptional()
  context?: Record<string, any>; // For things like access tokens

  @IsOptional()
  @IsBoolean()
  isEmailVerified?: boolean = false;
}

// --- Request Body Wrapper (Common Pattern) ---

class UserParamBaseDto {
  @IsString()
  @IsOptional()
  @MaxLength(64)
  @Matches(/^[a-zA-Z0-9\-[\]\\_.`{}]{3,}$/, {
    // Basic handle validation
    message: 'Handle contains invalid characters or is too short.',
  })
  handle?: string;

  @IsEmail()
  @IsOptional()
  email?: string;

  @IsString()
  @IsOptional()
  @MaxLength(64)
  firstName?: string;

  @IsString()
  @IsOptional()
  @MaxLength(64)
  lastName?: string;

  @ValidateNested()
  @Type(() => CredentialDto)
  @IsOptional()
  credential?: CredentialDto;

  @ValidateNested()
  @Type(() => CountryDto)
  @IsOptional()
  country?: CountryDto;

  @IsString()
  @IsOptional()
  status?: string; // e.g., 'A' for Active, 'U' for Unverified

  @IsString()
  @IsOptional()
  regSource?: string;

  @IsString()
  @IsOptional()
  utmSource?: string;

  @IsString()
  @IsOptional()
  utmMedium?: string;

  @IsString()
  @IsOptional()
  utmCampaign?: string;

  @IsBoolean()
  @IsOptional()
  isActive?: boolean; // This seems redundant if `status` is primary source of truth

  @IsString()
  @IsOptional()
  primaryRole?: string;

  @ValidateNested()
  @Type(() => UserProfileDto)
  @IsOptional()
  profile?: UserProfileDto; // For linking social profile during registration/update (if flow supports)

  // --- Added Self-Service Fields ---
  @IsString()
  @IsOptional()
  @MaxLength(255)
  description?: string; // For user bio/description

  @IsString()
  @IsOptional()
  @IsUrl() // Validate if it should be a URL
  photoURL?: string;

  @IsString()
  @IsOptional()
  @MaxLength(128)
  company?: string;

  @IsString()
  @IsOptional()
  @MaxLength(128)
  school?: string;

  @IsString()
  @IsOptional()
  @MaxLength(64)
  timeZone?: string;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  tracks?: string[]; // e.g., [DEVELOP, DESIGN, DATA_SCIENCE]

  @IsString()
  @IsOptional()
  @MaxLength(255)
  quote?: string;

  // Home Address
  @IsString()
  @IsOptional()
  @MaxLength(128)
  homeAddress1?: string;

  @IsString()
  @IsOptional()
  @MaxLength(128)
  homeAddress2?: string;

  @IsString()
  @IsOptional()
  @MaxLength(64)
  homeCity?: string;

  @IsString()
  @IsOptional()
  @MaxLength(32)
  homeStateCode?: string;

  @IsString()
  @IsOptional()
  @MaxLength(16)
  homeZip?: string;

  @IsString()
  @IsOptional()
  @Length(2, 3) // ISO 3166-1 alpha-2 or alpha-3
  competitionCountryCode?: string;

  // Work Address could be added similarly if needed
  // @IsString() @IsOptional() @MaxLength(128) workAddress1?: string;

  @IsBoolean()
  @IsOptional()
  emailNotifications?: boolean;

  @IsBoolean()
  @IsOptional()
  sendMarketingEmails?: boolean;

  @IsBoolean()
  @IsOptional()
  copilot?: boolean;

  @IsString()
  @IsOptional()
  @MaxLength(10)
  language?: string;
}

// --- Request Body DTOs (Actual Payloads) ---

// POST /users (Registration)
export class CreateUserBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserParamBaseDto)
  param: UserParamBaseDto; // Java API wraps params
}

// PATCH /users/{resourceId}
export class UpdateUserBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserParamBaseDto)
  param: UserParamBaseDto;
}

// POST /users/{userId}/SSOUserLogin
// PUT /users/{userId}/SSOUserLogin
export class CreateUpdateSSOBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserProfileDto)
  param: UserProfileDto; // Uses UserProfile directly in param
}

// PUT /users/resetPassword
export class ResetPasswordBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserParamBaseDto) // Contains credential.resetToken and credential.password
  param: UserParamBaseDto;
}

// --- 2FA / OTP DTOs (Moved UserOtpDto earlier) ---

export class UserOtpDto {
  @IsNumber()
  @IsOptional() // Not always required in request
  userId?: number;

  @IsString()
  @IsOptional()
  @Length(6, 6)
  otp?: string;

  @IsString()
  @IsOptional()
  resendToken?: string;
}

// PUT /users/activate
export class ActivateUserBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserOtpDto) // Use UserOtpDto within param
  param: UserOtpDto;
}

// PATCH /users/{resourceId}/handle
export class UpdateHandleBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserParamBaseDto) // Contains handle
  param: UserParamBaseDto;
}

// PATCH /users/{resourceId}/email
export class UpdateEmailBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserParamBaseDto) // Contains email
  param: UserParamBaseDto;
}

// POST /users/{resourceId}/profiles
export class CreateProfileBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserProfileDto) // Uses UserProfile directly in param
  param: UserProfileDto;
}

// PATCH /users/{resourceId}/status
export class UpdateStatusBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserParamBaseDto) // Contains status
  param: UserParamBaseDto;
}

// POST /users/updatePrimaryRole
export class UpdatePrimaryRoleBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserParamBaseDto) // Contains primaryRole
  param: UserParamBaseDto;
}

// --- 2FA / OTP DTOs ---

export class User2faDto {
  @IsBoolean()
  @IsOptional()
  mfaEnabled?: boolean;

  @IsBoolean()
  @IsOptional()
  diceEnabled?: boolean;
}

export class UpdateUser2faBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => User2faDto)
  param: User2faDto;
}

export class SendOtpBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserOtpDto) // Contains userId
  param: UserOtpDto;
}

export class ResendOtpEmailBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserOtpDto) // Contains userId and resendToken
  param: UserOtpDto;
}

export class CheckOtpBodyDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => UserOtpDto) // Contains userId and otp
  param: UserOtpDto;
}

// POST /dice-status (Webhook payload from DICE)
export class DiceStatusWebhookBodyDto {
  @IsString()
  @IsNotEmpty()
  event: string; // e.g., "connection-invitation", "connection-response", "credential-issuance"

  @IsString()
  @IsNotEmpty()
  connectionId: string;

  @IsEmail()
  @IsOptional()
  emailId?: string;

  @IsUrl()
  @IsOptional()
  shortUrl?: string;

  // Add other potential fields from DICE webhook
}

// --- Response DTOs ---

export class UserResponseDto {
  id: string;
  handle: string;
  email?: string; // Primary email
  firstName?: string;
  lastName?: string;
  status: string;
  roles?: any[]; // Simplified for now
  profiles?: UserProfileDto[]; // Social/SSO profiles
  mfaEnabled?: boolean;
  emailVerified?: boolean;
  createdAt?: string;
  updatedAt?: string;
  // Add other fields as needed based on FieldSelector
}

export class ValidationResponseDto {
  valid: boolean;
  reasonCode?: string;
  reason?: string;
}

export class AchievementDto {
  // Matches existing API/tests expectations
  achievement_type_id: number;
  achievement_desc: string;
  date: Date;
  // Optional additional description from user_achievement table
  description?: string | null;
}

export class DiceConnectionResponseDto {
  diceEnabled: boolean;
  connection?: string; // Connection URL from DICE
  accepted?: boolean;
}

export class UserOtpResponseDto {
  verified?: boolean;
  blocked?: boolean;
  expired?: boolean;
  resendToken?: string;
}

// DTO for one-time token response
export class OneTimeTokenResponseDto {
  token: string;
}

// Placeholder DTO for user search queries
export class UserSearchQueryDto {
  @IsString()
  @IsOptional()
  @ApiPropertyOptional({
    name: 'filter',
    type: String,
    description: "Legacy filter string in the form 'field=value'",
  })
  filter?: string;

  @IsString()
  @IsOptional()
  @ApiPropertyOptional({
    name: 'handle',
    type: String,
    description: 'member handle',
  })
  handle?: string;

  @IsEmail()
  @IsOptional()
  @ApiPropertyOptional({
    name: 'email',
    type: String,
    description: 'member email',
  })
  email?: string;

  @IsInt()
  @Min(1)
  @IsOptional()
  @ApiPropertyOptional({
    name: 'limit',
    type: Number,
    description: 'Default 20',
  })
  limit?: number = Constants.defaultPageSize;

  @IsInt()
  @Min(0)
  @IsOptional()
  @ApiPropertyOptional({
    name: 'offset',
    type: Number,
    description: 'Default 0',
  })
  offset?: number = 0;

  // Add other potential search fields: status, role, etc.
}

// --- Added for UserController.deleteSSOUserLogin ---
export class DeleteSSOUserLoginQueryDto {
  @IsString()
  @IsOptional()
  provider?: string; // Provider name (e.g., 'okta-customer')

  @IsNumber()
  @IsOptional()
  @Type(() => Number) // Ensure transformation from string query param
  providerId?: number; // Provider ID (numeric)

  @IsString()
  @IsNotEmpty() // ssoUserId is crucial for identifying the specific link
  ssoUserId: string; // The user's ID on the external provider system
}
