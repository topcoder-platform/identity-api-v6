import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { AxiosError } from 'axios';

interface SlackMessagePayload {
  channel: string;
  text: string;
  // Add other Slack API fields if needed (e.g., attachments, blocks)
}

@Injectable()
export class SlackService {
  private readonly logger = new Logger(SlackService.name);
  private readonly slackBotKey: string;
  private readonly slackChannelId: string;
  private readonly slackApiUrl = 'https://slack.com/api/chat.postMessage';
  private readonly topcoderEnv: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
  ) {
    this.slackBotKey = this.configService.get<string>('SLACK_BOT_KEY');
    this.slackChannelId = this.configService.get<string>('SLACK_CHANNEL_ID');
    this.topcoderEnv = this.configService.get<string>('ENV_NAME', 'DEV'); // Default to DEV if not set

    if (!this.slackBotKey || !this.slackChannelId) {
      this.logger.error(
        'Slack service configuration is incomplete. SLACK_BOT_KEY or SLACK_CHANNEL_ID is missing.',
      );
      // Depending on strictness, you might throw an error or allow the service to run in a degraded state.
      // For now, we'll log an error but let it continue, so other parts of the app don't break if Slack isn't critical.
    }
  }

  async sendNotification(message: string, handle?: string): Promise<void> {
    if (!this.slackBotKey || !this.slackChannelId) {
      this.logger.warn(
        'Slack service is not configured. Skipping notification.',
      );
      return;
    }

    const prefix = `[${this.topcoderEnv}]`;
    const fullMessage = handle
      ? `${prefix} ${handle} : ${message}`
      : `${prefix} : ${message}`;

    const payload: SlackMessagePayload = {
      channel: this.slackChannelId,
      text: fullMessage,
    };

    this.logger.debug(
      `Sending Slack notification to channel ${this.slackChannelId}: ${fullMessage}`,
    );

    try {
      await firstValueFrom(
        this.httpService.post(this.slackApiUrl, payload, {
          headers: {
            Authorization: `Bearer ${this.slackBotKey}`,
            'Content-Type': 'application/json; charset=utf-8',
          },
        }),
      );
      this.logger.log('Slack notification sent successfully.');
    } catch (error) {
      const axiosError = error as AxiosError;
      this.logger.error(
        `Error sending Slack notification: ${axiosError.message}`,
        axiosError.stack,
      );
      if (axiosError.response) {
        this.logger.error(
          `Slack API Response Status: ${axiosError.response.status}`,
        );
        this.logger.error(
          `Slack API Response Data: ${JSON.stringify(axiosError.response.data)}`,
        );
      }
      // Not throwing an error here to prevent an internal Slack issue from breaking a core user flow.
      // Depending on requirements, you might want to throw InternalServerErrorException.
    }
  }
}
