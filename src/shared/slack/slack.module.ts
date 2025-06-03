import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { SlackService } from './slack.service';

@Module({
  imports: [
    ConfigModule, // Ensure ConfigService is available
    HttpModule, // For making external API calls
  ],
  providers: [SlackService],
  exports: [SlackService], // Export if other modules will use it directly
})
export class SlackModule {}
