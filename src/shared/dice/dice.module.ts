import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { DiceService } from './dice.service';

@Module({
  imports: [
    ConfigModule, // Ensure ConfigService is available
    HttpModule, // For making external API calls
  ],
  providers: [DiceService],
  exports: [DiceService], // Export if other modules will use it directly
})
export class DiceModule {}
