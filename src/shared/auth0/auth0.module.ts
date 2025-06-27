import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { Auth0Service } from './auth0.service';
import { ConfigurationModule } from 'src/config/configuration.module';

@Module({
  imports: [
    ConfigurationModule,
    HttpModule,
  ],
  providers: [Auth0Service],
  exports: [Auth0Service],
})
export class Auth0Module {}
