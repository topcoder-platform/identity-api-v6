import { Controller, Get, Header } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AccessTokenSigner } from './access-token-signer.service';

@ApiTags('authorizations')
@Controller('authorizations/.well-known')
export class AccessTokenJwksController {
  constructor(private readonly signer: AccessTokenSigner) {}

  @Get('jwks.json')
  @Header('Cache-Control', 'public, max-age=300')
  @ApiOperation({ summary: 'Public keys for Topcoder-issued access tokens' })
  getKeys() {
    return this.signer.getJwks();
  }
}
