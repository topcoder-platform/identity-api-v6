import { ConfigService } from '@nestjs/config';
import { ConfigurationService } from './configuration.service';

describe('Identity issuer configuration', () => {
  const issuers = [
    'https://api.topcoder-dev.com',
    'https://auth.topcoder-dev.com/',
  ];

  it.each([JSON.stringify(issuers), issuers.join(', ')])(
    'preserves exact issuer URLs from JSON or comma-separated configuration',
    (VALID_ISSUERS) => {
      const service = new ConfigurationService(
        new ConfigService({ VALID_ISSUERS }),
      );
      expect(service.getCommon().validIssuers).toEqual(issuers);
    },
  );

  it.each(['[null]', '[123]', '[""]', '[bad'])(
    'rejects malformed issuer configuration: %s',
    (VALID_ISSUERS) => {
      expect(() =>
        new ConfigurationService(
          new ConfigService({ VALID_ISSUERS }),
        ).getCommon(),
      ).toThrow();
    },
  );
});
