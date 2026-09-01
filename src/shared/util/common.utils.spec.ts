import { BadRequestException } from '@nestjs/common';
import { CommonUtils } from './common.utils';

describe('CommonUtils', () => {
  describe('hashCode', () => {
    it('preserves the established deterministic 32-bit hash', () => {
      expect(CommonUtils.hashCode({ id: '123', target: '1' })).toBe(
        CommonUtils.hashCode({ id: '123', target: '1' }),
      );
    });

    it('rejects payloads that would cause unbounded hashing work', () => {
      expect(() => CommonUtils.hashCode({ value: 'a'.repeat(8193) })).toThrow(
        BadRequestException,
      );
    });
  });

  describe('generateAlphaNumericString', () => {
    it('returns a secret-safe alphanumeric string of the requested length', () => {
      expect(CommonUtils.generateAlphaNumericString(32)).toMatch(
        /^[A-Za-z0-9]{32}$/,
      );
    });
  });
});
