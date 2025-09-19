import { BadRequestException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as tokenValidator from 'tc-core-library-js';
import _ from 'lodash';
import { Constants } from '../../core/constant/constants';

export class CommonUtils {
  private constructor() {}

  static validateString(str: string | null | undefined) {
    if (str == null || str.trim().length === 0) {
      return false;
    }
    return true;
  }

  static validateStringThrow(str: string | null | undefined) {
    if (str == null || str.trim().length === 0) {
      throw new BadRequestException('Bad Request');
    }
  }

  static hashCode(obj: any): number {
    const str = JSON.stringify(obj);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return hash;
  }

  static parseJWTHeader(token: string): Record<string, any> {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === 'string') {
      throw new Error('Invalid JWT token');
    }
    return decoded.header as Record<string, any>;
  }

  static parseJWTClaims(token: string): Record<string, any> {
    const decoded = jwt.decode(token);
    if (!decoded || typeof decoded === 'string') {
      throw new Error('Invalid JWT token');
    }
    return decoded as Record<string, any>;
  }

  static generateJwt(payload, secret, opts): string {
    return jwt.sign(payload, secret, opts) as string;
  }

  static createIssuerFor(authDomain: string): string {
    if (authDomain == null || authDomain.length === 0) {
      throw new Error('authDomain must be specifeid.');
    }
    return `https://api.${authDomain}`;
  }

  static async verifyJwtToken(
    token: string,
    validIssuers: string[],
    secret: string,
  ): Promise<Record<string, any>> {
    const validator = tokenValidator.auth.verifier(validIssuers);
    return new Promise((resolve, reject) => {
      validator.validateToken(token, secret, (err, decoded) => {
        if (err) {
          return reject(new Error(err));
        }
        resolve(decoded);
      });
    });
  }

  static pick<T>(obj: T, keys: string[]) {
    return _.pick(obj, keys);
  }

  static pickArray<T>(objs: T[], keys: string[]) {
    return _.map(objs, (obj) => _.pick(obj, keys));
  }

  /**
   * Generate random string of letters and numbers with given length.
   * @param length random string length
   * @returns random string
   */
  static generateAlphaNumericString(length: number) {
    const chars = Constants.ALPHABET_ALPHA_EN + Constants.ALPHABET_DIGITS_EN;
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
}
