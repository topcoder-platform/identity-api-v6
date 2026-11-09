module.exports = {
  rootDir: '.',
  testRegex: 'test/redis.integration-spec.ts$',
  transform: { '^.+\\.(t|j)s$': 'ts-jest' },
  moduleNameMapper: { '^src/(.*)$': '<rootDir>/src/$1' },
  testEnvironment: 'node',
  testTimeout: 15000,
};
