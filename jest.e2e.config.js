module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: '.',
  testRegex: '.e2e-spec.ts$',
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  testEnvironment: 'node',
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@test/(.*)$': '<rootDir>/test/$1',
  },
  collectCoverageFrom: [
    'src/api/identity-provider/**/*.{ts,js}',
    '!src/api/identity-provider/*.module.ts',
    '!src/api/identity-provider/index.ts',
    '!src/**/*.d.ts',
    '!src/**/*.interface.ts',
  ],
  coverageDirectory: './coverage/e2e',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
  testTimeout: 30000,
  setupFilesAfterEnv: ['<rootDir>/test/e2e/setup.ts'],
};
