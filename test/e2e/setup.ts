// Ensure test environment
if (process.env.NODE_ENV !== 'test') {
  process.env.NODE_ENV = 'test';
}

// Use local PostgreSQL with identity_test2 database for testing
if (
  !process.env.IDENTITY_DB_URL ||
  !process.env.IDENTITY_DB_URL.includes('identity_test2')
) {
  // Update this connection string based on your local PostgreSQL setup
  // Format: postgresql://username:password@localhost:5432/identity_test2
  process.env.IDENTITY_DB_URL =
    'postgresql://postgres:postgres@localhost:5432/identity_test2';
}

// Extend Jest matchers
expect.extend({
  toContainObject(received: any[], expected: any) {
    const pass = received.some((item) =>
      Object.keys(expected).every((key) => item[key] === expected[key]),
    );

    if (pass) {
      return {
        message: () =>
          `expected ${JSON.stringify(received)} not to contain object ${JSON.stringify(expected)}`,
        pass: true,
      };
    } else {
      return {
        message: () =>
          `expected ${JSON.stringify(received)} to contain object ${JSON.stringify(expected)}`,
        pass: false,
      };
    }
  },
});

// Global setup
beforeAll(() => {
  // noop
});

afterAll(async () => {
  // noop
});
