// src/types/tc-core-library-js.d.ts

declare module 'tc-core-library-js/lib/auth/m2m' {
  // Define the shape of the function returned by requiring the module.
  // This assumes it returns a function that takes options and returns an M2M client object.
  // The client object likely has a getMachineToken method.
  // Adjust 'any' based on actual library usage if possible.
  interface M2MAuthClient {
    getMachineToken(clientId: string, clientSecret: string): Promise<string>;
    // Add other methods if they exist and are used
  }

  function m2mAuth(options: any): M2MAuthClient;

  export = m2mAuth;
}

declare module 'tc-core-library-js/lib/auth/verifier' {
  interface JwtVerifier {
    validateToken(
      token: string,
      secret: string,
      callback: (error: Error | null, decoded?: Record<string, any>) => void,
    ): void;
  }

  function createJwtVerifier(
    validIssuers: string[],
    jwtKeyCacheTime?: number,
  ): JwtVerifier;

  export = createJwtVerifier;
}

// Add other declarations for different parts of tc-core-library-js if needed
// declare module 'tc-core-library-js/lib/some/other/part' { ... }
