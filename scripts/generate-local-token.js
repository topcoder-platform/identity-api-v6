// Usage: node scripts/generate-local-token.js [userId] [roles] [handle] [email] [scopes] [expiresIn]
// Example: node scripts/generate-local-token.js 8547899 administrator,Topcoder\ User TonyJ tjefths+fix@topcoder.com read:users,write:users 1h

require('dotenv').config(); // Load .env variables
const jwt = require('jsonwebtoken');

// --- Configuration ---
const secret = process.env.AUTH_SECRET;
const issuer = process.env.JWT_ISSUER_URL || 'https://api.topcoder-dev.com';
const audience = process.env.JWT_AUDIENCE || 'www.example.com';

// --- Defaults ---
const defaultUserId = '40141235'; // Admin role assigned to this user
const defaultRoles = ['administrator', 'Topcoder User'];
const defaultHandle = 'TonyJ';
const defaultEmail = 'tjefths+fix@topcoder.com';
const defaultScopes = ['read:users', 'write:users']; // Added default scopes
const defaultExpiresIn = '8h'; // Default expiry

// --- Get Args ---
const userId = process.argv[2] || defaultUserId;
const rolesArg = process.argv[3];
const handle = process.argv[4] || defaultHandle;
const email = process.argv[5] || defaultEmail;
const scopesArg = process.argv[6]; // New argument for scopes
const expiresIn = process.argv[7] || defaultExpiresIn; // Shifted argument for expiresIn

const roles = rolesArg ? rolesArg.split(',').map(r => r.trim()) : defaultRoles;
const scopes = scopesArg ? scopesArg.split(',').map(s => s.trim()) : defaultScopes; // Process scopes

// --- Validate Secret ---
if (!secret || secret === 'your-local-dev-secret-key-placeholder' || secret === 'your-local-dev-secret-key-CHANGE-ME!') {
  console.error('Error: AUTH_SECRET is not set or is using the placeholder value in .env');
  console.error('Please set a strong, unique secret in your .env file.');
  process.exit(1);
}

// --- Create Payload ---
const payload = {
  iss: issuer,
  aud: audience,
  userId: userId,
  roles: roles,
  handle: handle,
  email: email,
  scopes: scopes, // Add scopes to payload
  // Add iat automatically by library
};

// --- Generate Token ---
try {
  const token = jwt.sign(payload, secret, { expiresIn: expiresIn, algorithm: 'HS256' });
  console.log('Generated Local HS256 Token:');
  console.log(token);
} catch (error) {
  console.error('Error generating token:', error.message);
  process.exit(1);
} 