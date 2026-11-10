# Topcoder access tokens with an isolated signing key

This is a staged migration. Deploying the code alone does not switch existing
sessions: `ACCESS_TOKEN_SIGNING_ALGORITHM` defaults to `HS256` until the coordinated
cutover. KMS failures never fall back from RS256 to the legacy secret.

## Signer and verifier separation

The Identity service remains the issuer (`https://api.topcoder.com` in production).
It creates claims only after its existing login or service-account authorization
and server-side role lookup. It hashes the JWT signing input with SHA-256 and asks
KMS to sign that digest using `RSASSA_PKCS1_V1_5_SHA_256` (JWT RS256). The private key
is never exported or stored in SSM, an image, an environment variable or this repo.
There is no public endpoint accepting claims to sign.

`GET /v6/authorizations/.well-known/jwks.json` returns only public RSA fields. It
can publish the public keys while the issuer is still signing legacy tokens, so
verifiers can be prepared before the cutover. It has a five-minute cache lifetime.

Create a **dedicated Identity task role** preserving the service's required
existing permissions. Do not use a role shared with API verifiers. Deploy
`infra/access-token-signing-key.yaml` with this role and a stable administrator
role. Only the Identity task role can perform `kms:Sign`; the key policy explicitly
denies signing by other principals, including broad IAM policies. Key administrators
can change that policy, so protect those administration credentials separately.
The stack retains keys on deletion/replacement; it does not automatically destroy
verification material. No KMS resources are created by application startup.

## Configuration

| Setting | Purpose |
| --- | --- |
| `ACCESS_TOKEN_SIGNING_ALGORITHM` | `HS256` during preparation, `RS256` at cutover |
| `ACCESS_TOKEN_KMS_KEY_ARN` | Immutable RSA SIGN_VERIFY key ARN; aliases are rejected |
| `ACCESS_TOKEN_AUDIENCE` | Explicit API audience, e.g. `https://api.topcoder.com/v6` |
| `ACCESS_TOKEN_TTL_SECONDS` | 900 by default; allowed range 60–86400 |
| `ACCESS_TOKEN_VERIFICATION_KEY_ARNS` | Optional comma-separated retiring public-key ARNs; at most five total |
| `AUTH_DOMAIN` | Existing issuer domain, e.g. `topcoder.com` |

KMS region and credentials use the AWS SDK's task-role/default region resolution.
The current and retiring keys must support RS256 and GetPublicKey for the Identity
role. Publish retired public keys for at least the longest issued token lifetime
plus verifier clock tolerance. The signer always uses the single configured
current key ARN. Public key responses must never include private RSA parameters.

## Coordinated cutover

1. Rotate the compromised legacy secret and separate Identity's one-time proof
   `JWT_SECRET` first. Updating a secret does not change an existing ECS task.
2. Provision the dedicated task role and key. Deploy this code in HS256 mode with
   the public key configured. Verify the public endpoint through the real gateway
   and confirm its cache behavior. Ensure no wildcard authorization route shadows it.
3. Prepare every API verifier, gateway, Community authentication consumer, worker
   and token-refresh flow. Keep production/dev issuers and keys separate. The new
   tc-core verifier supports public `JWT_ISSUER_POLICIES`; set a finite retirement
   deadline for any temporary HS256 policy. Do not migrate only Review.
4. Test the login/refresh experience with the intended shorter lifetime. Update
   consumers that assume 12-hour legacy sessions before enabling a 15-minute TTL.
5. In a coordinated window, switch the Topcoder policy to RS256 and set Identity
   to RS256. A policy must not simultaneously accept HS256 and RS256 for this issuer.
   Existing HS256 access tokens become invalid. Require fresh login/refresh through
   an authorized issuer flow; never translate arbitrary legacy bearer claims into
   newly signed administrator claims.
6. Verify new tokens with the public JWKS, reject old or forged HMAC tokens, and
   check human/machine authorization and the global denylists. Observe login,
   refresh and API error rates before declaring completion.
7. Remove legacy AUTH_SECRET injection from API verifiers and remove old signing
   paths after all consumers migrate. Retain a distinct key and audience for
   purpose-bound Identity proofs; never accept those proofs as API access tokens.

Example Topcoder policy for the hardened tc-core library (public data only):

```json
{
  "issuer": "https://api.topcoder.com",
  "algorithm": "RS256",
  "audience": "https://api.topcoder.com/v6",
  "jwksUri": "https://api.topcoder.com/v6/authorizations/.well-known/jwks.json"
}
```

Keep explicit, separately configured Auth0 RS256 policies for the production M2M
and supported user-token flows. The example is one entry, not a replacement for
all existing trusted providers. Merely checking that a user or role exists cannot
protect against a holder of an accepted HMAC signing key impersonating that user.
