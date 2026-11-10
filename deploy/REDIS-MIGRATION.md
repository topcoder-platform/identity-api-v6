# PM-6691: encrypted dev identity cache

Dev identity currently uses `REDIS_HOST=apirediscache.topcoder.com`, whose private
CNAME points to the standalone Redis OSS 6.2.6 `apicache` cluster. The replacement
is the `identity-api-v6-dev-cache` CloudFormation stack/replication group in
account `811668436784`, region `us-east-1`.

The replacement uses Valkey 9.1, one `cache.t4g.micro` node, cluster mode disabled,
required TLS, encryption at rest, and seven-day automatic snapshot retention.
Its security group admits port 6379 from the existing identity task security
group `sg-afba72dd`. This is the existing single-node dev availability model;
it does not add a replica or Multi-AZ failover. The stack retains a snapshot on
cache replacement/deletion and has termination protection enabled. Its deployed
CloudFormation template is the source of infrastructure configuration.

The initial restore is from `pm-6691-apicache-20261109`. The original `apicache`
and its DNS record remain available for rollback. The encrypted `v6identity`
cluster is a separate resource and is not used by this change. Keycloak is
outside this migration.

Prepared on November 9, 2026:

- Primary endpoint: `master.identity-api-v6-dev-cache.056cmt.use1.cache.amazonaws.com:6379`.
- The new `REDIS_URL` SecureString is version 1. The legacy host and port
  parameters were not changed.
- Task revision `identity-api-v6:150` adds only the `REDIS_URL` secret reference
  to revision 149. It retains image digest
  `sha256:bc31bde69612e9d09394fbc66c26b8990e7913027a9336793330f9e29b3328ce`.
  This stages the binding; it does not deploy the code in this PR.
- A disposable ECS task in the identity VPC verified a TLS `PING`, a synthetic
  write/read/TTL/delete cycle, and rejection of plaintext connections. The
  restored database had 12 keys before and after the test. The task received
  no identity application secrets.

## Configuration and application behavior

- `/config/identity-api-v6/appvar/REDIS_URL` is a SecureString containing
  `rediss://<replacement-primary-endpoint>:6379`. Use the AWS endpoint, not the
  legacy custom CNAME, so certificate hostname verification succeeds.
- The identity ECS task definition must bind `REDIS_URL` to that exact parameter
  ARN. The pinned deployment suite preserves existing secret references; merely
  creating the parameter does not inject it into tasks.
- The binding can be staged with the current image, which does not read
  `REDIS_URL`. It continues to use unchanged `REDIS_HOST`/`REDIS_PORT`. Do not
  overwrite those parameters or the old CNAME before the new code is deployed.
- This PR makes `REDIS_URL` take precedence for both `AuthDataStore` and the Nest
  cache. Without it, host/port continue to work for local development and the
  current production configuration. Production infrastructure is not changed.
- `rediss://` requires TLS 1.2 or later with certificate and hostname verification.
  Neither client disables verification or falls back from TLS to plaintext.
- The Nest cache now uses a Keyv Redis store through `stores`, replacing the
  obsolete `cache-manager-ioredis` configuration that was ignored by Nest cache
  manager v3. Startup checks connectivity. Cache values are shared across tasks
  under `identity-api-v6::`; per-entry TTLs remain milliseconds.
- Authorization entries retain the existing `ap:identity:authorization:` key
  format, JSON serialization, and 7,776,000-second (90-day) TTL.

## Cutover gate before merging/deploying

The initial restored snapshot is a preparation step, not ongoing replication.
The PR must not be deployed on the assumption that a snapshot stays current.

1. Recheck the running task revision and confirm only identity will consume the
   new `REDIS_URL`. Check the old cache's clients and command activity from inside
   the VPC; the investigation's quiet metrics are not proof of no future writes.
2. Pause identity authorization mutations for the final migration window. Check
   all Redis databases, counts, key types, and TTLs without logging token values.
   Confirm that the old authorization state still matches the restored state.
   If it has changed, refresh the replacement from a fresh snapshot or perform
   a controlled transfer preserving TTLs before resuming writes. Account for
   deletions/revocations as well as newly created sessions. Do not merge until
   the replacement reflects the final source state.
3. Merge/deploy this PR to dev. Avoid overlapping old/new writers during cutover;
   the existing service normally uses rolling deployments. Keep mutations paused
   until all old tasks have drained and the new task is healthy. Existing
   process-local OAuth/OTP flows cannot be carried across the restart; exercise
   new flows after deployment.
4. Validate authorization creation/read/refresh/logout, OAuth state, password
   reset, and email-change/OTP flows. Confirm shared cache behavior across tasks,
   encrypted connections, TTLs, and no Redis/certificate errors. Run the normal
   identity health check and verify the deployed image digest.
5. Observe before retiring the original cache. Do not delete `apicache`, its DNS
   record, or snapshots as part of this PR. Complete retirement before Redis OSS
   6 extended-support charges begin on February 1, 2027.

## Rollback

The previous image ignores `REDIS_URL` and still reads the old host/port, so its
configuration remains usable. However, after any writes on the new cache, a
simple image rollback would lose new sessions and could resurrect sessions that
were revoked after cutover. Pause mutations and reconcile state first, or make
an explicit session-invalidation decision. Never switch back to a stale snapshot
while authorization traffic continues. Keep both caches and their snapshots
until the rollback window ends.

## Verification

Unit tests cover URL precedence, legacy settings, invalid configuration, verified
TLS options, authorization TTLs, connection failures, and shutdown cleanup:

```sh
pnpm exec jest --runInBand src/config/redis.config.spec.ts src/api/authorization/auth-data-store.service.spec.ts
```

The integration suite requires a disposable Redis/Valkey instance. It writes only
uniquely prefixed synthetic test keys and deletes them, but must never be pointed
at an application cache. It constructs two independent Nest modules and verifies
shared values, expiry in milliseconds, deletion, and the authorization format/TTL.

```sh
REDIS_TEST_URL=redis://127.0.0.1:16379 pnpm exec jest --config jest.redis.config.js --runInBand
NODE_EXTRA_CA_CERTS=/path/to/test-ca.crt REDIS_TEST_URL=rediss://localhost:16380 pnpm exec jest --config jest.redis.config.js --runInBand
```

The TLS test server must present a certificate trusted by `test-ca.crt` and valid
for `localhost` only. The suite verifies that both clients reject the same server
when addressed by `127.0.0.1`. No certificate-verification bypass is used.
