## Running the legacy migration

Run `npm ci` in this directory to install the migration dependencies. The
PostgreSQL clients are checked in. The MySQL source uses `mysql2` with
`SOURCE_AUTH_MYSQL_URL`. Set `SOURCE_IDENTITY_PG_URL` and `IDENTITY_DB_URL`
for the source and target PostgreSQL databases, then run `npm run migrate`.

After editing a Prisma schema, install the pinned CLI with
`pnpm install --frozen-lockfile` at the repository root, then run
`npm run generate` in this directory. This regenerates the PostgreSQL clients
and the types used by the MySQL reader.
