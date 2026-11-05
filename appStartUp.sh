#!/bin/bash
set -eo pipefail

export DATABASE_URL=$(echo -e ${IDENTITY_DB_URL})

echo "Database - running migrations."
node node_modules/prisma/build/index.js migrate deploy

# Start the app
exec env NODE_OPTIONS=--openssl-legacy-provider node dist/main
