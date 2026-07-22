#!/bin/bash
set -eo pipefail

export DATABASE_URL=$(echo -e ${IDENTITY_DB_URL})

echo "Database - running migrations."
if $RESET_DB; then
    echo "Resetting DB"
    node node_modules/prisma/build/index.js migrate reset --force
else
    echo "Running migrations"
    node node_modules/prisma/build/index.js migrate deploy
fi

# Start the app
exec env NODE_OPTIONS=--openssl-legacy-provider node dist/main
