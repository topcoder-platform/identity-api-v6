#!/bin/bash
set -e

# Note: POSTGRES_USER and POSTGRES_DB are default env vars provided by the official postgres image
# POSTGRES_DB is the database created by default. We'll grant privileges on it.

# --- Create missing roles expected by the common_oltp dump ---
echo "[INIT_SCRIPT] Creating additional roles (if they don't exist)..."

# Use DO block to check existence before creating roles
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'topcoder') THEN CREATE ROLE topcoder; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'coder') THEN CREATE ROLE coder; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'db_sales_im') THEN CREATE ROLE db_sales_im; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'veredox') THEN CREATE ROLE veredox; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'openaim') THEN CREATE ROLE openaim; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'truveo') THEN CREATE ROLE truveo; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cockpit') THEN CREATE ROLE cockpit; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'winformula') THEN CREATE ROLE winformula; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'openxtraz') THEN CREATE ROLE openxtraz; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pgsyncuser') THEN CREATE ROLE pgsyncuser; END IF; END\$\$;"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qatcuser') THEN CREATE ROLE qatcuser; END IF; END\$\$;"

# Add any other roles from the error messages if missed
echo "[INIT_SCRIPT] Additional roles check/creation complete."
# -----------------------------------------------------------

echo "[INIT_SCRIPT] Database initialization script finished successfully."