#!/bin/bash

# Set default values if not provided
PGUSER="${PGUSER:-postgres}"
PGPASSWORD="${PGPASSWORD:-}"
PGDATABASE="${PGDATABASE:-postgres}"
PGHOST="${PGHOST:-localhost}"

# Export the password to avoid prompt
export PGPASSWORD="$PGPASSWORD"

# Connect to Postgres and execute role creation commands
psql -U "$PGUSER" -h "$PGHOST" -d "$PGDATABASE" <<EOF
-- Create roles with LOGIN and password same as role name
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pgsyncuser') THEN
        CREATE ROLE pgsyncuser WITH LOGIN PASSWORD 'pgsyncuser';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'qatcuser') THEN
        CREATE ROLE qatcuser WITH LOGIN PASSWORD 'qatcuser';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'coder') THEN
        CREATE ROLE coder WITH LOGIN PASSWORD 'coder';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'topcoder') THEN
        CREATE ROLE topcoder WITH LOGIN PASSWORD 'topcoder';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'db_sales_im') THEN
        CREATE ROLE db_sales_im WITH LOGIN PASSWORD 'db_sales_im';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'veredox') THEN
        CREATE ROLE veredox WITH LOGIN PASSWORD 'veredox';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openaim') THEN
        CREATE ROLE openaim WITH LOGIN PASSWORD 'openaim';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'truveo') THEN
        CREATE ROLE truveo WITH LOGIN PASSWORD 'truveo';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cockpit') THEN
        CREATE ROLE cockpit WITH LOGIN PASSWORD 'cockpit';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'winformula') THEN
        CREATE ROLE winformula WITH LOGIN PASSWORD 'winformula';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openxtraz') THEN
        CREATE ROLE openxtraz WITH LOGIN PASSWORD 'openxtraz';
    END IF;
END
\$\$;
EOF
