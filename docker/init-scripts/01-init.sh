#!/bin/bash
set -e

# Note: POSTGRES_USER and POSTGRES_DB are default env vars provided by the official postgres image
# POSTGRES_DB is the database created by default. We'll grant privileges on it.

echo "[INIT_SCRIPT] Granting privileges on default database: $POSTGRES_DB"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -c "GRANT ALL PRIVILEGES ON DATABASE \"$POSTGRES_DB\" TO $POSTGRES_USER;"
echo "[INIT_SCRIPT] Privileges granted on default DB."

# Determine which DB name is NOT the default one
SECOND_DB_NAME=""
if [ "$POSTGRES_DB" == "$COMMON_OLTP_DB_NAME" ]; then
  SECOND_DB_NAME="$AUTHORIZATION_DB_NAME"
elif [ "$POSTGRES_DB" == "$AUTHORIZATION_DB_NAME" ]; then
  SECOND_DB_NAME="$COMMON_OLTP_DB_NAME"
else
  echo "[INIT_SCRIPT] Warning: POSTGRES_DB ('$POSTGRES_DB') does not match COMMON_OLTP_DB_NAME ('$COMMON_OLTP_DB_NAME') or AUTHORIZATION_DB_NAME ('$AUTHORIZATION_DB_NAME'). Attempting creation for both if they don't exist."
  # Attempt to create COMMON_OLTP_DB_NAME if it wasn't the default and doesn't exist
  if [ "$POSTGRES_DB" != "$COMMON_OLTP_DB_NAME" ]; then
      echo "[INIT_SCRIPT] Checking/Creating database: $COMMON_OLTP_DB_NAME"
      # Check if DB exists before creating
      if ! psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "postgres" -tc "SELECT 1 FROM pg_database WHERE datname = '$COMMON_OLTP_DB_NAME'" | grep -q 1; then
          psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "CREATE DATABASE \"$COMMON_OLTP_DB_NAME\" OWNER $POSTGRES_USER;"
      else
          echo "[INIT_SCRIPT] Database '$COMMON_OLTP_DB_NAME' already exists."
      fi
      echo "[INIT_SCRIPT] Granting privileges on $COMMON_OLTP_DB_NAME"
      psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "GRANT ALL PRIVILEGES ON DATABASE \"$COMMON_OLTP_DB_NAME\" TO $POSTGRES_USER;"
      echo "[INIT_SCRIPT] $COMMON_OLTP_DB_NAME privileges done."
  fi
  # Set the second DB name to AUTHORIZATION_DB_NAME for the logic below
  SECOND_DB_NAME="$AUTHORIZATION_DB_NAME"
fi

# Check and Create the second database if determined and doesn't exist
if [ -n "$SECOND_DB_NAME" ]; then
  echo "[INIT_SCRIPT] Checking second database existence: $SECOND_DB_NAME"
  psql_output=$(psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "postgres" -tAc "SELECT 1 FROM pg_database WHERE datname = '$SECOND_DB_NAME'")
  if [ $? -ne 0 ]; then
      echo "[INIT_SCRIPT][ERROR] Failed to check existence for database '$SECOND_DB_NAME'."
      exit 1
  fi

  if [ "$psql_output" != "1" ]; then
    echo "[INIT_SCRIPT] Creating second database: $SECOND_DB_NAME"
    psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "CREATE DATABASE \"$SECOND_DB_NAME\" OWNER $POSTGRES_USER;"
    echo "[INIT_SCRIPT] Second database '$SECOND_DB_NAME' created."
  else
    echo "[INIT_SCRIPT] Second database '$SECOND_DB_NAME' already exists."
  fi

  # Always ensure privileges are granted
  echo "[INIT_SCRIPT] Granting privileges on second database: $SECOND_DB_NAME"
  psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" -c "GRANT ALL PRIVILEGES ON DATABASE \"$SECOND_DB_NAME\" TO $POSTGRES_USER;"
  echo "[INIT_SCRIPT] Privileges granted on second database."

else
   echo "[INIT_SCRIPT] Second database name could not be determined or wasn't needed."
fi


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