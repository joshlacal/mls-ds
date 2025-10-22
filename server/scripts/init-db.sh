#!/bin/bash
set -e

# Database initialization script
# This script is automatically run by postgres on first startup

echo "Initializing Catbird database..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Create extensions
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
    
    -- Grant privileges
    GRANT ALL PRIVILEGES ON DATABASE catbird TO catbird;
    
    -- Create basic tables (migrations will handle the rest)
    CREATE TABLE IF NOT EXISTS _sqlx_migrations (
        version BIGINT PRIMARY KEY,
        description TEXT NOT NULL,
        installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        success BOOLEAN NOT NULL,
        checksum BYTEA NOT NULL,
        execution_time BIGINT NOT NULL
    );
EOSQL

echo "Database initialization complete!"
