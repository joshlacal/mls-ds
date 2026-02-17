-- init-federation-dbs.sql — Create both databases for Docker Compose federation setup.
-- PostgreSQL creates catbird_mls_1 via POSTGRES_DB; this script creates catbird_mls_2.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create second database for Instance 2
CREATE DATABASE catbird_mls_2 OWNER catbird;

-- Enable extensions on second database
\c catbird_mls_2
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
GRANT ALL PRIVILEGES ON DATABASE catbird_mls_2 TO catbird;
