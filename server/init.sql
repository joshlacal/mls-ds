-- init.sql — run once by PostgreSQL on first container start
-- The actual schema is applied by sqlx migrations when the server boots.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant full privileges to the application user
GRANT ALL PRIVILEGES ON DATABASE catbird_mls TO catbird;
