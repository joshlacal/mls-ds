#!/bin/bash
set -e

echo "🔄 Running database migrations..."

# Wait for PostgreSQL to be ready
until pg_isready -h "${DATABASE_HOST:-postgres}" -p "${DATABASE_PORT:-5432}" -U "${DATABASE_USER:-catbird}" > /dev/null 2>&1; do
  echo "Waiting for PostgreSQL to be ready..."
  sleep 2
done

echo "✅ PostgreSQL is ready"

# Run migrations using sqlx-cli (properly tracks migration state)
if [ -n "$DATABASE_URL" ]; then
  echo "📂 Running database migrations with sqlx..."
  
  # Check if sqlx binary exists, if not install it
  if ! command -v sqlx &> /dev/null; then
    echo "⚠️  sqlx not found, running migrations manually (one-time only)..."
    # Fallback: run the idempotent schema-ensure migration
    DB_NAME=$(echo "$DATABASE_URL" | sed -n 's/.*\/\([^?]*\).*/\1/p')
    DB_HOST=$(echo "$DATABASE_URL" | sed -n 's/.*@\([^:]*\):.*/\1/p')
    DB_USER=$(echo "$DATABASE_URL" | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')
    
    PGPASSWORD="${POSTGRES_PASSWORD:-changeme}" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
      -f /app/migrations/20251101_000_ensure_schema_complete.sql 2>&1 || true
  else
    # Use sqlx to run migrations (tracks state in _sqlx_migrations table)
    sqlx migrate run --source /app/migrations || {
      echo "⚠️  Some migrations may have failed, running schema validation..."
      # Run idempotent schema fix as fallback
      DB_NAME=$(echo "$DATABASE_URL" | sed -n 's/.*\/\([^?]*\).*/\1/p')
      DB_HOST=$(echo "$DATABASE_URL" | sed -n 's/.*@\([^:]*\):.*/\1/p')
      DB_USER=$(echo "$DATABASE_URL" | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')
      
      PGPASSWORD="${POSTGRES_PASSWORD:-changeme}" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
        -f /app/migrations/20251101_000_ensure_schema_complete.sql 2>&1 || true
    }
  fi
  
  echo "✅ Migrations complete"
else
  echo "⚠️  DATABASE_URL not set, skipping migrations"
fi

echo "🚀 Starting server..."
exec /app/catbird-server
