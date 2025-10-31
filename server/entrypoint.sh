#!/bin/bash
set -e

echo "🔄 Running database migrations..."

# Wait for PostgreSQL to be ready
until pg_isready -h "${DATABASE_HOST:-postgres}" -p "${DATABASE_PORT:-5432}" -U "${DATABASE_USER:-catbird}" > /dev/null 2>&1; do
  echo "Waiting for PostgreSQL to be ready..."
  sleep 2
done

echo "✅ PostgreSQL is ready"

# Parse DATABASE_URL to get connection details
if [ -n "$DATABASE_URL" ]; then
  # Extract database name from URL
  DB_NAME=$(echo "$DATABASE_URL" | sed -n 's/.*\/\([^?]*\).*/\1/p')
  DB_HOST=$(echo "$DATABASE_URL" | sed -n 's/.*@\([^:]*\):.*/\1/p')
  DB_USER=$(echo "$DATABASE_URL" | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')
  
  echo "📂 Running migrations for database: $DB_NAME"
  
  # Run each migration file in order
  for migration in /app/migrations/*.sql; do
    if [ -f "$migration" ]; then
      migration_name=$(basename "$migration")
      echo "  ▶ Applying: $migration_name"
      
      # Use psql to run migration (requires PASSWORD env var or .pgpass)
      PGPASSWORD="${POSTGRES_PASSWORD:-changeme}" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -f "$migration" || {
        echo "  ⚠️  Warning: Migration $migration_name may have already been applied or failed"
      }
    fi
  done
  
  echo "✅ Migrations complete"
else
  echo "⚠️  DATABASE_URL not set, skipping migrations"
fi

echo "🚀 Starting server..."
exec /app/catbird-server
