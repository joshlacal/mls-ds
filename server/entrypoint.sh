#!/bin/bash
set -e

echo "🔄 Running database migrations..."

# Wait for PostgreSQL to be ready
until pg_isready -h "${DATABASE_HOST:-postgres}" -p "${DATABASE_PORT:-5432}" -U "${DATABASE_USER:-catbird}" > /dev/null 2>&1; do
  echo "Waiting for PostgreSQL to be ready..."
  sleep 2
done

echo "✅ PostgreSQL is ready"

# Run migrations using sqlx-cli
if [ -n "$DATABASE_URL" ]; then
  echo "📂 Running database migrations with sqlx..."
  
  if command -v sqlx &> /dev/null; then
    sqlx migrate run --source /app/migrations || {
      echo "❌ Migration failed!"
      exit 1
    }
    echo "✅ Migrations complete"
  else
    echo "❌ sqlx binary not found!"
    exit 1
  fi
else
  echo "⚠️  DATABASE_URL not set, skipping migrations"
fi

echo "🚀 Starting server..."
exec /app/catbird-server
