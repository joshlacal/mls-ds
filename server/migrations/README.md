# Database Migrations

This directory contains SQL migrations for the Catbird MLS Server database schema.

## Migration Files

Migrations are executed in order by filename:

1. **20240101000001_create_conversations.sql**
   - Creates `conversations` table
   - Indexes: creator_did, created_at

2. **20240101000002_create_members.sql**
   - Creates `members` table
   - Indexes: member_did, left_at (partial), active members, unread counts

3. **20240101000003_create_messages.sql**
   - Creates `messages` table
   - Indexes: convo+sent_at, sender, epoch, pagination

4. **20240101000004_create_key_packages.sql**
   - Creates `key_packages` table
   - Indexes: unique constraint, available packages (partial)

5. **20240101000005_create_blobs.sql**
   - Creates `blobs` table
   - Indexes: uploader, conversation, uploaded_at, size

## Running Migrations

### Using sqlx-cli

```bash
# Install sqlx-cli if not already installed
cargo install sqlx-cli --no-default-features --features postgres

# Set database URL
export DATABASE_URL=postgres://localhost/catbird

# Run all pending migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert

# Show migration status
sqlx migrate info
```

### Programmatically

Migrations run automatically on server startup via:

```rust
use catbird_server::db::init_db_default;

let pool = init_db_default().await?;
// Migrations are applied automatically
```

## Creating New Migrations

```bash
# Create a new migration file
sqlx migrate add <migration_name>

# Example
sqlx migrate add add_user_preferences

# This creates: migrations/YYYYMMDDHHMMSS_add_user_preferences.sql
```

## Migration Best Practices

1. **Never modify existing migrations** - Once applied, migrations are immutable
2. **Always test migrations** - Test on a copy of production data
3. **Use transactions** - Migrations should be atomic
4. **Add indexes carefully** - Consider CONCURRENTLY for large tables
5. **Document changes** - Add comments to explain complex migrations

## Schema Version Tracking

sqlx maintains a `_sqlx_migrations` table to track applied migrations:

```sql
SELECT * FROM _sqlx_migrations ORDER BY version;
```

## Rollback Strategy

To revert changes:

```bash
# Revert last migration
sqlx migrate revert

# Or create a new migration to undo changes
sqlx migrate add revert_feature_x
```

## Development vs Production

### Development

```bash
export DATABASE_URL=postgres://localhost/catbird_dev
sqlx migrate run
```

### Production

```bash
export DATABASE_URL=postgres://user:pass@prod-db/catbird?sslmode=require
sqlx migrate run
```

Always test migrations in staging before production!

## Troubleshooting

### Migration fails midway

If a migration fails, manually check the database state and either:
1. Fix the issue and re-run
2. Manually mark the migration as complete in `_sqlx_migrations`

### Reset database (development only)

```bash
# Drop and recreate database
sqlx database drop
sqlx database create
sqlx migrate run
```

### Check migration status

```bash
sqlx migrate info
```

Output shows:
- Applied migrations (✓)
- Pending migrations (✗)
- Migration checksums

## Index Creation

For large tables in production, consider using `CONCURRENTLY`:

```sql
-- Instead of:
CREATE INDEX idx_name ON table(column);

-- Use:
CREATE INDEX CONCURRENTLY idx_name ON table(column);
```

Note: sqlx migrations run in transactions, so `CONCURRENTLY` requires special handling.

## See Also

- [DATABASE_SCHEMA.md](../DATABASE_SCHEMA.md) - Complete schema documentation
- [DB_USAGE_EXAMPLES.md](../DB_USAGE_EXAMPLES.md) - Usage examples
- [sqlx documentation](https://docs.rs/sqlx/)
