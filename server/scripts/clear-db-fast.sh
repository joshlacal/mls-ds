#!/bin/bash
set -e

# Fast database clear (no confirmation) - use for automated testing
# Uses catbird_mls database on netcup VPS

export PGPASSWORD='dyvmo0-bewnur-tUrqad'

psql -h localhost -U catbird -d catbird_mls <<'EOF'
TRUNCATE TABLE users CASCADE;
EOF

echo "✅ Database cleared"
