.PHONY: help build run test clean deploy reset-dev-db backup restore health-check logs

# Default target
help:
	@echo "Catbird MLS Server - Make Commands"
	@echo "===================================="
	@echo "build              - Build release binary"
	@echo "run                - Run the server (foreground)"
	@echo "start              - Start systemd service"
	@echo "stop               - Stop systemd service"
	@echo "restart            - Restart systemd service"
	@echo "test               - Run tests"
	@echo "clean              - Clean build artifacts"
	@echo "deploy             - Build and deploy (preserve data)"
	@echo "reset-dev-db       - Drop, recreate and migrate a local compose database (URL=...)"
	@echo "migrate            - Run database migrations"
	@echo "backup             - Backup database"
	@echo "restore            - Restore database from backup"
	@echo "health-check       - Check server health"
	@echo "logs               - View logs"

# Build release binary
build:
	cargo build --release

# Run the server (foreground, for development)
run:
	cargo run --release

# Start systemd service
start:
	sudo systemctl start catbird-mls-server

# Stop systemd service
stop:
	sudo systemctl stop catbird-mls-server

# Restart systemd service
restart:
	sudo systemctl restart catbird-mls-server

# Run tests
test:
	cargo test

# Clean up
clean:
	cargo clean

# Deploy (preserve data)
deploy:
	./deploy-update.sh

# Run migrations
migrate:
	./scripts/run-migrations.sh

# Backup database
backup:
	./scripts/backup-db.sh /var/backups/catbird

# Restore database
restore:
	@echo "Usage: make restore BACKUP=/path/to/backup.sql.gz"
	@if [ -n "$(BACKUP)" ]; then \
		./scripts/restore-db.sh $(BACKUP); \
	fi

# Health check
health-check:
	./scripts/health-check.sh http://localhost:3000

# View logs
logs:
	sudo journalctl -u catbird-mls-server -f

# Drop, recreate and migrate a local compose database; refuses any other target
reset-dev-db:
	./scripts/reset-dev-db.sh "$(URL)"

# Status
status:
	sudo systemctl status catbird-mls-server --no-pager
