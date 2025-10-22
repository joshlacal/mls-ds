.PHONY: help build run test clean deploy deploy-k8s backup restore health-check logs

# Default target
help:
	@echo "Catbird MLS Server - Make Commands"
	@echo "===================================="
	@echo "build              - Build Docker image"
	@echo "run                - Run with docker-compose"
	@echo "run-dev            - Run in development mode with hot reload"
	@echo "stop               - Stop all containers"
	@echo "test               - Run tests"
	@echo "clean              - Clean up containers and volumes"
	@echo "deploy             - Deploy with docker-compose"
	@echo "deploy-k8s         - Deploy to Kubernetes"
	@echo "migrate            - Run database migrations"
	@echo "backup             - Backup database"
	@echo "restore            - Restore database from backup"
	@echo "health-check       - Check server health"
	@echo "logs               - View logs"
	@echo "shell              - Open shell in container"

# Build Docker image
build:
	docker build -t catbird-mls-server:latest .

# Run with docker-compose
run:
	docker-compose up -d

# Run in development mode
run-dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Stop all containers
stop:
	docker-compose down

# Run tests
test:
	cargo test

# Clean up
clean:
	docker-compose down -v
	cargo clean

# Deploy with docker-compose
deploy:
	./scripts/deploy.sh production

# Deploy to Kubernetes
deploy-k8s:
	./scripts/k8s-deploy.sh production

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
	docker-compose logs -f mls-server

# Open shell in container
shell:
	docker-compose exec mls-server /bin/bash

# Kubernetes specific commands
k8s-logs:
	kubectl logs -f deployment/catbird-mls-server -n catbird

k8s-shell:
	kubectl exec -it deployment/catbird-mls-server -n catbird -- /bin/bash

k8s-health:
	kubectl port-forward svc/catbird-mls-service 8080:80 -n catbird & \
	sleep 3 && \
	./scripts/health-check.sh http://localhost:8080 && \
	pkill -f "kubectl port-forward"

k8s-scale:
	@echo "Usage: make k8s-scale REPLICAS=5"
	@if [ -n "$(REPLICAS)" ]; then \
		kubectl scale deployment/catbird-mls-server --replicas=$(REPLICAS) -n catbird; \
	fi
