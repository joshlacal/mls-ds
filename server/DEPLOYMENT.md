# Catbird MLS Server - Deployment Guide

Complete production deployment guide for the Catbird MLS Server with Docker, Docker Compose, and Kubernetes.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Database Management](#database-management)
- [Monitoring and Health Checks](#monitoring-and-health-checks)
- [Backup and Restore](#backup-and-restore)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Tools

- Docker 24.0+ and Docker Compose 2.0+
- Kubernetes 1.28+ (for K8s deployment)
- kubectl CLI tool
- PostgreSQL client tools (for manual database operations)
- Rust 1.75+ (for local development)

### Infrastructure Requirements

**Minimum Resources:**
- CPU: 2 cores
- RAM: 4GB
- Storage: 20GB

**Production Recommended:**
- CPU: 4+ cores
- RAM: 8GB+
- Storage: 100GB+ SSD

## Quick Start

### Local Development with Docker Compose

1. **Clone and navigate to the server directory:**
```bash
cd server/
```

2. **Create environment file:**
```bash
cat > .env.production <<EOF
POSTGRES_PASSWORD=your_secure_password
REDIS_PASSWORD=your_secure_redis_password
JWT_SECRET=your_jwt_secret_key
RUST_LOG=info
EOF
```

3. **Deploy with Docker Compose:**
```bash
./scripts/deploy.sh production
```

4. **Verify deployment:**
```bash
curl http://localhost:3000/health
```

## Docker Deployment

### Building the Image

The Dockerfile uses a multi-stage build for optimal image size and security:

```bash
docker build -t catbird-mls-server:latest .
```

**Build stages:**
1. **Builder stage**: Compiles Rust code with all dependencies
2. **Runtime stage**: Minimal Debian image with only runtime dependencies

### Running with Docker Compose

The `docker-compose.yml` includes three services:

- **postgres**: PostgreSQL 16 database with persistence
- **redis**: Redis 7 cache with AOF persistence
- **mls-server**: The Catbird MLS server

**Start all services:**
```bash
docker-compose up -d
```

**View logs:**
```bash
docker-compose logs -f mls-server
```

**Stop services:**
```bash
docker-compose down
```

**Stop and remove volumes:**
```bash
docker-compose down -v
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://catbird:changeme@postgres:5432/catbird` |
| `REDIS_URL` | Redis connection string | `redis://:changeme@redis:6379` |
| `JWT_SECRET` | Secret key for JWT tokens | Required in production |
| `RUST_LOG` | Logging level | `info` |
| `SERVER_PORT` | Server port | `3000` |

## Kubernetes Deployment

### Prerequisites

1. **Install cert-manager (for TLS):**
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
```

2. **Install NGINX Ingress Controller:**
```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/cloud/deploy.yaml
```

### Deployment Steps

1. **Create namespace:**
```bash
kubectl apply -f k8s/namespace.yaml
```

2. **Update secrets:**
```bash
# Create production secrets (DO NOT commit to git)
kubectl create secret generic catbird-mls-secrets \
  --from-literal=POSTGRES_PASSWORD='your_secure_password' \
  --from-literal=REDIS_PASSWORD='your_secure_redis_password' \
  --from-literal=JWT_SECRET='your_jwt_secret_key' \
  --from-literal=DATABASE_URL='postgresql://catbird:password@postgres-service:5432/catbird' \
  --from-literal=REDIS_URL='redis://:password@redis-service:6379' \
  -n catbird
```

3. **Deploy infrastructure (PostgreSQL and Redis):**
```bash
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
```

4. **Wait for databases to be ready:**
```bash
kubectl wait --for=condition=ready pod -l app=postgres -n catbird --timeout=300s
kubectl wait --for=condition=ready pod -l app=redis -n catbird --timeout=300s
```

5. **Run database migrations:**
```bash
kubectl apply -f k8s/job-migrations.yaml
kubectl wait --for=condition=complete job/catbird-db-migrations -n catbird --timeout=300s
```

6. **Deploy the application:**
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

7. **Deploy ingress (update domain in ingress.yaml first):**
```bash
kubectl apply -f k8s/ingress.yaml
```

8. **Enable auto-scaling:**
```bash
kubectl apply -f k8s/hpa.yaml
```

9. **Enable automated backups:**
```bash
kubectl apply -f k8s/cronjob-backup.yaml
```

### Verify Deployment

```bash
# Check all pods
kubectl get pods -n catbird

# Check services
kubectl get svc -n catbird

# Check ingress
kubectl get ingress -n catbird

# View logs
kubectl logs -f deployment/catbird-mls-server -n catbird
```

### Update Deployment

```bash
# Build new image
docker build -t catbird-mls-server:v1.1.0 .

# Push to registry (if using remote cluster)
docker tag catbird-mls-server:v1.1.0 your-registry/catbird-mls-server:v1.1.0
docker push your-registry/catbird-mls-server:v1.1.0

# Update deployment
kubectl set image deployment/catbird-mls-server \
  catbird-mls-server=your-registry/catbird-mls-server:v1.1.0 \
  -n catbird

# Check rollout status
kubectl rollout status deployment/catbird-mls-server -n catbird
```

### Rollback Deployment

```bash
# View rollout history
kubectl rollout history deployment/catbird-mls-server -n catbird

# Rollback to previous version
kubectl rollout undo deployment/catbird-mls-server -n catbird

# Rollback to specific revision
kubectl rollout undo deployment/catbird-mls-server --to-revision=2 -n catbird
```

## Database Management

### Running Migrations

**Docker Compose:**
```bash
./scripts/run-migrations.sh "postgresql://catbird:password@localhost:5432/catbird"
```

**Kubernetes:**
```bash
kubectl apply -f k8s/job-migrations.yaml
```

**Manual (using sqlx-cli):**
```bash
cargo install sqlx-cli --no-default-features --features postgres
sqlx migrate run --database-url "postgresql://catbird:password@localhost:5432/catbird"
```

### Creating New Migrations

```bash
sqlx migrate add <migration_name>
# Edit the generated file in migrations/
sqlx migrate run
```

## Monitoring and Health Checks

### Health Endpoints

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `/health` | Detailed health status | JSON with DB and memory checks |
| `/health/live` | Liveness probe | 200 OK if alive |
| `/health/ready` | Readiness probe | 200 OK if ready to serve traffic |

### Examples

**Check overall health:**
```bash
curl http://localhost:3000/health | jq
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": 1698765432,
  "version": "0.1.0",
  "checks": {
    "database": "Healthy",
    "memory": "Healthy"
  }
}
```

**Check readiness:**
```bash
curl http://localhost:3000/health/ready
```

**Kubernetes health monitoring:**
```bash
# Check pod health
kubectl get pods -n catbird -w

# Describe pod for events
kubectl describe pod <pod-name> -n catbird

# View health check logs
kubectl logs -f <pod-name> -n catbird | grep health
```

### Prometheus Metrics (Future Enhancement)

Add Prometheus metrics endpoint for production monitoring:
- Request rates and latency
- Database connection pool metrics
- MLS operation metrics
- Error rates

## Backup and Restore

### Automated Backups

**Kubernetes CronJob** runs daily at 2 AM:
```bash
kubectl get cronjob -n catbird
kubectl get jobs -n catbird
```

**View backup logs:**
```bash
kubectl logs -f job/catbird-db-backup-<timestamp> -n catbird
```

### Manual Backup

**Docker Compose:**
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=catbird
export DB_USER=catbird
export DB_PASSWORD=your_password

./scripts/backup-db.sh /path/to/backups
```

**Kubernetes:**
```bash
kubectl exec -it postgres-0 -n catbird -- \
  pg_dump -U catbird catbird | gzip > backup_$(date +%Y%m%d).sql.gz
```

### Restore from Backup

**Docker Compose:**
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=catbird
export DB_USER=catbird
export DB_PASSWORD=your_password

./scripts/restore-db.sh /path/to/backup.sql.gz
```

**Kubernetes:**
```bash
# Copy backup to pod
kubectl cp backup.sql.gz catbird/postgres-0:/tmp/

# Restore
kubectl exec -it postgres-0 -n catbird -- \
  bash -c "gunzip < /tmp/backup.sql.gz | psql -U catbird catbird"
```

### Backup Retention

- **Local**: Last 30 days kept automatically
- **Production**: Configure S3/GCS backup with lifecycle policies

## Security

### Production Security Checklist

- [ ] Change all default passwords
- [ ] Use strong, randomly generated secrets
- [ ] Enable TLS/SSL for all connections
- [ ] Configure firewall rules
- [ ] Enable pod security policies
- [ ] Use network policies to restrict traffic
- [ ] Scan images for vulnerabilities
- [ ] Enable audit logging
- [ ] Rotate secrets regularly
- [ ] Use least-privilege service accounts

### Secrets Management

**Never commit secrets to git!**

**Kubernetes Secrets:**
```bash
# Create from file
kubectl create secret generic catbird-mls-secrets \
  --from-env-file=.env.production \
  -n catbird

# Or use external secrets manager
# - HashiCorp Vault
# - AWS Secrets Manager
# - Google Secret Manager
# - Azure Key Vault
```

### Network Security

**Configure network policies:**
```yaml
# k8s/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: catbird-mls-network-policy
  namespace: catbird
spec:
  podSelector:
    matchLabels:
      app: catbird-mls-server
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 3000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
```

### TLS Configuration

**Update ingress.yaml with your domain:**
```yaml
spec:
  tls:
  - hosts:
    - mls.yourdomain.com
    secretName: catbird-mls-tls
```

**Cert-manager will automatically provision Let's Encrypt certificates.**

## Troubleshooting

### Common Issues

#### Pod Fails to Start

```bash
# Check pod status
kubectl describe pod <pod-name> -n catbird

# View logs
kubectl logs <pod-name> -n catbird

# Check events
kubectl get events -n catbird --sort-by='.lastTimestamp'
```

#### Database Connection Errors

```bash
# Test database connectivity
kubectl exec -it postgres-0 -n catbird -- psql -U catbird -c "SELECT 1"

# Check database service
kubectl get svc postgres-service -n catbird

# Verify secrets
kubectl get secret catbird-mls-secrets -n catbird -o yaml
```

#### High Memory Usage

```bash
# Check pod resources
kubectl top pods -n catbird

# Adjust resource limits in deployment.yaml
```

#### Failed Health Checks

```bash
# Check health endpoint directly
kubectl port-forward svc/catbird-mls-service 3000:80 -n catbird
curl http://localhost:3000/health

# View detailed logs
kubectl logs -f deployment/catbird-mls-server -n catbird | grep -i health
```

### Debug Mode

Enable debug logging:
```bash
# Docker Compose
RUST_LOG=debug docker-compose up

# Kubernetes
kubectl set env deployment/catbird-mls-server RUST_LOG=debug -n catbird
```

### Performance Tuning

**Database Connection Pool:**
- Adjust `sqlx` pool size in `storage.rs`
- Monitor with: `SELECT count(*) FROM pg_stat_activity;`

**Horizontal Scaling:**
- Adjust `replicas` in `deployment.yaml`
- Configure HPA thresholds in `hpa.yaml`

**Resource Limits:**
- Monitor actual usage: `kubectl top pods -n catbird`
- Adjust requests/limits accordingly

### Getting Help

**Logs Collection:**
```bash
# Collect all logs
kubectl logs -l app=catbird-mls-server -n catbird --tail=1000 > mls-server.log
kubectl logs -l app=postgres -n catbird --tail=1000 > postgres.log
kubectl logs -l app=redis -n catbird --tail=1000 > redis.log

# Describe all resources
kubectl describe all -n catbird > resources.txt
```

## Additional Resources

- [Rust Deployment Best Practices](https://doc.rust-lang.org/cargo/reference/profiles.html)
- [PostgreSQL Production Checklist](https://www.postgresql.org/docs/current/runtime-config.html)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [Docker Security](https://docs.docker.com/engine/security/)

## License

See [LICENSE](../LICENSE) for details.
