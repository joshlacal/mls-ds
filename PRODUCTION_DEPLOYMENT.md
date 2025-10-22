# MLS Server Production Deployment Guide

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Staging Environment Setup](#staging-environment-setup)
5. [Production Deployment](#production-deployment)
6. [Monitoring and Observability](#monitoring-and-observability)
7. [Backup and Restore](#backup-and-restore)
8. [CI/CD Pipeline](#cicd-pipeline)
9. [Security and Secrets Management](#security-and-secrets-management)
10. [Rollback Procedures](#rollback-procedures)
11. [Runbook](#runbook)

---

## Overview

This document provides comprehensive guidance for deploying the MLS Server to production environments. The deployment uses a blue-green strategy for zero-downtime deployments, comprehensive monitoring, automated backups, and robust rollback procedures.

### Deployment Strategy
- **Blue-Green Deployment**: Two identical production environments (blue/green) for zero-downtime deployments
- **Staging Environment**: Mirror of production for pre-deployment testing
- **Automated CI/CD**: GitHub Actions pipeline for testing, building, and deployment
- **Health Checks**: Liveness, readiness, and startup probes
- **Auto-scaling**: Horizontal Pod Autoscaler based on CPU and memory

---

## Architecture

### Components
```
┌─────────────────────────────────────────────────────────────┐
│                      Load Balancer                           │
└───────────────┬─────────────────────────────────────────────┘
                │
        ┌───────┴───────┐
        │               │
    ┌───▼───┐       ┌───▼───┐
    │ Blue  │       │ Green │
    │ MLS   │       │ MLS   │
    │Server │       │Server │
    └───┬───┘       └───┬───┘
        │               │
        └───────┬───────┘
                │
    ┌───────────▼───────────┐
    │                       │
┌───▼────┐          ┌──────▼─────┐
│Postgres│          │   Redis    │
│Database│          │   Cache    │
└────────┘          └────────────┘
```

### Monitoring Stack
- **Prometheus**: Metrics collection and storage
- **Grafana**: Metrics visualization and dashboards
- **Loki**: Log aggregation
- **Promtail**: Log shipping
- **AlertManager**: Alert routing and notification

---

## Prerequisites

### Required Tools
```bash
# Install required tools
brew install kubectl
brew install helm
brew install awscli
brew install postgresql
brew install redis
```

### Access Requirements
- GitHub repository access
- Kubernetes cluster access (staging and production)
- AWS account with S3 access (for backups)
- Container registry access (GitHub Container Registry)

### GitHub Secrets Configuration
Configure the following secrets in your GitHub repository:

**Staging Secrets:**
- `STAGING_KUBE_CONFIG`: Base64-encoded kubeconfig for staging cluster
- `STAGING_URL`: Staging environment URL

**Production Secrets:**
- `PROD_KUBE_CONFIG`: Base64-encoded kubeconfig for production cluster
- `PROD_DB_HOST`: Production database host
- `PROD_DB_PASSWORD`: Production database password
- `PROD_GREEN_URL`: Production green environment URL

**Notification Secrets:**
- `SLACK_WEBHOOK`: Slack webhook for deployment notifications

---

## Staging Environment Setup

### 1. Configure Environment Variables

Copy and edit the staging environment file:
```bash
cd server/staging
cp .env.staging .env
```

Edit `.env` with your staging credentials:
```env
POSTGRES_PASSWORD=your_secure_staging_password
REDIS_PASSWORD=your_redis_staging_password
JWT_SECRET=your_jwt_secret_min_32_chars
GRAFANA_PASSWORD=your_grafana_password
```

### 2. Start Staging Environment

```bash
# Start all services
docker-compose -f docker-compose.staging.yml up -d

# Check service status
docker-compose -f docker-compose.staging.yml ps

# View logs
docker-compose -f docker-compose.staging.yml logs -f mls-server
```

### 3. Run Database Migrations

```bash
# Run migrations
docker-compose -f docker-compose.staging.yml exec mls-server \
  sqlx migrate run --source /app/migrations
```

### 4. Verify Staging Deployment

```bash
# Run smoke tests
./scripts/smoke-test.sh http://localhost:3000

# Check health endpoints
curl http://localhost:3000/health
curl http://localhost:3000/health/ready
curl http://localhost:3000/health/live

# Check metrics
curl http://localhost:3000/metrics
```

### 5. Access Monitoring Tools

- **Grafana**: http://localhost:3001 (admin/your_grafana_password)
- **Prometheus**: http://localhost:9090
- **AlertManager**: http://localhost:9093

---

## Production Deployment

### Manual Deployment Steps

#### 1. Pre-Deployment Checklist

- [ ] All tests passing in CI/CD
- [ ] Staging deployment successful
- [ ] Smoke tests passed in staging
- [ ] Database migrations tested
- [ ] Backup of production database taken
- [ ] Rollback plan reviewed
- [ ] Team notified of deployment window

#### 2. Create Database Backup

```bash
# Set environment variables
export DB_HOST=your-prod-db-host
export DB_PASSWORD=your-prod-db-password
export BACKUP_S3_BUCKET=your-backup-bucket

# Run backup
./server/scripts/backup/backup-db.sh
```

#### 3. Deploy to Green Environment

```bash
# Set kubectl context to production
kubectl config use-context production

# Deploy to green environment
kubectl set image deployment/mls-server-green \
  mls-server=ghcr.io/catbird/mls-server:v1.2.3 \
  -n production

# Wait for rollout
kubectl rollout status deployment/mls-server-green -n production --timeout=10m
```

#### 4. Run Production Smoke Tests

```bash
# Test green environment
./server/scripts/smoke-test.sh https://green.mls.catbird.blue
```

#### 5. Switch Traffic to Green

```bash
# Switch service selector to green
kubectl patch service mls-server -n production \
  -p '{"spec":{"selector":{"version":"green"}}}'

# Monitor for issues
kubectl logs -f deployment/mls-server-green -n production
```

#### 6. Monitor and Verify

```bash
# Check pod status
kubectl get pods -n production -l app=mls-server

# Check service
kubectl get service mls-server -n production

# Monitor metrics in Grafana
# Check error rates and latency
```

#### 7. Scale Down Blue

After 15-30 minutes of successful operation:
```bash
kubectl scale deployment/mls-server-blue -n production --replicas=1
```

### Automated Deployment via CI/CD

The deployment happens automatically through GitHub Actions:

**Staging Deployment:**
```bash
# Push to staging branch
git push origin staging
```

**Production Deployment:**
```bash
# Push to main branch or create release
git push origin main

# Or trigger manually
gh workflow run mls-deploy.yml -f environment=production
```

---

## Monitoring and Observability

### Metrics Endpoints

**Application Metrics:**
- `/metrics` - Prometheus metrics endpoint
- `/health` - Detailed health status
- `/health/ready` - Readiness probe
- `/health/live` - Liveness probe

### Key Metrics to Monitor

**Application Metrics:**
- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request latency
- `database_connections_active` - Active DB connections
- `database_queries_total` - Database query count
- `mls_messages_sent_total` - MLS messages sent
- `mls_groups_created_total` - MLS groups created

**System Metrics:**
- `process_resident_memory_bytes` - Memory usage
- `process_cpu_seconds_total` - CPU usage
- `node_filesystem_avail_bytes` - Disk space

### Grafana Dashboards

Access Grafana at: https://grafana.catbird.blue

**Pre-configured Dashboards:**
1. **MLS Server Overview** - High-level service metrics
2. **Database Performance** - PostgreSQL metrics
3. **System Resources** - CPU, memory, disk usage
4. **Error Tracking** - Error rates and types
5. **Request Latency** - P50, P95, P99 latencies

### Alerts

Configured alerts (see `server/monitoring/alerts/mls-alerts.yml`):

**Critical Alerts:**
- Service down > 2 minutes
- Database connection failures
- High error rate (>5% for 5 minutes)

**Warning Alerts:**
- High CPU usage (>80% for 10 minutes)
- High memory usage (>512MB for 10 minutes)
- Slow database queries (>1s average)
- Low disk space (<10%)

### Log Aggregation

**Access Logs:**
```bash
# View logs in Loki via Grafana
# Navigate to Explore > Loki
# Query: {app="mls-server"}

# Or use kubectl
kubectl logs -f deployment/mls-server -n production
```

**Log Levels:**
- `ERROR` - Errors requiring attention
- `WARN` - Warning conditions
- `INFO` - Informational messages
- `DEBUG` - Debug-level messages

---

## Backup and Restore

### Automated Backups

Backups run automatically via cron job:
```bash
# Add to crontab
0 2 * * * /path/to/server/scripts/backup/backup-db.sh
```

### Manual Backup

```bash
# Create backup
cd server
export DB_HOST=localhost
export DB_PASSWORD=your_password
export BACKUP_S3_BUCKET=catbird-backups

./scripts/backup/backup-db.sh
```

### Restore from Backup

```bash
# List available backups
ls -lh /backups/catbird_db_*.sql.gz

# Restore specific backup
export DB_HOST=localhost
export DB_PASSWORD=your_password

./scripts/backup/restore-db.sh catbird_db_20231201_120000.sql.gz
```

### Restore from S3

```bash
# Download and restore from S3
./scripts/backup/restore-db.sh s3://catbird-backups/backups/database/catbird_db_20231201_120000.sql.gz
```

### Backup Retention

- **Local backups**: 7 days
- **S3 backups**: 30 days
- **Production backups**: Taken before each deployment

---

## CI/CD Pipeline

### Pipeline Stages

The deployment pipeline (`.github/workflows/mls-deploy.yml`) consists of:

1. **Test** - Run linting, unit tests, and integration tests
2. **Build** - Build and push Docker image to registry
3. **Security Scan** - Vulnerability scanning with Trivy
4. **Deploy Staging** - Deploy to staging environment
5. **Smoke Tests** - Run automated smoke tests
6. **Deploy Production** - Blue-green deployment to production
7. **Rollback** - Automatic rollback on failure

### Pipeline Triggers

- **Push to `main`**: Deploy to production
- **Push to `staging`**: Deploy to staging
- **Pull Request**: Run tests only
- **Manual Trigger**: Deploy to chosen environment

### Manual Pipeline Execution

```bash
# Trigger staging deployment
gh workflow run mls-deploy.yml -f environment=staging

# Trigger production deployment
gh workflow run mls-deploy.yml -f environment=production
```

---

## Security and Secrets Management

### Kubernetes Secrets

Create secrets in Kubernetes:

```bash
# Create namespace
kubectl create namespace production

# Create secrets
kubectl create secret generic mls-secrets \
  --from-literal=database-url="postgresql://user:pass@host:5432/db" \
  --from-literal=redis-url="redis://:pass@host:6379" \
  --from-literal=jwt-secret="your-jwt-secret-min-32-chars" \
  -n production
```

### AWS Secrets Manager (Alternative)

```bash
# Store secret in AWS Secrets Manager
aws secretsmanager create-secret \
  --name mls-server/production/database-url \
  --secret-string "postgresql://user:pass@host:5432/db"

# Use External Secrets Operator to sync to Kubernetes
kubectl apply -f k8s/production/external-secret.yaml
```

### Secret Rotation

Rotate secrets regularly:
```bash
# 1. Update secret in Secrets Manager or Kubernetes
kubectl edit secret mls-secrets -n production

# 2. Restart pods to pick up new secret
kubectl rollout restart deployment/mls-server -n production
```

---

## Rollback Procedures

### Automatic Rollback

The CI/CD pipeline includes automatic rollback on deployment failure.

### Manual Rollback - Blue/Green

```bash
# Run rollback script
./server/scripts/rollback.sh production

# Or manually switch traffic back
kubectl patch service mls-server -n production \
  -p '{"spec":{"selector":{"version":"blue"}}}'
```

### Manual Rollback - Kubernetes

```bash
# Rollback to previous deployment
kubectl rollout undo deployment/mls-server -n production

# Rollback to specific revision
kubectl rollout undo deployment/mls-server -n production --to-revision=2

# Check rollout status
kubectl rollout status deployment/mls-server -n production
```

### Database Rollback

```bash
# Restore from pre-deployment backup
export DB_HOST=production-db-host
export DB_PASSWORD=production-password

./server/scripts/backup/restore-db.sh pre_restore_20231201_120000.sql.gz
```

---

## Runbook

### Common Operational Tasks

#### Check Service Health

```bash
# Check all pods
kubectl get pods -n production -l app=mls-server

# Check service status
kubectl get service mls-server -n production

# Check recent events
kubectl get events -n production --sort-by='.lastTimestamp'
```

#### View Logs

```bash
# Stream logs from all pods
kubectl logs -f deployment/mls-server -n production

# View logs from specific pod
kubectl logs mls-server-abc123 -n production

# View logs with timestamps
kubectl logs --timestamps deployment/mls-server -n production
```

#### Scale Service

```bash
# Scale manually
kubectl scale deployment/mls-server -n production --replicas=5

# Check HPA status
kubectl get hpa -n production
```

#### Database Operations

```bash
# Connect to database
kubectl port-forward svc/postgres 5432:5432 -n production
psql postgresql://catbird:password@localhost:5432/catbird

# Check database size
SELECT pg_size_pretty(pg_database_size('catbird'));

# Check active connections
SELECT count(*) FROM pg_stat_activity;
```

#### Clear Redis Cache

```bash
# Port forward to Redis
kubectl port-forward svc/redis 6379:6379 -n production

# Connect and flush cache
redis-cli -h localhost -a password
> FLUSHDB
```

### Troubleshooting

#### Service is Down

```bash
# 1. Check pod status
kubectl get pods -n production -l app=mls-server

# 2. Describe failing pod
kubectl describe pod <pod-name> -n production

# 3. Check logs
kubectl logs <pod-name> -n production

# 4. Check recent events
kubectl get events -n production --field-selector involvedObject.name=<pod-name>
```

#### High Error Rate

```bash
# 1. Check logs for errors
kubectl logs -f deployment/mls-server -n production | grep ERROR

# 2. Check Grafana error dashboard
# Navigate to: https://grafana.catbird.blue/d/errors

# 3. Check database connectivity
kubectl exec -it <pod-name> -n production -- curl http://localhost:3000/health

# 4. Scale up if needed
kubectl scale deployment/mls-server -n production --replicas=10
```

#### Database Connection Issues

```bash
# 1. Check database pod
kubectl get pods -n production -l app=postgres

# 2. Test database connection
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- \
  psql postgresql://catbird:password@postgres:5432/catbird

# 3. Check connection pool
# View metrics: database_connections_active

# 4. Restart server pods
kubectl rollout restart deployment/mls-server -n production
```

#### High Memory Usage

```bash
# 1. Check pod memory
kubectl top pods -n production -l app=mls-server

# 2. Check for memory leaks in Grafana
# Navigate to: https://grafana.catbird.blue/d/memory

# 3. Restart affected pods
kubectl delete pod <pod-name> -n production

# 4. Increase memory limits if needed
kubectl set resources deployment/mls-server -n production \
  --limits=memory=2Gi
```

#### Certificate Expiration

```bash
# Check certificate expiration
kubectl get certificate -n production

# Renew certificate (if using cert-manager)
kubectl delete secret <tls-secret> -n production
# cert-manager will automatically renew
```

### Emergency Procedures

#### Complete Service Outage

1. **Activate incident response team**
2. **Switch to maintenance mode**
   ```bash
   kubectl scale deployment/mls-server -n production --replicas=0
   # Deploy maintenance page
   ```
3. **Investigate root cause**
4. **Apply fix or rollback**
5. **Verify fix in staging**
6. **Restore service**
   ```bash
   kubectl scale deployment/mls-server -n production --replicas=3
   ```
7. **Post-incident review**

#### Data Breach Response

1. **Isolate affected systems**
2. **Revoke compromised credentials**
3. **Rotate all secrets**
4. **Audit logs for unauthorized access**
5. **Notify security team and stakeholders**
6. **Document incident**

---

## Performance Tuning

### Database Optimization

```sql
-- Create indexes for common queries
CREATE INDEX CONCURRENTLY idx_messages_convo_id ON messages(convo_id);
CREATE INDEX CONCURRENTLY idx_key_packages_did ON key_packages(did);

-- Analyze tables
ANALYZE messages;
ANALYZE convos;
ANALYZE key_packages;
```

### Connection Pool Tuning

Adjust in application configuration:
```env
# Increase pool size for high load
DATABASE_MAX_CONNECTIONS=20
DATABASE_MIN_CONNECTIONS=5
```

### Redis Cache Configuration

```bash
# Increase memory limit
kubectl set env deployment/mls-server -n production \
  REDIS_MAX_MEMORY=512mb
```

---

## Monitoring Checklist

**Daily:**
- [ ] Check service health dashboard
- [ ] Review error logs
- [ ] Verify backup completion
- [ ] Check disk space

**Weekly:**
- [ ] Review performance metrics
- [ ] Analyze slow queries
- [ ] Check for security updates
- [ ] Review alert history

**Monthly:**
- [ ] Performance review
- [ ] Capacity planning
- [ ] Security audit
- [ ] Disaster recovery test

---

## Support and Escalation

### Contact Information

- **DevOps Team**: devops@catbird.blue
- **On-Call Engineer**: oncall@catbird.blue
- **PagerDuty**: https://catbird.pagerduty.com

### Escalation Path

1. **Level 1**: On-call engineer
2. **Level 2**: DevOps team lead
3. **Level 3**: Engineering manager
4. **Level 4**: CTO

---

## Appendix

### Useful Commands Reference

```bash
# Quick status check
kubectl get all -n production -l app=mls-server

# Port forward to service
kubectl port-forward svc/mls-server 3000:80 -n production

# Execute command in pod
kubectl exec -it <pod-name> -n production -- /bin/bash

# Copy files from pod
kubectl cp production/<pod-name>:/path/to/file ./local-file

# View resource usage
kubectl top nodes
kubectl top pods -n production
```

### Environment Variables Reference

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Yes | - |
| `REDIS_URL` | Redis connection string | Yes | - |
| `JWT_SECRET` | JWT signing secret | Yes | - |
| `RUST_LOG` | Log level configuration | No | `info` |
| `SERVER_PORT` | HTTP server port | No | `3000` |
| `BACKUP_RETENTION_DAYS` | Backup retention period | No | `7` |

---

**Document Version**: 1.0  
**Last Updated**: 2024-01-01  
**Maintained By**: DevOps Team
