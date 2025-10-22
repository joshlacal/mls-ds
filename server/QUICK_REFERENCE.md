# Catbird MLS Server - Deployment Quick Reference

## 🚀 Quick Start Commands

### Local Development
```bash
# Start everything with Docker Compose
make run

# Start in development mode (with hot reload)
make run-dev

# View logs
make logs

# Stop services
make stop
```

### Production Deployment (Docker)
```bash
# Create production environment file
cp .env.example .env.production
# Edit .env.production with secure values

# Deploy
make deploy

# Check health
make health-check
```

### Kubernetes Deployment
```bash
# Create secrets first
kubectl create secret generic catbird-mls-secrets \
  --from-literal=POSTGRES_PASSWORD='your_password' \
  --from-literal=REDIS_PASSWORD='your_redis_password' \
  --from-literal=JWT_SECRET='your_jwt_secret' \
  -n catbird

# Deploy to Kubernetes
make deploy-k8s

# Check health
make k8s-health

# View logs
make k8s-logs
```

## 📁 File Structure

```
server/
├── Dockerfile                      # Multi-stage production build
├── .dockerignore                   # Docker build exclusions
├── docker-compose.yml              # Production compose config
├── docker-compose.dev.yml          # Development overrides
├── Makefile                        # Convenience commands
├── DEPLOYMENT.md                   # Complete deployment guide
│
├── src/
│   ├── health.rs                   # Health check endpoints
│   └── ...                         # Application code
│
├── scripts/
│   ├── deploy.sh                   # Docker deployment script
│   ├── k8s-deploy.sh              # Kubernetes deployment script
│   ├── init-db.sh                 # Database initialization
│   ├── run-migrations.sh          # Run database migrations
│   ├── backup-db.sh               # Database backup
│   ├── restore-db.sh              # Database restore
│   └── health-check.sh            # Health check script
│
└── k8s/
    ├── README.md                   # Kubernetes-specific docs
    ├── kustomization.yaml          # Kustomize config
    ├── namespace.yaml              # Namespace definition
    ├── configmap.yaml              # Configuration
    ├── secrets.yaml                # Secrets template
    ├── postgres.yaml               # PostgreSQL StatefulSet
    ├── redis.yaml                  # Redis StatefulSet
    ├── deployment.yaml             # Application deployment
    ├── service.yaml                # Service definitions
    ├── ingress.yaml                # Ingress with TLS
    ├── hpa.yaml                    # Horizontal auto-scaling
    ├── cronjob-backup.yaml         # Automated backups
    └── job-migrations.yaml         # Database migrations job
```

## 🏥 Health Endpoints

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `/health` | Detailed status | JSON with checks |
| `/health/live` | Liveness probe | `200 OK` |
| `/health/ready` | Readiness probe | `200 OK` |

## 🔧 Common Operations

### Database Operations
```bash
# Run migrations
make migrate

# Backup database
make backup

# Restore database
make restore BACKUP=/path/to/backup.sql.gz
```

### Scaling (Kubernetes)
```bash
# Scale to 5 replicas
make k8s-scale REPLICAS=5

# Auto-scaling is enabled via HPA (3-10 replicas)
kubectl get hpa -n catbird
```

### Debugging
```bash
# Docker Compose logs
docker-compose logs -f mls-server

# Kubernetes logs
kubectl logs -f deployment/catbird-mls-server -n catbird

# Shell access
make shell              # Docker
make k8s-shell         # Kubernetes
```

## 🔒 Security Checklist

- [ ] Change all default passwords in `.env.production`
- [ ] Use strong, randomly generated secrets
- [ ] Never commit `.env.production` or secrets to git
- [ ] Enable TLS/SSL for production
- [ ] Configure firewall rules
- [ ] Update `ingress.yaml` with your domain
- [ ] Review and adjust resource limits
- [ ] Enable audit logging
- [ ] Regular security updates

## 📊 Monitoring

### Docker Compose
```bash
# Container stats
docker stats

# View all logs
docker-compose logs -f
```

### Kubernetes
```bash
# Pod status
kubectl get pods -n catbird -w

# Resource usage
kubectl top pods -n catbird

# Events
kubectl get events -n catbird --sort-by='.lastTimestamp'

# HPA status
kubectl get hpa -n catbird
```

## 🔄 Updates and Rollbacks

### Docker Compose
```bash
# Pull latest images
docker-compose pull

# Restart with new images
docker-compose up -d --force-recreate
```

### Kubernetes
```bash
# Update deployment
kubectl set image deployment/catbird-mls-server \
  catbird-mls-server=catbird-mls-server:v1.1.0 -n catbird

# Check rollout
kubectl rollout status deployment/catbird-mls-server -n catbird

# Rollback
kubectl rollout undo deployment/catbird-mls-server -n catbird
```

## 🆘 Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose logs mls-server

# Check database connectivity
docker-compose exec mls-server curl http://localhost:3000/health
```

### Pod fails in Kubernetes
```bash
# Describe pod
kubectl describe pod <pod-name> -n catbird

# Check logs
kubectl logs <pod-name> -n catbird

# Check events
kubectl get events -n catbird
```

### Database connection issues
```bash
# Test database
docker-compose exec postgres psql -U catbird -c "SELECT 1"

# Kubernetes
kubectl exec -it postgres-0 -n catbird -- psql -U catbird -c "SELECT 1"
```

## 📚 Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Complete deployment guide
- **[k8s/README.md](k8s/README.md)** - Kubernetes-specific docs
- **[../README.md](../README.md)** - Project overview

## 🔗 Useful Links

- [Docker Documentation](https://docs.docker.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Redis Documentation](https://redis.io/docs/)
