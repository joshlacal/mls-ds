# Production Deployment Checklist

Use this checklist when deploying the Catbird MLS Server to production.

## Pre-Deployment

### Security
- [ ] Generate strong, random passwords for all services
  - [ ] PostgreSQL password (min 32 characters)
  - [ ] Redis password (min 32 characters)
  - [ ] JWT secret (min 64 characters)
- [ ] Update domain name in `k8s/ingress.yaml`
- [ ] Review and update resource limits based on expected load
- [ ] Configure firewall rules
- [ ] Set up SSL/TLS certificates (automated with cert-manager)
- [ ] Review Kubernetes security contexts
- [ ] Configure network policies

### Infrastructure
- [ ] Kubernetes cluster running (v1.28+)
- [ ] kubectl configured and tested
- [ ] cert-manager installed
- [ ] nginx-ingress-controller installed
- [ ] Storage class available for PVCs
- [ ] Monitoring stack ready (Prometheus/Grafana)
- [ ] Log aggregation configured

### Configuration
- [ ] Review `k8s/configmap.yaml` settings
- [ ] Set appropriate log levels (RUST_LOG)
- [ ] Configure resource requests/limits
- [ ] Set up external backup storage (S3/GCS)
- [ ] Configure backup retention policies

## Deployment Steps

### 1. Create Namespace and Secrets
```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Create secrets (NEVER commit these!)
kubectl create secret generic catbird-mls-secrets \
  --from-literal=POSTGRES_PASSWORD='YOUR_SECURE_PASSWORD' \
  --from-literal=REDIS_PASSWORD='YOUR_SECURE_REDIS_PASSWORD' \
  --from-literal=JWT_SECRET='YOUR_SECURE_JWT_SECRET' \
  --from-literal=DATABASE_URL='postgresql://catbird:PASSWORD@postgres-service:5432/catbird' \
  --from-literal=REDIS_URL='redis://:PASSWORD@redis-service:6379' \
  -n catbird
```
- [ ] Namespace created
- [ ] Secrets created and verified

### 2. Deploy Infrastructure
```bash
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
```
- [ ] ConfigMap applied
- [ ] PostgreSQL StatefulSet deployed
- [ ] Redis StatefulSet deployed
- [ ] Wait for databases to be ready (5-10 minutes)

### 3. Run Database Migrations
```bash
kubectl apply -f k8s/job-migrations.yaml
kubectl wait --for=condition=complete job/catbird-db-migrations -n catbird --timeout=300s
```
- [ ] Migration job completed successfully
- [ ] Database schema created

### 4. Deploy Application
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```
- [ ] Deployment created
- [ ] Services created
- [ ] Pods running and healthy (check with `kubectl get pods -n catbird`)

### 5. Configure Ingress
```bash
kubectl apply -f k8s/ingress.yaml
```
- [ ] Ingress created
- [ ] TLS certificate issued (check cert-manager logs)
- [ ] Domain resolves correctly
- [ ] HTTPS working

### 6. Enable Auto-scaling
```bash
kubectl apply -f k8s/hpa.yaml
```
- [ ] HorizontalPodAutoscaler created
- [ ] Metrics server working
- [ ] Scaling tested

### 7. Configure Automated Backups
```bash
kubectl apply -f k8s/cronjob-backup.yaml
```
- [ ] CronJob created
- [ ] Backup PVC created
- [ ] Test backup manually

## Post-Deployment Verification

### Health Checks
```bash
# Port-forward for testing
kubectl port-forward svc/catbird-mls-service 8080:80 -n catbird

# Check liveness
curl http://localhost:8080/health/live

# Check readiness
curl http://localhost:8080/health/ready

# Check detailed health
curl http://localhost:8080/health | jq
```
- [ ] Liveness probe returns 200 OK
- [ ] Readiness probe returns 200 OK
- [ ] Detailed health shows all checks healthy
- [ ] Database connectivity verified

### Functional Testing
- [ ] Create conversation works
- [ ] Add members works
- [ ] Send message works
- [ ] Get messages works
- [ ] Key package operations work
- [ ] Blob upload works

### Performance Testing
```bash
# Install hey for load testing
go install github.com/rakyll/hey@latest

# Run load test
hey -n 10000 -c 100 https://mls.yourdomain.com/health
```
- [ ] Response times acceptable (<100ms p95)
- [ ] No errors under load
- [ ] Auto-scaling triggers correctly
- [ ] Resource usage within limits

### Monitoring
- [ ] Pods are running (`kubectl get pods -n catbird`)
- [ ] No error logs (`kubectl logs -l app=catbird-mls-server -n catbird`)
- [ ] Metrics are being collected
- [ ] Alerts configured
- [ ] Dashboard showing metrics

## Ongoing Operations

### Daily
- [ ] Check pod health: `kubectl get pods -n catbird`
- [ ] Review error logs
- [ ] Monitor resource usage: `kubectl top pods -n catbird`

### Weekly
- [ ] Review backup status
- [ ] Check disk usage
- [ ] Review scaling events
- [ ] Security audit logs

### Monthly
- [ ] Test backup restoration
- [ ] Review and rotate secrets
- [ ] Update dependencies
- [ ] Capacity planning review

## Rollback Procedure

If deployment fails:

```bash
# View rollout history
kubectl rollout history deployment/catbird-mls-server -n catbird

# Rollback to previous version
kubectl rollout undo deployment/catbird-mls-server -n catbird

# Rollback to specific revision
kubectl rollout undo deployment/catbird-mls-server --to-revision=N -n catbird

# Verify rollback
kubectl rollout status deployment/catbird-mls-server -n catbird
```

- [ ] Rollback tested in staging
- [ ] Rollback procedure documented
- [ ] Team trained on rollback

## Emergency Contacts

Document your emergency contacts:

- **On-call Engineer**: _________________
- **DevOps Lead**: _________________
- **Security Team**: _________________
- **Infrastructure Provider Support**: _________________

## Incident Response

1. **Assess**: Check logs and metrics
2. **Communicate**: Notify team
3. **Mitigate**: Scale up or rollback
4. **Resolve**: Fix root cause
5. **Document**: Post-mortem

## Sign-off

- [ ] Deployment tested in staging
- [ ] All checklist items completed
- [ ] Documentation updated
- [ ] Team notified
- [ ] Monitoring confirmed

**Deployed by**: _________________ **Date**: _________________
**Reviewed by**: _________________ **Date**: _________________

---

**Remember**: 
- Never commit secrets to git
- Always test in staging first
- Keep documentation updated
- Monitor closely after deployment
