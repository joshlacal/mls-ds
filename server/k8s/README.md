# Kubernetes Manifests

Kubernetes deployment configuration for Catbird MLS Server.

## Quick Deploy

```bash
# Deploy everything
kubectl apply -k .

# Or use the deployment script
../scripts/k8s-deploy.sh production
```

## Files

- `namespace.yaml` - Creates the catbird namespace
- `configmap.yaml` - Configuration settings
- `secrets.yaml` - Secret values (template - create actual secrets separately!)
- `postgres.yaml` - PostgreSQL StatefulSet and Service
- `redis.yaml` - Redis StatefulSet and Service
- `deployment.yaml` - MLS Server Deployment
- `service.yaml` - Service definitions (ClusterIP and LoadBalancer)
- `ingress.yaml` - Ingress configuration with TLS
- `hpa.yaml` - HorizontalPodAutoscaler for auto-scaling
- `cronjob-backup.yaml` - Automated daily database backups
- `job-migrations.yaml` - Database migration Job
- `kustomization.yaml` - Kustomize configuration

## Prerequisites

1. **Kubernetes cluster** (v1.28+)
2. **kubectl** configured
3. **cert-manager** installed for TLS certificates
4. **nginx-ingress-controller** or similar
5. **Storage class** available (for PVCs)

## Deployment Order

1. Namespace and Secrets
2. ConfigMap
3. PostgreSQL and Redis (StatefulSets)
4. Database Migrations (Job)
5. Application Deployment
6. Services and Ingress
7. HPA and CronJobs

## Managing Secrets

**Never use the secrets.yaml template in production!**

Create secrets from command line:

```bash
kubectl create secret generic catbird-mls-secrets \
  --from-literal=POSTGRES_PASSWORD='strong_password' \
  --from-literal=REDIS_PASSWORD='strong_redis_password' \
  --from-literal=JWT_SECRET='strong_jwt_secret' \
  --from-literal=DATABASE_URL='postgresql://catbird:strong_password@postgres-service:5432/catbird' \
  --from-literal=REDIS_URL='redis://:strong_redis_password@redis-service:6379' \
  -n catbird
```

## Customization with Kustomize

Create environment-specific overlays:

```bash
mkdir -p overlays/production
cat > overlays/production/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
  - ../../base

namespace: catbird-prod

replicas:
  - name: catbird-mls-server
    count: 5

images:
  - name: catbird-mls-server
    newTag: v1.0.0
EOF

kubectl apply -k overlays/production
```

## Monitoring

```bash
# Watch pods
kubectl get pods -n catbird -w

# View logs
kubectl logs -f deployment/catbird-mls-server -n catbird

# Check scaling
kubectl get hpa -n catbird

# View backups
kubectl get cronjob -n catbird
kubectl get jobs -n catbird
```

## Troubleshooting

```bash
# Describe resources
kubectl describe pod <pod-name> -n catbird
kubectl describe deployment catbird-mls-server -n catbird

# Check events
kubectl get events -n catbird --sort-by='.lastTimestamp'

# Port forward for testing
kubectl port-forward svc/catbird-mls-service 3000:80 -n catbird
```

## Scaling

```bash
# Manual scaling
kubectl scale deployment/catbird-mls-server --replicas=5 -n catbird

# Auto-scaling is configured via hpa.yaml
kubectl get hpa -n catbird
```
