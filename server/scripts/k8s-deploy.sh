#!/bin/bash
set -e

# Kubernetes deployment script
# Usage: ./k8s-deploy.sh [environment]

ENVIRONMENT="${1:-production}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(dirname "$SCRIPT_DIR")/k8s"

echo "Deploying Catbird MLS Server to Kubernetes ($ENVIRONMENT)..."

# Check kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl not found. Please install kubectl."
    exit 1
fi

# Create namespace
echo "Creating namespace..."
kubectl apply -f "$K8S_DIR/namespace.yaml"

# Check if secrets exist, if not, prompt user
if ! kubectl get secret catbird-mls-secrets -n catbird &> /dev/null; then
    echo "Error: Secrets not found!"
    echo "Please create secrets first:"
    echo "kubectl create secret generic catbird-mls-secrets \\"
    echo "  --from-literal=POSTGRES_PASSWORD='...' \\"
    echo "  --from-literal=REDIS_PASSWORD='...' \\"
    echo "  --from-literal=JWT_SECRET='...' \\"
    echo "  --from-literal=DATABASE_URL='...' \\"
    echo "  --from-literal=REDIS_URL='...' \\"
    echo "  -n catbird"
    exit 1
fi

# Apply configmap
echo "Applying ConfigMap..."
kubectl apply -f "$K8S_DIR/configmap.yaml"

# Deploy databases
echo "Deploying PostgreSQL..."
kubectl apply -f "$K8S_DIR/postgres.yaml"

echo "Deploying Redis..."
kubectl apply -f "$K8S_DIR/redis.yaml"

# Wait for databases
echo "Waiting for databases to be ready..."
kubectl wait --for=condition=ready pod -l app=postgres -n catbird --timeout=300s || {
    echo "PostgreSQL failed to start. Check logs:"
    kubectl logs -l app=postgres -n catbird --tail=50
    exit 1
}

kubectl wait --for=condition=ready pod -l app=redis -n catbird --timeout=300s || {
    echo "Redis failed to start. Check logs:"
    kubectl logs -l app=redis -n catbird --tail=50
    exit 1
}

# Run migrations
echo "Running database migrations..."
kubectl delete job catbird-db-migrations -n catbird --ignore-not-found=true
kubectl apply -f "$K8S_DIR/job-migrations.yaml"
kubectl wait --for=condition=complete job/catbird-db-migrations -n catbird --timeout=300s || {
    echo "Migrations failed. Check logs:"
    kubectl logs -l job-name=catbird-db-migrations -n catbird
    exit 1
}

# Deploy application
echo "Deploying MLS Server..."
kubectl apply -f "$K8S_DIR/deployment.yaml"
kubectl apply -f "$K8S_DIR/service.yaml"

# Wait for deployment
echo "Waiting for deployment to be ready..."
kubectl rollout status deployment/catbird-mls-server -n catbird --timeout=300s

# Deploy ingress
echo "Deploying Ingress..."
kubectl apply -f "$K8S_DIR/ingress.yaml"

# Deploy HPA
echo "Deploying HorizontalPodAutoscaler..."
kubectl apply -f "$K8S_DIR/hpa.yaml"

# Deploy backup cronjob
echo "Deploying backup CronJob..."
kubectl apply -f "$K8S_DIR/cronjob-backup.yaml"

# Health check
echo "Performing health check..."
sleep 5
kubectl port-forward svc/catbird-mls-service 8080:80 -n catbird &
PORT_FORWARD_PID=$!
sleep 3

if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
    echo "✓ Deployment successful! Server is healthy."
else
    echo "⚠ Warning: Health check failed. Check logs:"
    kubectl logs -l app=catbird-mls-server -n catbird --tail=50
fi

kill $PORT_FORWARD_PID 2>/dev/null || true

# Show deployment info
echo ""
echo "Deployment Summary:"
echo "==================="
kubectl get all -n catbird
echo ""
echo "Ingress:"
kubectl get ingress -n catbird

echo ""
echo "To view logs: kubectl logs -f deployment/catbird-mls-server -n catbird"
echo "To scale: kubectl scale deployment/catbird-mls-server --replicas=5 -n catbird"
