#!/bin/bash
set -e

# Health check script for monitoring systems
# Usage: ./health-check.sh [URL]

URL="${1:-http://localhost:3000}"
TIMEOUT=10
MAX_RETRIES=3

echo "Checking health of Catbird MLS Server at $URL..."

for i in $(seq 1 $MAX_RETRIES); do
    echo "Attempt $i/$MAX_RETRIES..."
    
    # Liveness check
    if ! curl -sf --max-time $TIMEOUT "$URL/health/live" > /dev/null 2>&1; then
        echo "⚠ Liveness check failed"
        if [ $i -eq $MAX_RETRIES ]; then
            echo "❌ Server is not alive after $MAX_RETRIES attempts"
            exit 1
        fi
        sleep 2
        continue
    fi
    echo "✓ Liveness check passed"
    
    # Readiness check
    if ! curl -sf --max-time $TIMEOUT "$URL/health/ready" > /dev/null 2>&1; then
        echo "⚠ Readiness check failed"
        if [ $i -eq $MAX_RETRIES ]; then
            echo "❌ Server is not ready after $MAX_RETRIES attempts"
            exit 2
        fi
        sleep 2
        continue
    fi
    echo "✓ Readiness check passed"
    
    # Detailed health check
    HEALTH_RESPONSE=$(curl -sf --max-time $TIMEOUT "$URL/health" 2>&1)
    if [ $? -ne 0 ]; then
        echo "⚠ Health endpoint failed"
        if [ $i -eq $MAX_RETRIES ]; then
            echo "❌ Health check failed after $MAX_RETRIES attempts"
            exit 3
        fi
        sleep 2
        continue
    fi
    
    echo "✓ Health check passed"
    echo ""
    echo "Health Status:"
    echo "$HEALTH_RESPONSE" | jq . 2>/dev/null || echo "$HEALTH_RESPONSE"
    
    exit 0
done

echo "❌ Health check failed after $MAX_RETRIES attempts"
exit 1
