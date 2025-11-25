#!/bin/bash
set -e

echo "🧹 Starting clean rebuild and host deployment..."

# Step 1: Stop and remove all Docker containers to ensure no conflicts
echo "🛑 Stopping all Docker containers..."
# Navigate to server directory where docker-compose.yml likely resides
if [ -d "/home/ubuntu/mls/server" ]; then
    cd /home/ubuntu/mls/server
    sudo docker compose down -v 2>/dev/null || true
else
    echo "⚠️  Server directory not found, skipping docker compose down"
fi

# Step 2: Clean up Docker resources
echo "🗑️  Cleaning up Docker resources..."
sudo docker volume rm catbird-postgres-data 2>/dev/null || true
sudo docker volume rm catbird-redis-data 2>/dev/null || true
sudo docker volume rm server_postgres_data 2>/dev/null || true
sudo docker volume rm server_redis_data 2>/dev/null || true
sudo docker system prune -f

# Step 3: Deploy to host using deploy.sh
echo "🚀 Deploying to host machine..."
cd /home/ubuntu/mls
if [ -f "./deploy.sh" ]; then
    ./deploy.sh
else
    echo "❌ deploy.sh not found!"
    exit 1
fi
