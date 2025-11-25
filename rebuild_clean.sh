#!/bin/bash
set -e

echo "🧹 Starting complete Docker rebuild with clean database..."

cd /home/ubuntu/mls/server

# Step 1: Stop and remove all containers
echo "🛑 Stopping all containers..."
sudo docker compose down -v

# Step 2: Remove all volumes (THIS DELETES ALL DATA!)
echo "🗑️  Removing all volumes (database will be wiped)..."
sudo docker volume rm catbird-postgres-data 2>/dev/null || true
sudo docker volume rm catbird-redis-data 2>/dev/null || true
sudo docker volume rm server_postgres_data 2>/dev/null || true
sudo docker volume rm server_redis_data 2>/dev/null || true

# Step 3: Remove old images to force rebuild
echo "🔨 Removing old images..."
sudo docker rmi server-mls-server 2>/dev/null || true
sudo docker rmi catbird-mls-server 2>/dev/null || true

# Step 4: Clean Docker system (optional but thorough)
echo "🧽 Cleaning Docker system..."
sudo docker system prune -f

# Step 5: Rebuild and start with fresh database
echo "🚀 Building and starting with fresh database..."
sudo docker compose --env-file .env.docker up -d --build

# Step 6: Wait for services to be healthy
echo "⏳ Waiting for services to be healthy..."
sleep 10

# Step 7: Check status
echo ""
echo "✅ Status:"
sudo docker compose ps

echo ""
echo "🎉 Complete! Fresh deployment ready."
echo "📋 Check health: curl http://localhost:3000/health"
echo "📝 View logs: sudo docker logs -f catbird-mls-server"
