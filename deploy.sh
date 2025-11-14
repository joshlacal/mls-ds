#!/bin/bash
#
# Catbird MLS Server Deployment Script
# Usage: ./deploy.sh
#
# This script:
# 1. Builds the release binary
# 2. Copies it to the correct location
# 3. Rebuilds the Docker image
# 4. Recreates the container
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
MLS_ROOT="/home/ubuntu/mls"
SERVER_DIR="$MLS_ROOT/server"
TARGET_DIR="$MLS_ROOT/target"
BINARY_NAME="catbird-server"
IMAGE_NAME="server-mls-server"
CONTAINER_NAME="catbird-mls-server"
NETWORK_NAME="server_catbird-network"

echo -e "${GREEN}=== Catbird MLS Server Deployment ===${NC}"
echo

# Step 1: Build release binary
echo -e "${YELLOW}[1/6] Building release binary...${NC}"
cd "$MLS_ROOT/server"
SQLX_OFFLINE=true cargo build --release
echo -e "${GREEN}✓ Build complete${NC}"
echo

# Step 2: Verify binary exists and copy it
echo -e "${YELLOW}[2/6] Copying binary to Docker build location...${NC}"
if [ ! -f "$TARGET_DIR/release/$BINARY_NAME" ]; then
    echo -e "${RED}ERROR: Binary not found at $TARGET_DIR/release/$BINARY_NAME${NC}"
    exit 1
fi

cp -f "$TARGET_DIR/release/$BINARY_NAME" "$SERVER_DIR/$BINARY_NAME"
echo -e "${GREEN}✓ Binary copied${NC}"
echo "  From: $TARGET_DIR/release/$BINARY_NAME"
echo "  To:   $SERVER_DIR/$BINARY_NAME"
echo "  Size: $(du -h "$SERVER_DIR/$BINARY_NAME" | cut -f1)"
echo "  Date: $(date -r "$SERVER_DIR/$BINARY_NAME" '+%Y-%m-%d %H:%M:%S')"
echo

# Step 3: Stop and remove old container
echo -e "${YELLOW}[3/6] Stopping old container...${NC}"
if docker ps -a | grep -q "$CONTAINER_NAME"; then
    docker stop "$CONTAINER_NAME" || true
    docker rm "$CONTAINER_NAME" || true
    echo -e "${GREEN}✓ Old container removed${NC}"
else
    echo "  No existing container found"
fi
echo

# Step 4: Rebuild Docker image (no cache)
echo -e "${YELLOW}[4/6] Rebuilding Docker image...${NC}"
cd "$SERVER_DIR"
docker build --no-cache -f Dockerfile.prebuilt -t "$IMAGE_NAME" .
echo -e "${GREEN}✓ Docker image rebuilt${NC}"
echo

# Step 5: Start new container
echo -e "${YELLOW}[5/6] Starting new container...${NC}"
docker run -d \
  --name "$CONTAINER_NAME" \
  --network "$NETWORK_NAME" \
  -p 3000:3000 \
  -e DATABASE_URL="postgresql://catbird:changeme@catbird-postgres:5432/catbird" \
  -e REDIS_URL="redis://catbird-redis:6379" \
  -e RUST_LOG="info" \
  -e SERVICE_DID="did:web:mls.catbird.blue" \
  -e SERVER_PORT="3000" \
  "$IMAGE_NAME"
echo -e "${GREEN}✓ Container started${NC}"
echo

# Step 6: Verify deployment
echo -e "${YELLOW}[6/6] Verifying deployment...${NC}"
sleep 3

# Check container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo -e "${RED}ERROR: Container is not running${NC}"
    echo "Container logs:"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -20
    exit 1
fi

# Check binary timestamp in container
CONTAINER_BINARY_DATE=$(docker exec "$CONTAINER_NAME" date -r "/app/$BINARY_NAME" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")
echo -e "${GREEN}✓ Container is running${NC}"
echo "  Binary date in container: $CONTAINER_BINARY_DATE"
echo

# Show recent logs
echo "Recent logs:"
docker logs "$CONTAINER_NAME" 2>&1 | grep -E "Starting|Server listening|ERROR" | tail -5
echo

echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo "The server is now running with the latest binary."
echo
echo "Useful commands:"
echo "  View logs:    docker logs -f $CONTAINER_NAME"
echo "  Stop server:  docker stop $CONTAINER_NAME"
echo "  Restart:      docker restart $CONTAINER_NAME"
echo "  Shell access: docker exec -it $CONTAINER_NAME /bin/sh"
