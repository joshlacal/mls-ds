#!/bin/bash

# =============================================================================
# Catbird MLS Server - Deployment Helper
# =============================================================================
# This script helps you choose the right deployment method.
# =============================================================================

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Catbird MLS Server - Deployment Helper                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Choose a deployment method:"
echo ""
echo "  1) Fresh Deploy (WIPE ALL DATA - for development/testing)"
echo "     - Stops all services"
echo "     - Removes ALL volumes (postgres_data, redis_data)"
echo "     - Rebuilds with greenfield schema"
echo "     - ⚠️  WARNING: ALL DATA WILL BE LOST"
echo ""
echo "  2) Update Deploy (PRESERVE DATA - for production updates)"
echo "     - Builds new binary"
echo "     - Rebuilds Docker image"
echo "     - Restarts mls-server only"
echo "     - ✓ Database and Redis data preserved"
echo ""
echo "  3) Quick Restart (no rebuild - just restart services)"
echo "     - Restarts all services with existing images"
echo "     - ✓ Data preserved"
echo ""
echo "  4) Status (check current deployment)"
echo "     - Show running containers"
echo "     - Show health status"
echo "     - Show recent logs"
echo ""
echo "  0) Cancel"
echo ""

read -p "Enter choice [0-4]: " choice

case $choice in
    1)
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "Starting Fresh Deploy..."
        echo "═══════════════════════════════════════════════════════════════"
        exec ./deploy-fresh.sh
        ;;
    2)
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "Starting Update Deploy..."
        echo "═══════════════════════════════════════════════════════════════"
        exec ./deploy-update.sh
        ;;
    3)
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "Restarting services..."
        echo "═══════════════════════════════════════════════════════════════"
        docker compose restart
        echo ""
        sleep 5
        echo "Service Status:"
        docker compose ps
        echo ""
        echo "✅ Services restarted"
        ;;
    4)
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "Current Status:"
        echo "═══════════════════════════════════════════════════════════════"
        docker compose ps
        echo ""
        echo "Health Check:"
        curl -s http://localhost:3000/health | jq . 2>/dev/null || curl -s http://localhost:3000/health || echo "⚠️  Server not responding"
        echo ""
        echo "Recent Logs (last 20 lines):"
        docker compose logs --tail 20 mls-server
        ;;
    0|*)
        echo "Cancelled"
        exit 0
        ;;
esac
