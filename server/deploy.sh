#!/bin/bash

# =============================================================================
# Catbird MLS Server - Deployment Helper
# =============================================================================
# Host-based deployment using systemd
# =============================================================================

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Catbird MLS Server - Deployment Helper                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Choose a deployment method:"
echo ""
echo "  1) Fresh Deploy (WIPE ALL DATA - for development/testing)"
echo "     - Stops the server"
echo "     - Clears the database"
echo "     - Rebuilds binary"
echo "     - ⚠️  WARNING: ALL DATA WILL BE LOST"
echo ""
echo "  2) Update Deploy (PRESERVE DATA - for production updates)"
echo "     - Builds new binary"
echo "     - Restarts the server"
echo "     - ✓ Database preserved"
echo ""
echo "  3) Quick Restart (no rebuild - just restart)"
echo "     - Restarts the systemd service"
echo "     - ✓ Data preserved"
echo ""
echo "  4) Status (check current deployment)"
echo "     - Show service status"
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
        echo "Restarting service..."
        echo "═══════════════════════════════════════════════════════════════"
        sudo systemctl restart catbird-mls-server
        sleep 3
        echo ""
        echo "Service Status:"
        sudo systemctl status catbird-mls-server --no-pager || true
        echo ""
        echo "✅ Service restarted"
        ;;
    4)
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "Current Status:"
        echo "═══════════════════════════════════════════════════════════════"
        sudo systemctl status catbird-mls-server --no-pager || true
        echo ""
        echo "Health Check:"
        curl -s http://localhost:3000/health | jq . 2>/dev/null || curl -s http://localhost:3000/health || echo "⚠️  Server not responding"
        echo ""
        echo "Recent Logs (last 20 lines):"
        sudo journalctl -u catbird-mls-server -n 20 --no-pager
        ;;
    0|*)
        echo "Cancelled"
        exit 0
        ;;
esac
