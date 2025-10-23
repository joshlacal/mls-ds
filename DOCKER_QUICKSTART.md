# MLS Server Quick Reference

## 🚀 Quick Start
```bash
cd /home/ubuntu/mls/server
sudo docker compose --env-file .env.docker up -d
```

## 🔍 Check Status
```bash
sudo docker compose ps
curl http://localhost:3000/health
```

## 📝 View Logs
```bash
sudo docker logs -f catbird-mls-server
```

## 🔄 Restart
```bash
sudo docker compose restart
```

## 🛑 Stop
```bash
sudo docker compose down
```

## 🌐 Endpoints
- **MLS Server**: http://localhost:3000
- **Health Check**: http://localhost:3000/health
- **PostgreSQL**: localhost:5433 (user: catbird, db: catbird)
- **Redis**: localhost:6380

## 📦 Containers
- `catbird-mls-server` - MLS application
- `catbird-postgres` - PostgreSQL database
- `catbird-redis` - Redis cache

## ⚙️ Configuration
Edit: `/home/ubuntu/mls/server/.env.docker`

---
For detailed info, see: `/home/ubuntu/mls/DOCKER_MIGRATION_SUMMARY.md`
