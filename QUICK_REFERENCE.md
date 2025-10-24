# Quick Reference Guide

## JWT Token Generation

### Generate Test Tokens
```bash
cd server/scripts
python3 generate_test_jwt.py
```

**Output**: Creates 4 token files:
- `test_token_1h.txt` - Short-lived (1 hour)
- `test_token_24h.txt` - Medium-lived (24 hours)  
- `test_token_168h.txt` - Long-lived (1 week)
- `test_token_720h.txt` - Extended (30 days)

### Use Tokens in API Calls
```bash
# Load token
TOKEN=$(cat server/test_token_24h.txt)

# Make API call
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/xrpc/blue.catbird.mls.listGroups
```

### Configure Token Generation
```bash
# Set environment variables before running
export JWT_SECRET="your-secret-key"
export SERVICE_DID="did:web:your-service"
export ISSUER_DID="did:plc:your-issuer"

python3 generate_test_jwt.py
```

---

## Staging Deployment

### Quick Deploy
```bash
cd server/scripts
./deploy-staging.sh
```

### Manual Staging Control
```bash
cd server/staging

# Start
docker-compose -f docker-compose.staging.yml up -d

# Stop
docker-compose -f docker-compose.staging.yml down

# View logs
docker-compose -f docker-compose.staging.yml logs -f mls-server

# Restart specific service
docker-compose -f docker-compose.staging.yml restart mls-server
```

### Access Staging Services
- **MLS Server**: http://localhost:3000
- **Health Check**: http://localhost:3000/health
- **Metrics**: http://localhost:3000/metrics
- **Grafana**: http://localhost:3001
- **Prometheus**: http://localhost:9090

---

## Load Testing

### Basic Load Test
```bash
cd server/scripts
./load_test.sh
```

### Custom Load Test
```bash
# Configure parameters
export BASE_URL="http://localhost:3000"
export NUM_USERS=50
export MESSAGES_PER_USER=200
export CONCURRENT=10

./load_test.sh
```

### Load Test Parameters
- `BASE_URL` - Server URL (default: http://localhost:3000)
- `NUM_USERS` - Number of test users (default: 10)
- `MESSAGES_PER_USER` - Messages per user (default: 100)
- `CONCURRENT` - Concurrent requests (default: 5)

### View Results
```bash
# Results are saved to timestamped directory
ls -la load_test_results_*/

# View summary
cat load_test_results_*/summary.txt

# View individual metrics
cat load_test_results_*/create_convo.csv
cat load_test_results_*/send_message.csv
cat load_test_results_*/get_messages.csv
cat load_test_results_*/stress_test.csv
```

---

## Common API Endpoints

### Health & Metrics
```bash
# Health check
curl http://localhost:3000/health

# Prometheus metrics
curl http://localhost:3000/metrics
```

### Conversations
```bash
TOKEN=$(cat server/test_token_24h.txt)

# List conversations
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/xrpc/blue.catbird.mls.listConvos

# Create conversation
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.createConvo \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cipherSuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    "metadata": {"name": "Test Group"}
  }'

# Get conversation
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/xrpc/blue.catbird.mls.getConvo?convoId=<ID>"
```

### Messages
```bash
# Send message
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.sendMessage \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "convoId": "<CONVO_ID>",
    "senderDid": "did:plc:test123",
    "ciphertext": "<BASE64_ENCRYPTED_DATA>",
    "epoch": 0
  }'

# Get messages
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/xrpc/blue.catbird.mls.getMessages?convoId=<ID>&limit=50"
```

---

## Troubleshooting

### JWT Issues
```bash
# Verify token claims
TOKEN=$(cat test_token_24h.txt)
echo $TOKEN | cut -d. -f2 | base64 -d | jq

# Check expiration
echo $TOKEN | cut -d. -f2 | base64 -d | jq .exp
date -r $(echo $TOKEN | cut -d. -f2 | base64 -d | jq -r .exp)

# Regenerate tokens
python3 server/scripts/generate_test_jwt.py
```

### Server Issues
```bash
# Check if server is running
curl http://localhost:3000/health

# View server logs (Docker)
docker logs catbird-mls-server

# View server logs (Staging)
cd server/staging
docker-compose -f docker-compose.staging.yml logs -f mls-server

# Restart server
docker restart catbird-mls-server
```

### Database Issues
```bash
# Connect to PostgreSQL
docker exec -it catbird-postgres psql -U catbird

# Check tables
\dt

# View conversations
SELECT * FROM conversations LIMIT 5;

# View messages
SELECT id, convo_id, sender_did, epoch FROM messages LIMIT 5;
```

### Load Test Issues
```bash
# Check dependencies
which curl jq bc python3

# Run with debug output
set -x
./load_test.sh

# Test single endpoint
curl -v -H "Authorization: Bearer $(cat test_token_24h.txt)" \
  http://localhost:3000/health
```

---

## Performance Monitoring

### View Live Metrics
```bash
# Prometheus metrics
curl http://localhost:3000/metrics

# Grafana dashboards
open http://localhost:3001

# View specific metric
curl -s http://localhost:3000/metrics | grep "http_requests_total"
```

### Database Performance
```bash
# Connect to database
docker exec -it catbird-postgres psql -U catbird

# Check table sizes
SELECT 
  relname as table_name,
  pg_size_pretty(pg_total_relation_size(relid)) as size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;

# Check index usage
SELECT 
  schemaname,
  tablename,
  indexname,
  idx_scan,
  idx_tup_read,
  idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
```

---

## Environment Variables

### Required for Production
```bash
DATABASE_URL=postgresql://user:pass@host:5432/dbname
JWT_SECRET=your-secret-key-min-32-chars
SERVICE_DID=did:web:your-service.com
```

### Optional Configuration
```bash
RUST_LOG=info,catbird_server=debug
REDIS_URL=redis://localhost:6379
SERVER_PORT=3000
ENVIRONMENT=staging
```

---

## Development Workflow

### 1. Local Development
```bash
# Start local server
cargo run --release

# Generate test tokens
python3 server/scripts/generate_test_jwt.py

# Test API
./test_api.sh
```

### 2. Testing
```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test '*'

# Run load tests
./server/scripts/load_test.sh
```

### 3. Deploy to Staging
```bash
# Deploy
./server/scripts/deploy-staging.sh

# Verify
curl http://localhost:3000/health

# Monitor
docker-compose -f server/staging/docker-compose.staging.yml logs -f
```

### 4. Production Deploy
```bash
# Build production image
docker build -t catbird-server:production -f server/Dockerfile .

# Tag and push
docker tag catbird-server:production your-registry/catbird-server:latest
docker push your-registry/catbird-server:latest

# Deploy (depends on your infrastructure)
kubectl apply -f k8s/production/
```

---

## Quick Links

- **Project Documentation**: README.md
- **API Documentation**: docs/API.md
- **Architecture**: CLOUDKIT_MLS_ARCHITECTURE.md
- **Deployment Guide**: PRODUCTION_DEPLOYMENT.md
- **Task Completion Report**: TASKS_COMPLETED.md

---

**Last Updated**: October 24, 2025
