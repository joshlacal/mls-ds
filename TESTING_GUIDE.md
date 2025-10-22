# MLS Server Testing Guide

## Server Information

- **URL**: http://mls.vps-9f95c91c.vps.ovh.us (or http://51.81.33.144)
- **DID**: `did:web:mls.vps-9f95c91c.vps.ovh.us`
- **Server Port**: 3000 (proxied through nginx on port 80)
- **Database**: PostgreSQL (mls_dev)
- **Cache**: Redis (localhost:6379)

## DID Document

The server's DID document is available at:
```bash
curl http://mls.vps-9f95c91c.vps.ovh.us/.well-known/did.json
```

**Response:**
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "did:web:mls.vps-9f95c91c.vps.ovh.us",
  "verificationMethod": [
    {
      "id": "did:web:mls.vps-9f95c91c.vps.ovh.us#atproto",
      "type": "Multikey",
      "controller": "did:web:mls.vps-9f95c91c.vps.ovh.us",
      "publicKeyMultibase": "zWo9ufkfcQw8iA4yO-6XCwv0XhfGN1AmV01jJ0K5rmpc"
    }
  ],
  "service": [
    {
      "id": "#mls",
      "type": "MlsServer",
      "serviceEndpoint": "https://mls.vps-9f95c91c.vps.ovh.us"
    }
  ]
}
```

**Private Key**: Stored in `/home/ubuntu/mls/did_key.pem` (ED25519)

## Health Checks

### Main Health Endpoint
```bash
curl http://mls.vps-9f95c91c.vps.ovh.us/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "timestamp": 1761097473,
  "version": "0.1.0",
  "checks": {
    "database": "healthy",
    "memory": "healthy"
  }
}
```

### Readiness Check
```bash
curl http://mls.vps-9f95c91c.vps.ovh.us/health/ready
```

### Liveness Check
```bash
curl http://mls.vps-9f95c91c.vps.ovh.us/health/live
```

### Metrics
```bash
curl http://mls.vps-9f95c91c.vps.ovh.us/metrics
```

## API Endpoints

All MLS endpoints are under the `/xrpc/blue.catbird.mls.*` namespace:

### 1. Create Conversation
```bash
curl -X POST http://mls.vps-9f95c91c.vps.ovh.us/xrpc/blue.catbird.mls.createConvo \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer did:web:mls.vps-9f95c91c.vps.ovh.us" \
  -d '{
    "title": "Test Conversation",
    "members": ["did:web:mls.vps-9f95c91c.vps.ovh.us"]
  }'
```

**Expected Response:**
```json
{
  "convoId": "uuid-here",
  "rev": "initial-revision"
}
```

### 2. Add Members
```bash
curl -X POST http://mls.vps-9f95c91c.vps.ovh.us/xrpc/blue.catbird.mls.addMembers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer did:web:mls.vps-9f95c91c.vps.ovh.us" \
  -d '{
    "convoId": "your-convo-id",
    "members": ["did:plc:example123"],
    "commit": "base64-encoded-mls-commit"
  }'
```

### 3. Send Message
```bash
curl -X POST http://mls.vps-9f95c91c.vps.ovh.us/xrpc/blue.catbird.mls.sendMessage \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer did:web:mls.vps-9f95c91c.vps.ovh.us" \
  -d '{
    "convoId": "your-convo-id",
    "message": {
      "ciphertext": "base64-encrypted-content",
      "embed": null
    }
  }'
```

### 4. Get Messages
```bash
curl "http://mls.vps-9f95c91c.vps.ovh.us/xrpc/blue.catbird.mls.getMessages?convoId=your-convo-id&limit=50" \
  -H "Authorization: Bearer did:web:mls.vps-9f95c91c.vps.ovh.us"
```

### 5. Publish Key Package
```bash
curl -X POST http://mls.vps-9f95c91c.vps.ovh.us/xrpc/blue.catbird.mls.publishKeyPackage \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer did:web:mls.vps-9f95c91c.vps.ovh.us" \
  -d '{
    "keyPackage": "base64-encoded-mls-keypackage"
  }'
```

### 6. Get Key Packages
```bash
curl "http://mls.vps-9f95c91c.vps.ovh.us/xrpc/blue.catbird.mls.getKeyPackages?dids=did:web:mls.vps-9f95c91c.vps.ovh.us" \
  -H "Authorization: Bearer did:web:mls.vps-9f95c91c.vps.ovh.us"
```

### 7. Leave Conversation
```bash
curl -X POST http://mls.vps-9f95c91c.vps.ovh.us/xrpc/blue.catbird.mls.leaveConvo \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer did:web:mls.vps-9f95c91c.vps.ovh.us" \
  -d '{
    "convoId": "your-convo-id"
  }'
```

### 8. Upload Blob
```bash
curl -X POST http://mls.vps-9f95c91c.vps.ovh.us/xrpc/blue.catbird.mls.uploadBlob \
  -H "Content-Type: application/octet-stream" \
  -H "Authorization: Bearer did:web:mls.vps-9f95c91c.vps.ovh.us" \
  --data-binary @/path/to/file
```

## Server Management

### View Server Logs
```bash
tail -f /home/ubuntu/mls/server.log
```

### Check Server Process
```bash
ps aux | grep catbird-server
```

### Stop Server
```bash
pkill -f catbird-server
```

### Start Server
```bash
cd /home/ubuntu/mls/server && /home/ubuntu/mls/target/release/catbird-server > /home/ubuntu/mls/server.log 2>&1 &
```

### Restart Server
```bash
pkill -f catbird-server && sleep 2 && cd /home/ubuntu/mls/server && /home/ubuntu/mls/target/release/catbird-server > /home/ubuntu/mls/server.log 2>&1 &
```

## Database Access

### Connect to Database
```bash
psql -d mls_dev
```

### View Tables
```sql
\dt
```

### Query Conversations
```sql
SELECT * FROM conversations;
```

### Query Messages
```sql
SELECT * FROM messages LIMIT 10;
```

### Query Key Packages
```sql
SELECT did, created_at FROM key_packages;
```

## Configuration

### Environment Variables
Located in `/home/ubuntu/mls/server/.env`:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SERVER_PORT`: Server port (3000)
- `JWT_SECRET`: JWT signing secret
- `SERVICE_DID`: Server's DID identifier
- `RUST_LOG`: Logging level (info, debug, trace)

### Nginx Configuration
Located in `/etc/nginx/sites-available/mls`:
- Serves DID document from `/home/ubuntu/mls/.well-known/did.json`
- Proxies API requests to `localhost:3000`

## Troubleshooting

### Server Not Responding
```bash
# Check if server is running
curl http://localhost:3000/health

# Check nginx
sudo systemctl status nginx

# Check logs
tail -50 /home/ubuntu/mls/server.log
```

### Database Connection Issues
```bash
# Test PostgreSQL
psql -d mls_dev -c "SELECT 1;"

# Check PostgreSQL status
sudo systemctl status postgresql
```

### Redis Connection Issues
```bash
# Test Redis
redis-cli ping

# Check Redis status
sudo systemctl status redis-server
```

## Security Notes

⚠️ **Current Configuration is for TESTING ONLY**

For production:
1. Use HTTPS/TLS (install Let's Encrypt certificate)
2. Change `JWT_SECRET` to a strong random value
3. Enable proper authentication middleware
4. Set up rate limiting
5. Restrict database access
6. Use proper DNS (not /etc/hosts)
7. Enable firewall rules

## DNS Setup (For External Access)

To make this accessible from the internet, you need to:

1. **Add DNS Record** (at your domain provider):
   ```
   Type: A
   Name: mls.vps-9f95c91c.vps.ovh
   Value: 51.81.33.144
   TTL: 300
   ```

2. **Install SSL Certificate**:
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d mls.vps-9f95c91c.vps.ovh.us
   ```

3. **Update DID Document** to use `https://` instead of `http://`

## Testing Workflow

1. **Health Check**: Verify server is running
2. **DID Document**: Verify DID is accessible
3. **Create Conversation**: Test conversation creation
4. **Publish Key Package**: Upload a key package
5. **Get Key Packages**: Retrieve key packages
6. **Send Message**: Test message sending
7. **Get Messages**: Retrieve messages

## Quick Test Script

```bash
#!/bin/bash
BASE_URL="http://mls.vps-9f95c91c.vps.ovh.us"
DID="did:web:mls.vps-9f95c91c.vps.ovh.us"

echo "=== Testing Health ==="
curl -s "$BASE_URL/health" | jq .

echo -e "\n=== Testing DID Document ==="
curl -s "$BASE_URL/.well-known/did.json" | jq .

echo -e "\n=== Creating Conversation ==="
CONVO=$(curl -s -X POST "$BASE_URL/xrpc/blue.catbird.mls.createConvo" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DID" \
  -d "{\"title\":\"Test\",\"members\":[\"$DID\"]}")
echo "$CONVO" | jq .

CONVO_ID=$(echo "$CONVO" | jq -r .convoId)
echo -e "\nConversation ID: $CONVO_ID"
```

Save this as `test.sh`, make it executable with `chmod +x test.sh`, and run with `./test.sh`.
