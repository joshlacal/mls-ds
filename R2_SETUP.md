# Cloudflare R2 Setup Guide

## Why Cloudflare R2?

**Cloudflare R2 is dramatically cheaper than AWS S3 or PostgreSQL blob storage:**

- **No egress fees** (AWS charges $0.09/GB for downloads)
- **Storage**: $0.015/GB/month (vs S3's $0.023/GB/month)
- **Free tier**: 10 GB storage + 1M Class A operations/month
- **S3-compatible API** (drop-in replacement)

### Cost Comparison for 1000 users:

| Storage Method | Monthly Cost |
|---------------|-------------|
| PostgreSQL blobs (1GB) | $20-50 (VPS upgrade) |
| AWS S3 (1GB storage + 10GB egress) | $1.02 |
| **Cloudflare R2 (1GB storage + 10GB egress)** | **$0.015** |

**R2 is literally 68x cheaper than S3!**

## Setting Up R2

### 1. Create Cloudflare Account
1. Go to https://dash.cloudflare.com/
2. Sign up (free tier available)
3. Navigate to **R2** in the sidebar

### 2. Create R2 Bucket
```bash
# In Cloudflare Dashboard -> R2
1. Click "Create Bucket"
2. Name: catbird-messages
3. Location: Automatic (or choose region)
4. Click "Create Bucket"
```

### 3. Generate API Tokens
```bash
# In R2 Dashboard -> Manage R2 API Tokens
1. Click "Create API Token"
2. Name: catbird-server
3. Permissions: 
   - Object Read & Write
4. Apply to specific bucket: catbird-messages
5. Click "Create API Token"

# You'll get:
# - Access Key ID
# - Secret Access Key
# - Endpoint URL (looks like: https://abc123.r2.cloudflarestorage.com)
```

⚠️ **Save these credentials immediately - you can't retrieve them later!**

### 4. Configure Environment Variables

Create `.env` file:
```bash
cp .env.example .env
```

Edit `.env`:
```bash
R2_ENDPOINT=https://YOUR_ACCOUNT_ID.r2.cloudflarestorage.com
R2_BUCKET=catbird-messages
R2_ACCESS_KEY_ID=your_access_key_id_here
R2_SECRET_ACCESS_KEY=your_secret_access_key_here
R2_REGION=auto
```

### 5. Test Connection

```bash
# Run the server
cd server
cargo run

# In another terminal, test the blob storage
curl -X POST http://localhost:3000/api/v1/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "encrypted_data": "base64_encoded_encrypted_message",
    "convo_id": "convo_123",
    "recipients": ["did:plc:user1", "did:plc:user2"]
  }'
```

## Using R2 Custom Domains (Optional)

For production, you can serve R2 objects through your own domain:

1. In R2 Dashboard -> Settings -> Domain
2. Add custom domain: `cdn.catbird.example.com`
3. Cloudflare handles SSL automatically
4. Update `R2_ENDPOINT` to use your custom domain

This hides that you're using R2 and provides better branding.

## Lifecycle Policies

Set automatic cleanup to delete old messages:

```bash
# In R2 Dashboard -> Bucket Settings -> Lifecycle Rules
1. Click "Add Rule"
2. Name: delete-old-messages
3. Prefix: messages/
4. Delete after: 30 days
5. Save
```

This automatically deletes messages older than 30 days, keeping storage costs low.

## Migration from PostgreSQL Blobs

If you're currently storing blobs in PostgreSQL:

```sql
-- Extract and upload to R2
SELECT id, encrypted_data FROM messages;

-- For each row:
-- 1. Upload encrypted_data to R2
-- 2. Store returned blob_key
-- 3. Update message record
```

## Monitoring Usage

Track your R2 usage:
1. Cloudflare Dashboard -> R2 -> Analytics
2. Monitor:
   - Storage (GB)
   - Class A operations (PUT, LIST)
   - Class B operations (GET, HEAD)

Free tier limits:
- 10 GB storage
- 1M Class A operations/month
- 10M Class B operations/month

For 1000 active users, you'll stay well within free tier.

## Security Best Practices

1. **Rotate API tokens** every 90 days
2. **Use least-privilege access** (only the permissions you need)
3. **Enable CORS** only for your domains:
   ```bash
   # In R2 Dashboard -> Bucket -> Settings -> CORS
   {
     "AllowedOrigins": ["https://catbird.app"],
     "AllowedMethods": ["GET", "PUT"],
     "AllowedHeaders": ["*"],
     "MaxAgeSeconds": 3600
   }
   ```
4. **Never commit credentials** to git (use .env files)

## Troubleshooting

### "Access Denied" errors
- Check your API token has correct permissions
- Verify bucket name matches exactly
- Ensure token hasn't expired

### "Endpoint not found"
- Verify R2_ENDPOINT includes your account ID
- Check you're using the R2 endpoint, not S3

### "Connection timeout"
- Check firewall isn't blocking Cloudflare IPs
- Verify R2_ENDPOINT uses HTTPS

## Alternative: AWS S3

If you prefer AWS S3 (though it costs 68x more):

```bash
# Same code works! Just change env vars:
R2_ENDPOINT=https://s3.us-east-1.amazonaws.com
R2_BUCKET=your-s3-bucket
R2_ACCESS_KEY_ID=your-aws-access-key
R2_SECRET_ACCESS_KEY=your-aws-secret-key
R2_REGION=us-east-1
```

The code is S3-compatible, so you can switch providers anytime.

## Cost Calculator

For your expected usage:

```
Users: 1000
Messages per user per day: 50
Average message size: 2 KB
Storage duration: 30 days

Total storage: 1000 * 50 * 2KB * 30 = 3 GB
Monthly operations: 1000 * 50 * 30 = 1.5M requests

R2 Cost:
- Storage: 3 GB * $0.015 = $0.045
- Operations: Covered by free tier (1M free)
Total: ~$0.05/month

PostgreSQL Cost:
- Need VPS upgrade: $20-50/month
Total: $20-50/month

Savings: 400-1000x cheaper with R2!
```

## Next Steps

1. ✅ Set up R2 bucket
2. ✅ Configure environment variables
3. ✅ Run database migration
4. ✅ Test with curl or Postman
5. ✅ Integrate with iOS client
6. ✅ Set up lifecycle policies
7. ✅ Monitor usage

You're now storing encrypted messages for pennies per month! 🎉
