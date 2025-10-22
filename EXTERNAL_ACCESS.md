# External Access Setup

## Current Status

Your MLS server is running and accessible locally. To access it from the internet, you need to configure DNS.

## Server Details

- **Internal URL**: http://localhost:3000
- **Local nginx URL**: http://mls.vps-9f95c91c.vps.ovh.us (via /etc/hosts)
- **External IP**: 51.81.33.144
- **Desired hostname**: mls.vps-9f95c91c.vps.ovh.us

## Option 1: Using the IP Address Directly

You can access the server directly via IP (assuming firewall allows):

```bash
# Test health (replace with actual IP if different)
curl http://51.81.33.144/health

# Test DID document
curl http://51.81.33.144/.well-known/did.json
```

**Note**: The DID in the document references `mls.vps-9f95c91c.vps.ovh.us`, so you'll need proper DNS for full functionality.

## Option 2: Set Up DNS (Recommended)

### Step 1: Add DNS Record

Go to your DNS provider (appears to be OVH) and add an A record:

```
Type: A
Name: mls.vps-9f95c91c.vps.ovh
Value: 51.81.33.144
TTL: 300 (or default)
```

Or if you control the full domain:
```
Type: A
Name: mls
Hostname: vps-9f95c91c.vps.ovh.us
Value: 51.81.33.144
```

### Step 2: Wait for DNS Propagation

DNS changes can take 5 minutes to 48 hours. Check with:

```bash
# Check if DNS is resolving
nslookup mls.vps-9f95c91c.vps.ovh.us

# Or
dig mls.vps-9f95c91c.vps.ovh.us
```

### Step 3: Update /etc/hosts (temporary removal)

Once DNS is working, remove the local override:

```bash
sudo sed -i '/mls.vps-9f95c91c.vps.ovh.us/d' /etc/hosts
```

### Step 4: Install SSL Certificate

Once DNS is working, install Let's Encrypt:

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d mls.vps-9f95c91c.vps.ovh.us

# Follow the prompts
```

This will:
- Automatically configure nginx for HTTPS
- Set up auto-renewal
- Redirect HTTP to HTTPS

### Step 5: Update DID Document

Update the service endpoints to use HTTPS:

```bash
nano /home/ubuntu/mls/.well-known/did.json
```

Change:
```json
"serviceEndpoint": "http://mls.vps-9f95c91c.vps.ovh.us"
```

To:
```json
"serviceEndpoint": "https://mls.vps-9f95c91c.vps.ovh.us"
```

## Option 3: Use a Custom Domain

If you have your own domain (e.g., example.com), you can:

### Step 1: Add DNS Record
```
Type: A
Name: mls
Domain: example.com
Value: 51.81.33.144
```

This creates: mls.example.com

### Step 2: Update Configuration

1. Update nginx config (`/etc/nginx/sites-available/mls`):
```nginx
server_name mls.example.com;
```

2. Update DID document:
```json
"id": "did:web:mls.example.com"
```

3. Update `.env`:
```
SERVICE_DID=did:web:mls.example.com
```

4. Restart services:
```bash
sudo systemctl reload nginx
pkill -f catbird-server
cd /home/ubuntu/mls/server && \
/home/ubuntu/mls/target/release/catbird-server > /home/ubuntu/mls/server.log 2>&1 &
```

5. Get SSL certificate:
```bash
sudo certbot --nginx -d mls.example.com
```

## Testing External Access

Once DNS is set up:

```bash
# From another machine
curl http://mls.vps-9f95c91c.vps.ovh.us/health

# Should return:
# {"status":"healthy","timestamp":...}
```

```bash
# Test DID document
curl http://mls.vps-9f95c91c.vps.ovh.us/.well-known/did.json

# Should return the DID document JSON
```

## Firewall Configuration

Ensure your firewall allows incoming connections:

```bash
# Check current firewall status
sudo ufw status

# Allow HTTP and HTTPS if needed
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

If using a cloud provider firewall (OVH), ensure:
- Port 80 (HTTP) is open
- Port 443 (HTTPS) is open

## Troubleshooting

### DNS Not Resolving

```bash
# Check if DNS is set correctly
dig mls.vps-9f95c91c.vps.ovh.us

# Check from external DNS
dig @8.8.8.8 mls.vps-9f95c91c.vps.ovh.us
```

If not working:
1. Verify DNS record is correct at provider
2. Wait longer (can take up to 24 hours)
3. Clear DNS cache on your machine

### Can't Connect from External Network

```bash
# Test if server is listening on all interfaces
sudo netstat -tlnp | grep :80

# Should show nginx listening on 0.0.0.0:80
```

Check firewall:
```bash
sudo ufw status verbose
```

Test from server itself:
```bash
curl http://localhost:3000/health
curl http://127.0.0.1/health
curl http://51.81.33.144/health
```

### SSL Certificate Issues

If certbot fails:
1. Ensure DNS is resolving correctly
2. Ensure ports 80 and 443 are open
3. Check nginx config is valid: `sudo nginx -t`
4. Check certbot logs: `sudo tail -50 /var/log/letsencrypt/letsencrypt.log`

## Security Checklist

Before exposing to the internet:

- [ ] DNS is configured
- [ ] SSL/TLS certificate installed
- [ ] Strong JWT_SECRET set in .env
- [ ] Firewall configured (only ports 80, 443, 22 open)
- [ ] Rate limiting enabled
- [ ] Database backups configured
- [ ] Monitoring/alerting set up
- [ ] Log rotation configured
- [ ] Server hardening applied

## Current Access Methods

**Local only** (via /etc/hosts):
```bash
curl http://mls.vps-9f95c91c.vps.ovh.us/health
```

**Direct IP** (if firewall allows):
```bash
curl http://51.81.33.144/health
```

**After DNS setup**:
```bash
curl http://mls.vps-9f95c91c.vps.ovh.us/health
```

**After SSL setup**:
```bash
curl https://mls.vps-9f95c91c.vps.ovh.us/health
```

## Summary

1. Server is running and healthy ✓
2. Local access works ✓
3. For internet access: Configure DNS at OVH
4. For secure access: Install SSL with certbot
5. For production: Complete security checklist

---

For questions about DNS setup specific to OVH, refer to:
https://docs.ovh.com/us/en/domains/web_hosting_how_to_edit_my_dns_zone/
