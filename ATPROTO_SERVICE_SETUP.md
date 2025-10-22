# AT Protocol MLS Service Setup

## Service Information

Your MLS server is now configured as an AT Protocol service that can be used with PDS service proxying.

### Service Details

- **Service URL**: https://mls.catbird.blue
- **Service DID**: `did:web:mls.catbird.blue`
- **Service Type**: `AtprotoMlsService`
- **Service ID**: `#atproto_mls`

## DID Document

The DID document is served at:
```
https://mls.catbird.blue/.well-known/did.json
```

**Document Contents:**
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "did:web:mls.catbird.blue",
  "verificationMethod": [
    {
      "id": "did:web:mls.catbird.blue#atproto",
      "type": "Multikey",
      "controller": "did:web:mls.catbird.blue",
      "publicKeyMultibase": "zWo9ufkfcQw8iA4yO-6XCwv0XhfGN1AmV01jJ0K5rmpc"
    }
  ],
  "service": [
    {
      "id": "#atproto_mls",
      "type": "AtprotoMlsService",
      "serviceEndpoint": "https://mls.catbird.blue"
    }
  ]
}
```

## Using with PDS Service Proxy

Clients can use the PDS service proxy feature to access your MLS service. The client sends requests to their PDS with the `atproto-proxy` header:

```http
atproto-proxy: did:web:mls.catbird.blue#atproto_mls
```

### Example Request via PDS

```bash
# Client authenticates with their PDS
# PDS proxies the request to your MLS service with inter-service JWT

curl -X POST https://your-pds.example.com/xrpc/blue.catbird.mls.createConvo \
  -H "Authorization: Bearer <user-access-token>" \
  -H "atproto-proxy: did:web:mls.catbird.blue#atproto_mls" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My Secure Chat",
    "members": ["did:plc:user123"]
  }'
```

The PDS will:
1. Verify the user's authentication
2. Resolve `did:web:mls.catbird.blue`
3. Extract the service endpoint from the DID document
4. Create an inter-service JWT signed with the user's key
5. Forward the request to `https://mls.catbird.blue/xrpc/blue.catbird.mls.createConvo`

## Inter-Service Authentication

Your server is configured to accept inter-service JWTs from PDSs. The JWT includes:

- **iss**: User's DID (who the request is on behalf of)
- **aud**: Your service DID (`did:web:mls.catbird.blue`)
- **lxm**: Lexicon method (NSID of the endpoint)
- **exp**: Short expiration (60 seconds recommended)

The server validates the JWT by:
1. Resolving the user's DID
2. Extracting their signing key from their DID document
3. Verifying the JWT signature

## XRPC Endpoints

All MLS endpoints are available under the `/xrpc/blue.catbird.mls.*` namespace:

### Available Endpoints

1. **blue.catbird.mls.createConvo** - Create new MLS group conversation
2. **blue.catbird.mls.addMembers** - Add members to existing conversation
3. **blue.catbird.mls.sendMessage** - Send encrypted message
4. **blue.catbird.mls.getMessages** - Retrieve conversation messages
5. **blue.catbird.mls.publishKeyPackage** - Upload MLS key package
6. **blue.catbird.mls.getKeyPackages** - Fetch key packages for users
7. **blue.catbird.mls.leaveConvo** - Leave a conversation
8. **blue.catbird.mls.uploadBlob** - Upload encrypted attachments

## Direct Access (Without Proxy)

You can also access the service directly:

```bash
# Direct access with JWT
curl -X POST https://mls.catbird.blue/xrpc/blue.catbird.mls.createConvo \
  -H "Authorization: Bearer <inter-service-jwt>" \
  -H "Content-Type: application/json" \
  -d '{...}'
```

## Testing

### Test Health Endpoint
```bash
curl https://mls.catbird.blue/health
```

### Test DID Resolution
```bash
curl https://mls.catbird.blue/.well-known/did.json
```

### Test XRPC Endpoint (requires auth)
```bash
curl -X POST https://mls.catbird.blue/xrpc/blue.catbird.mls.createConvo \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Test","members":["did:web:mls.catbird.blue"]}'
```

## DNS Setup

To make this accessible from the internet, add an A record:

```
Type: A
Name: mls
Domain: catbird.blue
Value: 51.81.33.144
TTL: 300
```

## SSL/TLS Setup

Install Let's Encrypt certificate:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d mls.catbird.blue
```

After SSL is installed:
1. Update DID document service endpoint to use `https://`
2. Test that the DID document is accessible via HTTPS
3. Restart the server

## Configuration Files

### Nginx Config
- **Location**: `/etc/nginx/sites-available/mls.catbird.blue`
- **Features**:
  - Serves DID document at `/.well-known/did.json`
  - Proxies all `/xrpc/*` requests to backend
  - Health check endpoints
  - CORS headers for DID document

### Server Config
- **Location**: `/home/ubuntu/mls/server/.env`
- **Key Settings**:
  - `SERVICE_DID=did:web:mls.catbird.blue`
  - `SERVER_PORT=3000`
  - `DATABASE_URL` for PostgreSQL
  - `REDIS_URL` for caching

## Security Considerations

### For Service Proxy Mode

1. **JWT Validation**: Server must validate:
   - Signature matches user's DID signing key
   - `aud` field matches your service DID
   - `exp` hasn't expired
   - `lxm` matches the requested endpoint (if present)

2. **Rate Limiting**: Implement per-user rate limits based on JWT `iss` field

3. **Authorization**: Check if the user has permission for the requested action

### For Direct Access

1. **Strong JWT Secret**: Change default secret in production
2. **HTTPS Only**: Enforce TLS for all connections
3. **DID Verification**: Validate user DIDs exist and are active

## Monitoring

View server logs:
```bash
tail -f /home/ubuntu/mls/server.log
```

View nginx logs:
```bash
tail -f /var/log/nginx/mls.catbird.blue.access.log
tail -f /var/log/nginx/mls.catbird.blue.error.log
```

Check metrics:
```bash
curl https://mls.catbird.blue/metrics
```

## Integration Example

Here's how a client app would use this service through their PDS:

```typescript
// Client code
const client = new AtprotoClient({
  service: 'https://user-pds.example.com'
});

// Authenticate with PDS
await client.login({
  identifier: 'user.handle',
  password: 'user-password'
});

// Create MLS conversation via service proxy
const response = await client.api.com.atproto.repo.call({
  headers: {
    'atproto-proxy': 'did:web:mls.catbird.blue#atproto_mls'
  },
  nsid: 'blue.catbird.mls.createConvo',
  data: {
    title: 'Secure Team Chat',
    members: ['did:plc:member1', 'did:plc:member2']
  }
});
```

## Troubleshooting

### PDS Can't Resolve Service DID

**Check:**
1. DNS is configured correctly
2. DID document is accessible via HTTPS
3. DID document JSON is valid
4. Service entry exists in DID document

### JWT Verification Fails

**Check:**
1. User's DID resolves correctly
2. User's DID document has signing key
3. JWT signature algorithm matches key type
4. JWT hasn't expired

### CORS Issues

**Check:**
1. CORS headers are set for DID document endpoint
2. Nginx configuration includes CORS headers
3. Browser preflight requests are handled

## Resources

- **AT Protocol Specs**: https://atproto.com/specs/xrpc
- **DID Web Method**: https://w3c-ccg.github.io/did-method-web/
- **JWT RFC**: https://datatracker.ietf.org/doc/html/rfc7519
- **MLS RFC 9420**: https://datatracker.ietf.org/doc/rfc9420/

---

**Service Status**: ✅ CONFIGURED  
**DID**: `did:web:mls.catbird.blue`  
**Endpoint**: https://mls.catbird.blue

Your MLS service is now ready to accept proxied requests from AT Protocol PDSs!
