#!/usr/bin/env python3
"""Generate test JWT tokens for API testing"""

import json
import hmac
import hashlib
import base64
import time
import secrets
from datetime import datetime, timedelta
import os
import sys

def base64url_encode(data):
    """Base64url encode without padding"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def generate_token(jwt_secret, service_did, issuer_did, hours, lxm=None):
    """Generate a JWT token"""
    now = int(time.time())
    exp = now + (hours * 3600)
    jti = secrets.token_hex(16)
    
    # Create claims
    claims = {
        "iss": issuer_did,
        "aud": service_did,
        "exp": exp,
        "iat": now,
        "sub": issuer_did,
        "jti": jti
    }
    
    if lxm:
        claims["lxm"] = lxm
    
    # Create header
    header = {"alg": "HS256", "typ": "JWT"}
    
    # Encode header and claims
    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')))
    payload_b64 = base64url_encode(json.dumps(claims, separators=(',', ':')))
    
    # Create signature
    message = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = hmac.new(
        jwt_secret.encode('utf-8'),
        message,
        hashlib.sha256
    ).digest()
    signature_b64 = base64url_encode(signature)
    
    # Combine parts
    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    return token, exp

def main():
    # Load environment variables
    jwt_secret = os.getenv('JWT_SECRET', 'dev-secret-key-change-in-production')
    service_did = os.getenv('SERVICE_DID', 'did:web:catbird.social')
    issuer_did = os.getenv('ISSUER_DID', 'did:plc:test123')
    
    print("🔐 Generating Test JWT Tokens")
    print("=" * 50)
    print()
    print("Configuration:")
    print(f"  JWT_SECRET: {jwt_secret[:10]}...")
    print(f"  SERVICE_DID: {service_did}")
    print(f"  ISSUER_DID: {issuer_did}")
    print()
    
    # Generate tokens with different expiration times
    tokens = [
        (1, "Short-lived token (1 hour)", "blue.mls.createGroup"),
        (24, "Medium-lived token (24 hours)", "blue.mls.sendMessage"),
        (168, "Long-lived token (1 week)", None),
        (720, "Extended token (30 days)", None),
    ]
    
    for hours, description, lxm in tokens:
        token, exp = generate_token(jwt_secret, service_did, issuer_did, hours, lxm)
        exp_date = datetime.fromtimestamp(exp)
        
        print(f"✓ {description}")
        print(f"  Expires: {exp_date}")
        print(f"  Token: {token}")
        print()
        
        # Save to file
        filename = f"test_token_{hours}h.txt"
        with open(filename, 'w') as f:
            f.write(token)
        print(f"  Saved to: {filename}")
        print()
    
    print("✅ Test tokens generated successfully!")
    print()
    print("Usage example:")
    print('  curl -H "Authorization: Bearer $(cat test_token_24h.txt)" \\')
    print('    http://localhost:3000/xrpc/blue.mls.listGroups')

if __name__ == '__main__':
    main()
