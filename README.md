# Discourse OIDC Bridge

Middleware that bridges Discourse SSO (DiscourseConnect) to standard OpenID Connect (OIDC), allowing external applications like AFFiNE to authenticate users against a Discourse instance.

## Overview

This service acts as an OIDC Identity Provider (IdP) that uses Discourse as its authentication backend. It implements the OAuth 2.0 Authorization Code flow with PKCE support.

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│   Client    │      │  OIDC Bridge     │      │  Discourse  │
│  (AFFiNE)   │      │  (this service)  │      │   Server    │
└──────┬──────┘      └────────┬─────────┘      └──────┬──────┘
       │                      │                       │
       │  1. /authorize       │                       │
       │─────────────────────>│                       │
       │                      │                       │
       │                      │  2. SSO Request       │
       │                      │──────────────────────>│
       │                      │                       │
       │                      │                       │  3. User logs in
       │                      │                       │  (if not already)
       │                      │                       │
       │                      │  4. SSO Response      │
       │                      │<──────────────────────│
       │                      │                       │
       │  5. Redirect w/code  │                       │
       │<─────────────────────│                       │
       │                      │                       │
       │  6. POST /token      │                       │
       │─────────────────────>│                       │
       │                      │                       │
       │  7. ID + Access Token│                       │
       │<─────────────────────│                       │
       │                      │                       │
       │  8. GET /userinfo    │                       │
       │─────────────────────>│                       │
       │                      │                       │
       │  9. User profile     │                       │
       │<─────────────────────│                       │
```

## Features

- **Standard OIDC Compliance**: Discovery endpoint, JWKS, authorization code flow
- **PKCE Support**: S256 and plain code challenge methods
- **RS256 JWT Signing**: Secure token signing with auto-generated keys
- **User Info Mapping**: Maps Discourse user attributes to OIDC claims
- **Multiple Auth Methods**: Supports both Basic auth and POST body credentials

## Quick Start

### 1. Deploy the Service

**Using Docker:**
```bash
docker build -t discourse-oidc-bridge .
docker run -p 3000:3000 \
  -e BASE_URL=https://auth.example.com \
  -e DISCOURSE_URL=https://discourse.example.com \
  -e DISCOURSE_SSO_SECRET=your-discourse-secret \
  -e OIDC_CLIENT_ID=myapp \
  -e OIDC_CLIENT_SECRET=your-client-secret \
  -e ALLOWED_REDIRECT_URIS=https://myapp.example.com/callback \
  discourse-oidc-bridge
```

**Using Node.js:**
```bash
npm install
PORT=3000 BASE_URL=https://auth.example.com ... npm start
```

### 2. Configure Discourse

See [Discourse Setup](#discourse-setup) section below.

### 3. Configure Your Client App

See [Client Configuration](#client-configuration) section below.

## Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PORT` | No | Server port (default: 3000) | `3000` |
| `BASE_URL` | Yes | Public URL of this service | `https://auth.yodev.dev` |
| `DISCOURSE_URL` | Yes | Your Discourse instance URL | `https://community.yodev.dev` |
| `DISCOURSE_SSO_SECRET` | Yes | Discourse SSO secret (from admin settings) | `64-char-hex-string` |
| `OIDC_CLIENT_ID` | No | Client ID for OIDC apps (default: affine) | `affine` |
| `OIDC_CLIENT_SECRET` | Yes | Client secret for OIDC apps | `generate-a-strong-secret` |
| `ALLOWED_REDIRECT_URIS` | Yes | Comma-separated allowed redirect URIs | `https://app.example.com/oauth/callback` |

### Generating Secrets

**Generate a secure OIDC client secret:**
```bash
openssl rand -hex 32
```

**The Discourse SSO secret** should match what's configured in Discourse admin.

## Discourse Setup

### Step 1: Enable DiscourseConnect Provider

1. Go to Discourse Admin → Settings → Login
2. Search for `discourse connect`
3. Enable: `enable_discourse_connect_provider` = true

### Step 2: Configure Provider Secrets

1. Find: `discourse_connect_provider_secrets`
2. Add your OIDC bridge domain and secret:
   ```
   auth.yodev.dev|your-64-character-discourse-sso-secret-here
   ```

   Format: `domain|secret` (one per line for multiple clients)

### Step 3: Verify SSO Settings

Ensure these settings are configured:
- `discourse_connect_provider_secrets` - Contains your bridge domain
- `enable_discourse_connect_provider` - Enabled

**Note:** The secret here must match `DISCOURSE_SSO_SECRET` in the bridge environment variables.

## Client Configuration

### AFFiNE Setup

In AFFiNE Admin Panel → Settings → OAuth:

**Environment variables (Railway):**
```
OAUTH_OIDC_ENABLED=true
OAUTH_OIDC_ISSUER=https://auth.yodev.dev/
OAUTH_OIDC_CLIENT_ID=affine
OAUTH_OIDC_CLIENT_SECRET=your-oidc-client-secret
```

**Or via Admin UI config:**
```json
{
  "clientId": "affine",
  "clientSecret": "your-oidc-client-secret",
  "issuer": "https://auth.yodev.dev/",
  "args": {
    "scope": "openid profile email"
  }
}
```

### Generic OIDC Client Setup

For any OIDC-compatible application:

| Setting | Value |
|---------|-------|
| Issuer / Authority | `https://your-bridge-domain/` |
| Authorization URL | `https://your-bridge-domain/authorize` |
| Token URL | `https://your-bridge-domain/token` |
| Userinfo URL | `https://your-bridge-domain/userinfo` |
| JWKS URL | `https://your-bridge-domain/.well-known/jwks.json` |
| Scopes | `openid profile email` |
| Response Type | `code` |

## OIDC Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery document |
| `/.well-known/jwks.json` | GET | JSON Web Key Set for token verification |
| `/authorize` | GET | Authorization endpoint (redirects to Discourse) |
| `/callback` | GET | Callback from Discourse (internal) |
| `/token` | POST | Token exchange endpoint |
| `/userinfo` | GET | User information endpoint |
| `/health` | GET | Health check |

## User Claims Mapping

| Discourse Field | OIDC Claim | Description |
|-----------------|------------|-------------|
| `external_id` or `username` | `sub` | Unique user identifier |
| `name` or `username` | `name` | Display name |
| `email` | `email` | Email address |
| (always true) | `email_verified` | Email verification status |
| `username` | `preferred_username` | Username |
| `avatar_url` | `picture` | Profile picture URL |

## Architecture Details

### Token Generation

- **ID Token**: RS256-signed JWT containing user identity claims
- **Access Token**: RS256-signed JWT with user info for the userinfo endpoint
- **Key Rotation**: Keys are generated on startup (see Limitations)

### Security Features

- PKCE support (S256 and plain methods)
- HMAC-SHA256 signature verification for Discourse SSO
- Configurable redirect URI whitelist
- Short-lived authorization codes (10 minute expiry)

### Request Flow

1. **Client initiates auth**: `GET /authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid`
2. **Bridge stores pending auth** and generates Discourse SSO request
3. **User redirected to Discourse** for authentication
4. **Discourse authenticates user** and returns SSO response
5. **Bridge validates SSO signature** and generates authorization code
6. **Client exchanges code for tokens**: `POST /token`
7. **Bridge returns ID token and access token**
8. **Client can fetch user info**: `GET /userinfo` with Bearer token

## Limitations & Considerations

### In-Memory Storage

Authorization codes and pending auth states are stored in-memory. This means:

- **Single instance only**: Cannot run multiple replicas without shared state
- **Restart clears state**: Active auth flows will fail if service restarts
- **Not production-ideal**: For high availability, implement Redis storage

**To add Redis support**, modify the `authorizationCodes` and `pendingAuths` Maps to use Redis.

### Key Rotation

RSA keys are generated on each startup:

- Tokens issued before restart cannot be verified after restart
- For production, consider persisting keys or implementing proper rotation

### No Refresh Tokens

Current implementation does not support refresh tokens. Sessions expire after 1 hour.

## Troubleshooting

### "Invalid or expired nonce"

**Cause**: The nonce returned from Discourse doesn't match any pending auth.

**Solutions**:
1. User took too long to authenticate (>10 min timeout)
2. Service restarted during auth flow
3. Multiple auth attempts interfering

### "Invalid signature" from Discourse callback

**Cause**: `DISCOURSE_SSO_SECRET` doesn't match Discourse config.

**Solutions**:
1. Verify secret in Discourse admin matches environment variable
2. Check for extra whitespace in secret
3. Ensure domain in `discourse_connect_provider_secrets` matches exactly

### "invalid_client" on token request

**Cause**: Client ID or secret mismatch.

**Solutions**:
1. Verify `OIDC_CLIENT_ID` matches what client sends
2. Verify `OIDC_CLIENT_SECRET` matches client configuration
3. Check client is sending credentials correctly (Basic auth or POST body)

### "invalid_redirect_uri"

**Cause**: Redirect URI not in allowed list.

**Solutions**:
1. Add the exact URI to `ALLOWED_REDIRECT_URIS`
2. Check for trailing slashes - must match exactly
3. Ensure protocol (http/https) matches

### Debug Logging

The service logs all requests and key events. Check logs for:
- `Authorize request:` - Shows incoming auth parameters
- `Discourse user data:` - Shows data received from Discourse
- `Pending auth for nonce:` - Shows if nonce lookup succeeded
- `Token request parsed:` - Shows token exchange parameters
- `PKCE verification` - Shows PKCE challenge results

## Development

### Local Development

```bash
# Install dependencies
npm install

# Run with watch mode
npm run dev

# Or run directly
npm start
```

### Testing the Flow

1. Start the service locally
2. Visit: `http://localhost:3000/.well-known/openid-configuration`
3. Verify discovery document is returned
4. Test authorize endpoint with your client

### Environment for Local Testing

```bash
export PORT=3000
export BASE_URL=http://localhost:3000
export DISCOURSE_URL=https://your-discourse.com
export DISCOURSE_SSO_SECRET=your-secret
export OIDC_CLIENT_ID=testclient
export OIDC_CLIENT_SECRET=testsecret
export ALLOWED_REDIRECT_URIS=http://localhost:8080/callback
npm start
```

## Deployment

### Railway

1. Connect GitHub repo to Railway
2. Set environment variables in Railway dashboard
3. Deploy - Railway will auto-detect Dockerfile

### Docker

```bash
docker build -t discourse-oidc-bridge .
docker run -d \
  --name oidc-bridge \
  -p 3000:3000 \
  --env-file .env \
  discourse-oidc-bridge
```

## Related Documentation

- [OpenID Connect Core Spec](https://openid.net/specs/openid-connect-core-1_0.html)
- [Discourse DiscourseConnect Provider](https://meta.discourse.org/t/discourseconnect-official-single-sign-on-for-discourse-sso/13045)
- [OAuth 2.0 PKCE](https://datatracker.ietf.org/doc/html/rfc7636)

## License

MIT
