# Discourse OIDC Bridge

Middleware that bridges Discourse SSO (DiscourseConnect) to standard OIDC, allowing external apps like AFFiNE to authenticate against Discourse.

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `BASE_URL` | Public URL of this service | `https://auth.yodev.dev` |
| `DISCOURSE_URL` | Your Discourse instance URL | `https://yodev.dev` |
| `DISCOURSE_SSO_SECRET` | Discourse SSO secret (from admin settings) | `your-secret-here` |
| `OIDC_CLIENT_ID` | Client ID for OIDC apps | `affine` |
| `OIDC_CLIENT_SECRET` | Client secret for OIDC apps | `generate-a-strong-secret` |
| `ALLOWED_REDIRECT_URIS` | Comma-separated allowed redirect URIs | `https://affine.yodev.dev/oauth/callback` |

## Discourse Setup

1. Go to Discourse Admin → Settings → Login
2. Enable `enable_discourse_connect_provider`
3. Set `discourse_connect_provider_secrets` to include your client domain and secret:
   ```
   auth.yodev.dev|your-discourse-sso-secret
   ```

## AFFiNE Setup

In AFFiNE Admin → Settings → OAuth, configure OIDC:

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

## Endpoints

- `/.well-known/openid-configuration` - OIDC Discovery
- `/.well-known/jwks.json` - JSON Web Key Set
- `/authorize` - Authorization endpoint
- `/token` - Token endpoint
- `/userinfo` - User info endpoint
- `/health` - Health check
