import express from 'express';
import crypto from 'crypto';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { v4 as uuidv4 } from 'uuid';

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// Configuration from environment
const config = {
  port: process.env.PORT || 3000,
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',

  // Discourse settings
  discourseUrl: process.env.DISCOURSE_URL || 'https://yodev.dev',
  discourseSecret: process.env.DISCOURSE_SSO_SECRET,

  // OIDC client settings (for AFFiNE)
  clientId: process.env.OIDC_CLIENT_ID || 'affine',
  clientSecret: process.env.OIDC_CLIENT_SECRET,
  allowedRedirectUris: (process.env.ALLOWED_REDIRECT_URIS || 'https://affine.yodev.dev/oauth/callback').split(','),
};

// In-memory stores (use Redis in production for multi-instance)
const authorizationCodes = new Map();
const pendingAuths = new Map();

// Generate RSA key pair for signing JWTs
let privateKey, publicKey, jwk;

async function initKeys() {
  const keyPair = await generateKeyPair('RS256');
  privateKey = keyPair.privateKey;
  publicKey = keyPair.publicKey;
  jwk = await exportJWK(publicKey);
  jwk.kid = 'discourse-bridge-key-1';
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  console.log('RSA keys initialized');
}

// Discourse SSO helpers
function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

function signPayload(payload) {
  const base64Payload = Buffer.from(payload).toString('base64');
  const sig = crypto
    .createHmac('sha256', config.discourseSecret)
    .update(base64Payload)
    .digest('hex');
  return { sso: base64Payload, sig };
}

function verifyPayload(sso, sig) {
  const expectedSig = crypto
    .createHmac('sha256', config.discourseSecret)
    .update(sso)
    .digest('hex');

  if (sig !== expectedSig) {
    throw new Error('Invalid signature');
  }

  const payload = Buffer.from(sso, 'base64').toString('utf8');
  return Object.fromEntries(new URLSearchParams(payload));
}

// OIDC Discovery endpoint
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: config.baseUrl,
    authorization_endpoint: `${config.baseUrl}/authorize`,
    token_endpoint: `${config.baseUrl}/token`,
    userinfo_endpoint: `${config.baseUrl}/userinfo`,
    jwks_uri: `${config.baseUrl}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    claims_supported: ['sub', 'name', 'email', 'email_verified', 'picture', 'preferred_username'],
    code_challenge_methods_supported: ['S256', 'plain'],
  });
});

// JWKS endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({
    keys: [jwk],
  });
});

// Authorization endpoint - redirects to Discourse
app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;
  console.log('Authorize request:', JSON.stringify({ client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method }));

  // Validate client
  if (client_id !== config.clientId) {
    return res.status(400).json({ error: 'invalid_client' });
  }

  // Validate redirect URI
  if (!config.allowedRedirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_redirect_uri' });
  }

  // Generate nonce and store pending auth
  const nonce = generateNonce();
  pendingAuths.set(nonce, {
    redirect_uri,
    state,
    scope,
    code_challenge,
    code_challenge_method,
    created: Date.now(),
  });

  // Build Discourse SSO request
  const returnUrl = `${config.baseUrl}/callback`;
  const payload = `nonce=${nonce}&return_sso_url=${encodeURIComponent(returnUrl)}`;
  const { sso, sig } = signPayload(payload);

  // Redirect to Discourse
  const discourseAuthUrl = `${config.discourseUrl}/session/sso_provider?sso=${encodeURIComponent(sso)}&sig=${sig}`;
  res.redirect(discourseAuthUrl);
});

// Callback from Discourse
app.get('/callback', async (req, res) => {
  const { sso, sig } = req.query;

  try {
    // Verify and decode Discourse response
    const userData = verifyPayload(sso, sig);
    console.log('Discourse user data:', JSON.stringify(userData));

    // Get pending auth
    const pending = pendingAuths.get(userData.nonce);
    console.log('Pending auth for nonce:', userData.nonce, pending ? 'found' : 'NOT FOUND');
    if (!pending) {
      return res.status(400).send('Invalid or expired nonce');
    }
    pendingAuths.delete(userData.nonce);

    // Generate authorization code
    const code = uuidv4();
    authorizationCodes.set(code, {
      user: userData,
      redirect_uri: pending.redirect_uri,
      scope: pending.scope,
      code_challenge: pending.code_challenge,
      code_challenge_method: pending.code_challenge_method,
      created: Date.now(),
    });

    // Redirect back to client with code
    const redirectUrl = new URL(pending.redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (pending.state) {
      redirectUrl.searchParams.set('state', pending.state);
    }

    console.log('Redirecting to:', redirectUrl.toString());
    res.redirect(redirectUrl.toString());
  } catch (error) {
    console.error('Callback error:', error);
    res.status(400).send('Authentication failed');
  }
});

// Token endpoint
app.post('/token', async (req, res) => {
  console.log('Token request body:', JSON.stringify(req.body));

  // Handle both form and JSON bodies, and Basic auth
  let clientId, clientSecret, code, grantType, redirectUri;

  // Check for Basic auth header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Basic ')) {
    const base64Credentials = authHeader.slice(6);
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
    [clientId, clientSecret] = credentials.split(':');
  }

  // Body params override
  clientId = req.body.client_id || clientId;
  clientSecret = req.body.client_secret || clientSecret;
  code = req.body.code;
  grantType = req.body.grant_type;
  redirectUri = req.body.redirect_uri;
  const codeVerifier = req.body.code_verifier;

  console.log('Token request parsed:', { clientId, grantType, code: code?.substring(0, 8) + '...', redirectUri, hasCodeVerifier: !!codeVerifier });

  // Validate client credentials
  if (clientId !== config.clientId || clientSecret !== config.clientSecret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  if (grantType !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  // Validate authorization code
  const authCode = authorizationCodes.get(code);
  if (!authCode) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired code' });
  }

  // Verify redirect URI matches
  if (redirectUri && redirectUri !== authCode.redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' });
  }

  // Verify PKCE code_verifier if code_challenge was provided
  if (authCode.code_challenge) {
    if (!codeVerifier) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier required' });
    }

    // Compute the challenge from the verifier
    let computedChallenge;
    if (authCode.code_challenge_method === 'S256') {
      computedChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
    } else {
      // plain method
      computedChallenge = codeVerifier;
    }

    if (computedChallenge !== authCode.code_challenge) {
      console.log('PKCE verification failed:', { expected: authCode.code_challenge, computed: computedChallenge });
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    }
    console.log('PKCE verification successful');
  }

  authorizationCodes.delete(code);

  const user = authCode.user;

  // Generate ID token
  const idToken = await new SignJWT({
    sub: user.external_id || user.username,
    name: user.name || user.username,
    email: user.email,
    email_verified: true,
    preferred_username: user.username,
    picture: user.avatar_url,
  })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
    .setIssuer(config.baseUrl)
    .setAudience(config.clientId)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);

  // Generate access token (simple signed JWT)
  const accessToken = await new SignJWT({
    sub: user.external_id || user.username,
    scope: authCode.scope || 'openid profile email',
  })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
    .setIssuer(config.baseUrl)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken,
    scope: authCode.scope || 'openid profile email',
  });
});

// Userinfo endpoint
app.get('/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  // For simplicity, decode the access token to get user info
  // In production, you'd want to verify the signature
  const token = authHeader.slice(7);
  try {
    const [, payloadBase64] = token.split('.');
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64url').toString());

    res.json({
      sub: payload.sub,
    });
  } catch (error) {
    res.status(401).json({ error: 'invalid_token' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Cleanup expired entries periodically
setInterval(() => {
  const now = Date.now();
  const maxAge = 10 * 60 * 1000; // 10 minutes

  for (const [key, value] of authorizationCodes) {
    if (now - value.created > maxAge) {
      authorizationCodes.delete(key);
    }
  }

  for (const [key, value] of pendingAuths) {
    if (now - value.created > maxAge) {
      pendingAuths.delete(key);
    }
  }
}, 60000);

// Start server
initKeys().then(() => {
  app.listen(config.port, () => {
    console.log(`Discourse OIDC Bridge running on port ${config.port}`);
    console.log(`OIDC Discovery: ${config.baseUrl}/.well-known/openid-configuration`);
  });
});
