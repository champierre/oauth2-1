const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const base64url = require('base64url');

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const clients = new Map();
clients.set('demo-client', {
  client_id: 'demo-client',
  client_secret: 'demo-secret',
  redirect_uris: ['http://localhost:3000/callback'],
  client_name: 'Demo OAuth Client'
});

const authorizationCodes = new Map();
const accessTokens = new Map();

function generateRandomString(length = 32) {
  return base64url(crypto.randomBytes(length));
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

app.get('/authorize', (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method
  } = req.query;

  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }

  const client = clients.get(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client' });
  }

  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_redirect_uri' });
  }

  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).json({ 
      error: 'invalid_request',
      error_description: 'PKCE is required with S256 method' 
    });
  }

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth 2.1 Authorization</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .auth-form { border: 1px solid #ddd; padding: 20px; border-radius: 8px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
      </style>
    </head>
    <body>
      <div class="auth-form">
        <h2>OAuth 2.1 Authorization Request</h2>
        <div class="info">
          <p><strong>Client:</strong> ${client.client_name}</p>
          <p><strong>Scope:</strong> ${scope || 'read'}</p>
          <p><strong>PKCE Challenge:</strong> ${code_challenge.substring(0, 20)}...</p>
        </div>
        <p>Do you authorize this application to access your data?</p>
        <form method="post" action="/authorize/approve">
          <input type="hidden" name="client_id" value="${client_id}">
          <input type="hidden" name="redirect_uri" value="${redirect_uri}">
          <input type="hidden" name="state" value="${state || ''}">
          <input type="hidden" name="scope" value="${scope || 'read'}">
          <input type="hidden" name="code_challenge" value="${code_challenge}">
          <input type="hidden" name="code_challenge_method" value="${code_challenge_method}">
          <button type="submit" name="decision" value="approve">Approve</button>
          <button type="submit" name="decision" value="deny" style="background: #dc3545; margin-left: 10px;">Deny</button>
        </form>
      </div>
    </body>
    </html>
  `);
});

app.post('/authorize/approve', (req, res) => {
  const {
    client_id,
    redirect_uri,
    state,
    scope,
    code_challenge,
    code_challenge_method,
    decision
  } = req.body;

  if (decision !== 'approve') {
    const params = new URLSearchParams({
      error: 'access_denied',
      ...(state && { state })
    });
    return res.redirect(`${redirect_uri}?${params}`);
  }

  const authCode = generateRandomString();
  
  authorizationCodes.set(authCode, {
    client_id,
    redirect_uri,
    scope: scope || 'read',
    code_challenge,
    code_challenge_method,
    expires_at: Date.now() + 10 * 60 * 1000,
    used: false
  });

  const params = new URLSearchParams({
    code: authCode,
    ...(state && { state })
  });

  res.redirect(`${redirect_uri}?${params}`);
});

app.post('/token', (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    client_secret,
    code_verifier
  } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const client = clients.get(client_id);
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  const authCodeData = authorizationCodes.get(code);
  if (!authCodeData) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (authCodeData.used) {
    authorizationCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (Date.now() > authCodeData.expires_at) {
    authorizationCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (authCodeData.client_id !== client_id || authCodeData.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (!code_verifier) {
    return res.status(400).json({ 
      error: 'invalid_request',
      error_description: 'code_verifier is required' 
    });
  }

  const challengeFromVerifier = base64url(sha256(code_verifier));
  if (challengeFromVerifier !== authCodeData.code_challenge) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  authCodeData.used = true;

  const accessToken = generateRandomString();
  accessTokens.set(accessToken, {
    client_id,
    scope: authCodeData.scope,
    expires_at: Date.now() + 60 * 60 * 1000
  });

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: authCodeData.scope
  });
});

app.get('/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const token = authHeader.substring(7);
  const tokenData = accessTokens.get(token);
  
  if (!tokenData) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  if (Date.now() > tokenData.expires_at) {
    accessTokens.delete(token);
    return res.status(401).json({ error: 'invalid_token' });
  }

  res.json({
    sub: '1234567890',
    name: 'Demo User',
    email: 'demo@example.com',
    scope: tokenData.scope
  });
});

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: `http://localhost:${PORT}`,
    authorization_endpoint: `http://localhost:${PORT}/authorize`,
    token_endpoint: `http://localhost:${PORT}/token`,
    userinfo_endpoint: `http://localhost:${PORT}/userinfo`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['read', 'write'],
    token_endpoint_auth_methods_supported: ['client_secret_post']
  });
});

app.listen(PORT, () => {
  console.log(`OAuth 2.1 Authorization Server running on http://localhost:${PORT}`);
  console.log(`Discovery endpoint: http://localhost:${PORT}/.well-known/oauth-authorization-server`);
});