const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const base64url = require('base64url');

const app = express();
const PORT = 3000;

app.use(express.static('public'));
app.use(express.json());

const CLIENT_ID = 'demo-client';
const CLIENT_SECRET = 'demo-secret';
const REDIRECT_URI = 'http://localhost:3000/callback';
const AUTH_SERVER_BASE = 'http://localhost:3001';

const sessions = new Map();

function generateRandomString(length = 32) {
  return base64url(crypto.randomBytes(length));
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

function generatePKCE() {
  const codeVerifier = generateRandomString(32);
  const codeChallenge = base64url(sha256(codeVerifier));
  return { codeVerifier, codeChallenge };
}

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth 2.1 Client Demo</title>
      <style>
        body { 
          font-family: Arial, sans-serif; 
          max-width: 800px; 
          margin: 50px auto; 
          padding: 20px; 
          line-height: 1.6;
        }
        .container { 
          border: 1px solid #ddd; 
          padding: 30px; 
          border-radius: 8px; 
          background: #f8f9fa;
        }
        button { 
          background: #007bff; 
          color: white; 
          padding: 12px 24px; 
          border: none; 
          border-radius: 4px; 
          cursor: pointer; 
          font-size: 16px;
          margin: 10px 0;
        }
        button:hover { background: #0056b3; }
        .info { 
          background: white; 
          padding: 20px; 
          border-radius: 4px; 
          margin: 20px 0; 
          border-left: 4px solid #007bff;
        }
        .step { margin: 15px 0; }
        .code { 
          background: #f1f3f4; 
          padding: 2px 6px; 
          border-radius: 3px; 
          font-family: monospace;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>OAuth 2.1 Client Application Demo</h1>
        
        <div class="info">
          <h3>OAuth 2.1 Features Demonstrated:</h3>
          <ul>
            <li><strong>PKCE (Proof Key for Code Exchange):</strong> Required for all OAuth flows</li>
            <li><strong>Authorization Code Flow:</strong> Secure three-legged OAuth flow</li>
            <li><strong>No Implicit Grant:</strong> OAuth 2.1 removes the less secure implicit flow</li>
            <li><strong>State Parameter:</strong> CSRF protection</li>
            <li><strong>Secure Redirect URIs:</strong> Exact match required</li>
          </ul>
        </div>

        <div class="step">
          <h3>Step 1: Start OAuth 2.1 Authorization Flow</h3>
          <p>Click the button below to initiate the OAuth 2.1 authorization flow with PKCE.</p>
          <button onclick="startOAuth()">Start OAuth 2.1 Flow</button>
        </div>

        <div class="step">
          <h3>OAuth 2.1 Flow Steps:</h3>
          <ol>
            <li>Generate PKCE <span class="code">code_verifier</span> and <span class="code">code_challenge</span></li>
            <li>Redirect to authorization server with <span class="code">code_challenge</span></li>
            <li>User authorizes the application</li>
            <li>Authorization server redirects back with <span class="code">authorization_code</span></li>
            <li>Exchange code for access token using <span class="code">code_verifier</span></li>
            <li>Use access token to access protected resources</li>
          </ol>
        </div>

        <div id="result" style="margin-top: 30px;"></div>
      </div>

      <script>
        function startOAuth() {
          fetch('/start-oauth', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
              if (data.authUrl) {
                window.location.href = data.authUrl;
              } else {
                document.getElementById('result').innerHTML = 
                  '<div style="color: red;">Error: ' + JSON.stringify(data) + '</div>';
              }
            })
            .catch(error => {
              document.getElementById('result').innerHTML = 
                '<div style="color: red;">Error: ' + error + '</div>';
            });
        }
      </script>
    </body>
    </html>
  `);
});

app.post('/start-oauth', (req, res) => {
  const state = generateRandomString();
  const { codeVerifier, codeChallenge } = generatePKCE();
  
  sessions.set(state, {
    codeVerifier,
    codeChallenge,
    timestamp: Date.now()
  });

  const authUrl = new URL(`${AUTH_SERVER_BASE}/authorize`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', 'read');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  res.json({ authUrl: authUrl.toString() });
});

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.send(`
      <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
          <h2>Authorization Failed</h2>
          <p>Error: ${error}</p>
          <a href="/">Back to Home</a>
        </body>
      </html>
    `);
  }

  if (!code || !state) {
    return res.status(400).send('Missing code or state parameter');
  }

  const session = sessions.get(state);
  if (!session) {
    return res.status(400).send('Invalid state parameter');
  }

  sessions.delete(state);

  try {
    const tokenResponse = await axios.post(`${AUTH_SERVER_BASE}/token`, {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code_verifier: session.codeVerifier
    });

    const { access_token } = tokenResponse.data;

    const userResponse = await axios.get(`${AUTH_SERVER_BASE}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>OAuth 2.1 Success</title>
        <style>
          body { 
            font-family: Arial, sans-serif; 
            max-width: 800px; 
            margin: 50px auto; 
            padding: 20px; 
            line-height: 1.6;
          }
          .success { 
            border: 1px solid #28a745; 
            padding: 30px; 
            border-radius: 8px; 
            background: #d4edda;
            color: #155724;
          }
          .data { 
            background: white; 
            padding: 20px; 
            border-radius: 4px; 
            margin: 20px 0; 
            border: 1px solid #ddd;
          }
          .token { 
            background: #f8f9fa; 
            padding: 10px; 
            border-radius: 3px; 
            font-family: monospace; 
            word-break: break-all;
            border: 1px solid #e9ecef;
          }
          button { 
            background: #007bff; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            text-decoration: none;
            display: inline-block;
          }
          button:hover { background: #0056b3; }
        </style>
      </head>
      <body>
        <div class="success">
          <h1>✅ OAuth 2.1 Authorization Successful!</h1>
          
          <div class="data">
            <h3>Access Token (JWT):</h3>
            <div class="token">${access_token}</div>
          </div>
          
          <div class="data">
            <h3>User Information:</h3>
            <pre>${JSON.stringify(userResponse.data, null, 2)}</pre>
          </div>
          
          <div class="data">
            <h3>Token Details:</h3>
            <pre>${JSON.stringify(tokenResponse.data, null, 2)}</pre>
          </div>

          <div class="data">
            <h3>OAuth 2.1 Security Features Used:</h3>
            <ul>
              <li><strong>PKCE:</strong> Code verifier and challenge protected the authorization code exchange</li>
              <li><strong>State Parameter:</strong> Protected against CSRF attacks</li>
              <li><strong>Secure Redirect:</strong> Exact redirect URI matching enforced</li>
              <li><strong>Authorization Code Flow:</strong> Most secure OAuth flow (no implicit grant)</li>
              <li><strong>Short-lived Tokens:</strong> Access token expires in 1 hour</li>
            </ul>
          </div>
          
          <a href="/" style="color: white;"><button>Start New Flow</button></a>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('Token exchange error:', error.response?.data || error.message);
    res.status(500).send(`
      <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
          <h2>Token Exchange Failed</h2>
          <p>Error: ${error.response?.data?.error || error.message}</p>
          <p>Description: ${error.response?.data?.error_description || 'Unknown error'}</p>
          <a href="/">Back to Home</a>
        </body>
      </html>
    `);
  }
});

app.listen(PORT, () => {
  console.log(`OAuth 2.1 Client Application running on http://localhost:${PORT}`);
  console.log('Make sure the Authorization Server is running on http://localhost:3001');
});