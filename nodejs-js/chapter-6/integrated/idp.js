/**
 * @file idp.js
 * @description
 * Sets up an OpenID Connect (OIDC) Identity Provider using the `oidc-provider` library and Express.js.
 * 
 * Features:
 * - Configures OIDC clients and custom interaction policies.
 * - Integrates custom interaction and account logic from local modules.
 * - Serves the OIDC provider at `/oidc` over HTTPS with custom TLS certificates.
 * - Provides a `/qrcode` endpoint for generating QR codes from query data.
 * - Serves static assets for JS Base64 encoding.
 */
const express = require("express");
const app = express();
const oidc = require("oidc-provider");
const {setupInteractionPolicy, setupInteractions, findAccount} = require('./interaction');
// OIDC Provider configuration
const oidcProvider = new oidc.Provider('https://idp.local:8443/oidc', {
  clients: [
    {
      client_id: '222222',
      client_secret: '22222222',
      client_name: 'Test Client',
      client_uri: 'https://mysrv.local:8444',
      redirect_uris: ['https://mysrv.local:8444/oauth/callback'],
      post_logout_redirect_uris: ['https://mysrv.local:8444/oauth/callback/logout'],
      grant_types: ['implicit', 'authorization_code', 'refresh_token'],
      access_type: 'offline',
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post',
    }
  ],              
  features: {
    devInteractions: {enabled: false},
  },
  findAccount,
  interactions: {
    policy: setupInteractionPolicy(),
  },
  pkce: {
    required: (_ctx, _client) => false,
  },
});

setupInteractions(oidcProvider, app);

// Mount OIDC provider callback at /oidc
app.use("/oidc", oidcProvider.callback());

app.use('/js-base64',express.static('node_modules/js-base64'));

const qrcode = require('qrcode');
app.get('/qrcode', async (req, res) => {
  const { data } = req.query;
  if (!data) {
    return res.status(400).send('Data parameter is required');
  } else {
    res.setHeader('Content-Type', 'image/png'); 
    qrcode.toFileStream(res, data, {width: 180, margin: 1}, (err) => {
      if (err) {
        console.error('Error generating QR code:', err);
        res.status(500).send('Error generating QR code');
      }
    });
  }
});

const path = require('node:path');
const fs = require('node:fs');
const https = require('node:https');
const { Provider } = require("oidc-provider");
// Define path to certificate directory
const certsDirectory = path.join("..", "certs");

// TLS options for HTTPS server
const tlsOptions = {
  key: fs.readFileSync(path.join(certsDirectory, "idp.local.key")),
  passphrase: "password",
  cert: Buffer.concat([
    fs.readFileSync(path.join(certsDirectory, "idp.local.crt")),
    fs.readFileSync(path.join(certsDirectory, "scas.crt"))
  ])
};

// Create and start HTTPS server
const httpsServer = https.createServer(tlsOptions, app);
httpsServer.listen(8443, () => {
  console.log("HTTPS server up and running on port 8443");
});
