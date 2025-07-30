/**
 * @file idp.js
 * @description
 * This file sets up an OpenID Connect (OIDC) Identity Provider (IDP) using the `oidc-provider` library and Express.js.
 * It configures OIDC clients, custom interaction policies, and account finding logic.
 * The OIDC provider is mounted at `/oidc` and supports secure HTTPS connections using custom TLS certificates.
 * Additionally, it exposes a `/qrcode` endpoint to generate QR codes from provided data.
 *
 * Key Features:
 * - OIDC Provider configuration with custom client and interaction settings.
 * - HTTPS server setup with TLS certificates for secure communication.
 * - QR code generation endpoint for auxiliary authentication flows.
 * - Integration with custom interaction and account logic via imported modules.
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
