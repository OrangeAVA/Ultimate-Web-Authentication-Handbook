/**
 * @file idp.js
 * @description
 * This file sets up an OpenID Connect (OIDC) Identity Provider (IDP) using the `oidc-provider` library,
 * served over HTTPS with Express. It configures OIDC clients, token lifetimes, and custom refresh token logic.
 * The server uses TLS certificates for secure communication.
 *
 * @endpoint
 *   - /oidc
 *     - Mounts the OIDC provider callback, handling all OIDC protocol endpoints (e.g., /authorize, /token, /userinfo).
 *
 * @usage
 *   - Start the HTTPS server on port 8443.
 *   - Serves OIDC authentication and token endpoints at https://idp.local:8443/oidc.
 *
 * @see
 *   - https://github.com/panva/node-oidc-provider
 *   - OIDC specification: https://openid.net/specs/openid-connect-core-1_0.html
 */
// Import required modules
const express = require("express");
const https = require("node:https");
const path = require("path");
const fs = require("fs");
const oidc = require("oidc-provider");

// Initialize Express application
const app = express();

// OIDC Provider configuration
const oidcProvider = new oidc.Provider('https://idp.local:8443/oidc', {
  clients: [
    {
      client_id: '222222',
      client_secret: '22222222',
      redirect_uris: ['https://mysrv.local:8444/'],
      grant_types: ['implicit', 'authorization_code', 'refresh_token'],
      access_type: 'offline',
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }
  ],
  ttl: {
    AccessToken: 30,   // Access token time-to-live in seconds
    RefreshToken: 60   // Refresh token time-to-live in seconds
  },
  // Custom logic to determine if a refresh token should be issued
  async issueRefreshToken(ctx, client, code) {
    if (!client.grantTypeAllowed('refresh_token')) {
      return false;
    }
    return code.scopes.has('offline_access') ||
      (client.applicationType === 'web' && client.clientAuthMethod === 'none');
  },
});

// Mount OIDC provider callback at /oidc
app.use("/oidc", oidcProvider.callback());

// Define path to certificate directory
const certsDirectory = path.join("..", "certs");

// TLS options for HTTPS server
const tlsOptions = {
  key: fs.readFileSync(path.join(certsDirectory, "idp.local.key")),
  passphrase: "password",
  cert: Buffer.concat([
    fs.readFileSync(path.join(certsDirectory, "idp.local.crt")),
    fs.readFileSync(path.join(certsDirectory, "sint.crt"))
  ])
};

// Create and start HTTPS server
const httpsServer = https.createServer(tlsOptions, app);
httpsServer.listen(8443, () => {
  console.log("HTTPS server up and running on port 8443");
});
