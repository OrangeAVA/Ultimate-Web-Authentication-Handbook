/**
 * @file resource.js
 * @description
 * This file sets up an HTTPS Express server that listens on port 8444.
 * It serves as a resource endpoint for PKCE (Proof Key for Code Exchange) flows,
 * typically used in OAuth 2.0 authentication scenarios.
 * 
 * TLS options are configured using server and intermediate certificates.
 * 
 * @endpoint GET /
 * @description
 *   Handles GET requests to the root path.
 *   - If the `code` query parameter is present, responds with an HTML page displaying the code.
 *   - If the `code` query parameter is missing, responds with a 400 error and an error message.
 * 
 * @example
 *   GET https://localhost:8444/?code=AUTH_CODE
 *   Response: HTML page showing the code.
 * 
 *   GET https://localhost:8444/
 *   Response: 400 error with "Missing code parameter".
 */
const express = require("express");
const https = require("node:https");
const app = express();

app.get("/", (req, res) => {
  if (req.query?.code) {
    res.send(`
      <h1>Code</h1>
      <p>${req.query.code}</p>
    `);
  } else {
    res.status(400).send(`
      <h1>Error</h1>
      <p>Missing code parameter</p>
    `);   
  }
});

const path = require("path");
const scertpath = path.join("..", "certs");
const fs = require("fs");

var tlsopts = {
  key:  fs.readFileSync(path.join(scertpath, "mysrv.local.key")),
  passphrase: "password",
  cert: Buffer.concat([
    fs.readFileSync(path.join(scertpath, "mysrv.local.crt")),
    fs.readFileSync(path.join(scertpath, "sint.crt"))
  ])
};

const httpsServer = https.createServer(tlsopts, app);
httpsServer.listen(8444, () => {
  console.log("HTTPS server up and running on port 8444")
});
