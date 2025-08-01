/**
 * Express HTTPS server with basic authentication and optional client certificate authentication.
 *
 * Endpoints:
 * 
 * @endpoint GET /hello
 * @description Responds with "Hello, World!" for testing server availability.
 *
 * @endpoint GET /basicauth
 * @description Implements HTTP Basic Authentication. Requires 'Authorization' header with credentials.
 *              - If credentials are missing or invalid, responds with 401 and 'WWW-Authenticate' header.
 *              - If credentials are valid (user: 'jdoe', pass: 'password'), responds with success message.
 *
 * HTTPS Configuration:
 * - Loads server key and certificate from local files.
 * - Optionally enforces client certificate authentication if CLIENT_AUTH is true.
 * - Listens on port 8443.
 */
const express = require("express");
const https = require("node:https");
const app = express();

app.get('/hello', (req, res) => {
  res.send('Hello, World!');
});

app.get('/basicauth', (req, res) => {
  const authheader = req.headers.authorization;
  console.log(req.headers);
  if (!authheader) {
    res
      .setHeader('WWW-Authenticate', 'Basic')
      .status(401)
      .send("User not authenticated");
    return;
  }

  const auth = new Buffer.from(authheader.split(' ')[1],'base64').toString().split(':');
  const user = auth[0];
  const pass = auth[1];

  if (user == 'jdoe' && pass == 'password') {
    res.send(`User ${user} authenticated successfully`);
  } else {
    res
      .setHeader('WWW-Authenticate', 'Basic')
      .status(401)
      .send("User not authenticated");
  }
});

const path = require("path");
const scertpath = path.join("certs", "server");
const fs = require("fs");

const CLIENT_AUTH = true;

var options = {
  key:  fs.readFileSync(path.join(scertpath, "mysrv.local.key")),
  passphrase: "password",
  cert: Buffer.concat([
    fs.readFileSync(path.join(scertpath, "mysrv.local.crt")),
    fs.readFileSync(path.join(scertpath, "sint.crt"))
  ])
};

if (CLIENT_AUTH) {
  options["ca"] = fs.readFileSync(path.join(scertpath, "croots.crt"));
  options["requestCert"] = true;
  options["rejectUnauthorized"] = true;
}

const httpsServer = https.createServer(options, app);

httpsServer.listen(8443, () => {
  console.log("HTTPS server up and running on port 8443")
});