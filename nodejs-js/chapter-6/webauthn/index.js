/**
 * @fileoverview WebAuthn server implementation using Express and fido2-lib.
 * This file provides endpoints for WebAuthn registration and authentication flows,
 * serving static frontend assets, and running an HTTPS server.
 *
 * Endpoints:
 * 
 * @endpoint GET /hello
 *   @description Simple test endpoint. Returns "Hello, World!".
 *   @returns {string} "Hello, World!"
 *
 * @endpoint POST /webauthn/register/begin
 *   @description Initiates WebAuthn registration for a user.
 *   @query {string} username - The username to register.
 *   @query {string} state - A unique state identifier for the registration session.
 *   @returns {object} PublicKeyCredentialCreationOptions for the client.
 *
 * @endpoint POST /webauthn/register/finish
 *   @description Completes WebAuthn registration by verifying attestation response.
 *   @query {string} username - The username being registered.
 *   @query {string} state - The state identifier for the registration session.
 *   @body {object} attestation response from client.
 *   @returns {object} Success or error message.
 *
 * @endpoint POST /webauthn/login/begin
 *   @description Initiates WebAuthn authentication for a user.
 *   @query {string} username - The username to authenticate.
 *   @query {string} state - A unique state identifier for the authentication session.
 *   @returns {object} PublicKeyCredentialRequestOptions for the client.
 *
 * @endpoint POST /webauthn/login/finish
 *   @description Completes WebAuthn authentication by verifying assertion response.
 *   @query {string} username - The username being authenticated.
 *   @query {string} state - The state identifier for the authentication session.
 *   @body {object} assertion response from client.
 *   @returns {object} Success or error message.
 *
 * Static Assets:
 *   Serves frontend files from 'frontend' directory.
 *   Serves js-base64 library from 'node_modules/js-base64'.
 *
 * HTTPS Server:
 *   Runs on port 8443 with TLS certificates.
 */
const express = require("express");
const https = require("node:https");
const app = express();
const fido = require("fido2-lib");

app.use(express.json());
app.use(express.static('frontend'));
app.use('/js-base64',express.static('node_modules/js-base64'));

app.get('/hello', (req, res) => {
  res.send('Hello, World!');
});

const fido2lib = new fido.Fido2Lib({
    rpId: "mysrv.local",
    rpName: "MySrv"
});

const states = {};
const users = {};

const {Base64} = require('js-base64');

app.post('/webauthn/register/begin', (req, res) => {
  if (!(req.query && req.query.username && req.query.state)) {
    console.error("No username or state.")
    res.status(400).json({"error": "No username or state."});
    return;
  }
  const state = req.query.state;
  fido2lib.attestationOptions()
    .then(pkcc => {
      pkcc.user.id = req.query.username;
      pkcc.user.name = req.query.username;
      pkcc.user.displayName = req.query.username;
      pkcc.challenge = Base64.fromUint8Array(new Uint8Array(pkcc.challenge), true);
      states[state] = {
        "user" : req.query.username,
        "challenge": pkcc.challenge,
        "type": "attest"
      };
      res.status(200).json(pkcc);
    })
    .catch(e => {
      res.status(500).json({"error": "Unable to create public key creation options."});
    });
});

app.post('/webauthn/register/finish', (req, res) => {
  console.log("States data: ", states);
  if (!(req.query && req.query.username && req.query.state)) {
    res.status(400).json({"error": "No username or state."});
    return;
  }
  const state = req.query.state;
  if (!state in states || 
      states[state].user != req.query.username || 
      states[state].type != "attest"){
    res.status(400).json({"error": "Invalid request."});
    return;
  }

  attresp = {
    id: Base64.toUint8Array(req.body.id).buffer,
    rawId: Base64.toUint8Array(req.body.rawId).buffer,
    response: {
      attestationObject: req.body.response.attestationObject,
      clientDataJSON: req.body.response.clientDataJSON
    }
  }

  const challenge = states[state].challenge;
  delete states[state];
  fido2lib.attestationResult(attresp, {
    challenge,
    origin: "https://mysrv.local:8443",
    factor: "either"
  })
    .then(r => {
      if (r.audit.validExpectations && r.audit.validRequest && r.audit.complete){
        console.log(r.authnrData);
        credId = Base64.fromUint8Array(new Uint8Array(r.authnrData.get('credId')));
        users[req.query.username] = {
          "counter": r.authnrData.get('counter'),
          "credentialPublicKeyPem": r.authnrData.get('credentialPublicKeyPem'),
          credId
        }
        res.status(200).json({"success": "Credential was registered successfully."});
        console.log("Users table:", users);
      }
    })
    .catch( e => {
      console.log(e);
      res.status(500).json({"error": "Failed to register the credential."});
    });
});

app.post('/webauthn/login/begin', (req, res) => {
  if (!(req.query && req.query.username && req.query.state)) {
    console.error("No username or state.")
    res.status(400).json({"error": "No username or state."});
    return;
  }
  const state = req.query.state;
  fido2lib.assertionOptions()
    .then(pkcr => {
      const user = users[req.query.username];
      pkcr.allowCredentials = [{
        type: "public-key",
        id: user.credId
      }];
      pkcr.challenge = Base64.fromUint8Array(new Uint8Array(pkcr.challenge), true);
      states[state] = {
        "user" : req.query.username,
        "challenge": pkcr.challenge,
        "type": "login"
      };
      console.log(pkcr);
      res.status(200).json(pkcr);
    })
    .catch(e => {
      res.status(500).json({"error": "Unable to create public key creation options."});
    });
});

app.post('/webauthn/login/finish', (req, res) => {
  console.log("States data: ", states);
  if (!(req.query && req.query.username && req.query.state)) {
    res.status(400).json({"error": "No username or state."});
    return;
  }
  const state = req.query.state;
  if (!state in states || 
      states[state].user != req.query.username || 
      states[state].type != "login"){
    res.status(400).json({"error": "Invalid request."});
    return;
  }

  assresp = {
    id: Base64.toUint8Array(req.body.id).buffer,
    rawId: Base64.toUint8Array(req.body.rawId).buffer,
    response: {
      authenticatorData: req.body.response.authenticatorData,
      clientDataJSON: req.body.response.clientDataJSON,
      signature: req.body.response.signature
    }
  }

  const challenge = states[state].challenge;
  const publicKey = users[req.query.username].credentialPublicKeyPem;
  const prevCounter = users[req.query.username].counter;

  delete states[state];

  fido2lib.assertionResult(assresp, {
    challenge,
    origin: "https://mysrv.local:8443",
    factor: "either",
    publicKey,
    prevCounter,
    userHandle: null
  })
    .then(r => {
      if (r.audit.validExpectations && r.audit.validRequest && r.audit.complete){
        users[req.query.username].counter = r.authnrData.get('counter');
        res.status(200).json({"success": `${req.query.username} authenticated successfully.`});
      }
    })
    .catch( e => {
      console.log(e);
      res.status(401).json({"error": `Failed to authenticate ${req.query.username}.`});
    });
});


const p = require("path");
const scertpath = p.join("..", "certs");
const fs = require("fs");
const { randomBytes } = require("crypto");

var tlsopts = {
  key:  fs.readFileSync(p.join(scertpath, "mysrv.local.key")),
  passphrase: "password",
  cert: Buffer.concat([
    fs.readFileSync(p.join(scertpath, "mysrv.local.crt")),
    fs.readFileSync(p.join(scertpath, "scas.crt"))
  ])
};

const httpsServer = https.createServer(tlsopts, app);

httpsServer.listen(8443, () => {
  console.log("HTTPS server up and running on port 8443")
});