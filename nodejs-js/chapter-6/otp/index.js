/**
 * @fileoverview
 * This file implements a simple HTTPS server using Express for OTP (One-Time Password) authentication.
 * It supports both TOTP (Time-based OTP) and HOTP (Counter-based OTP) mechanisms using the otplib library.
 * The server provides endpoints for user registration (generating OTP secrets and QR codes) and OTP validation.
 * Static files are served for the frontend and otplib browser preset.
 * 
 * @module otp-server
 * 
 * @endpoint GET /register/:user/:type
 *   Registers a new user for OTP authentication.
 *   @param {string} user - The username to register.
 *   @param {string} type - The OTP type ("totp" or "hotp").
 *   @returns {Object} JSON containing the secret, type, (counter for HOTP), and QR code file path.
 * 
 * @endpoint GET /validate/:user/:otp
 *   Validates an OTP token for a registered user.
 *   @param {string} user - The username to validate.
 *   @param {string} otp - The OTP token to verify.
 *   @returns {string} Success or failure message with appropriate HTTP status code.
 * 
 * @endpoint GET /hello
 *   Simple test endpoint.
 *   @returns {string} "Hello, World!"
 * 
 * @static /frontend
 *   Serves static frontend files.
 * 
 * @static /@otplib/preset-browser
 *   Serves static files for otplib browser preset.
 * 
 * @security
 *   The server uses HTTPS with TLS certificates for secure communication.
 */
const express = require("express");
const https = require("node:https");
const app = express();

app.use(express.static('frontend'));

app.get('/hello', (req, res) => {
  res.send('Hello, World!');
});

const otplib = require('otplib');
const auth = otplib.authenticator;
const hotp = otplib.hotp;
const qrcode = require('qrcode');
const tmp = require('tmp');
const p = require('path');

const users = {};

app.get('/register/:user/:type', (req, res) => {
  const user = req.params.user;
  const type = req.params.type; 
  const secret = auth.generateSecret(20);
  var value = {"secret": secret, "type": type};
  var counter = 0;
  if (type == "hotp"){
    value["counter"] = counter = 1;
  }

  const uri = (type == "hotp") ? 
    hotp.keyuri(user, "myserv", secret, counter) : 
    auth.keyuri(user, "myserv", secret);
  console.log(uri);
  tmp.tmpName({ tmpdir: "frontend/images/", postfix: '.png' }, (err, path) => {
    if (err) {
      res.status(500).send("Failed to create temp files");
      return;
    }
    qrcode.toFile(path, uri, (err) => {
      if (err) {
        res.status(500).send("Failed to create QR code");
        return;
      }
      value["qrfile"] = p.join("images", p.basename(path));
      res.json(value);
      if (type == "hotp"){
        // Decode the secret for HOTP. HOTP does not assume a specific encoding.
        // So, the data is binary. We use the authenticator interface to convert
        // from base32 to hex and then hex to binary. 
        const hex_secret = otplib.authenticator.decode(secret);
        const decoded_secret = Buffer.from(hex_secret, 'hex').toString('binary');
        value["secret"] = decoded_secret;
      }
      users[user] = value;
    })
  });
});

app.get('/validate/:user/:otp', (req, res) => {
  const user = req.params.user;
  const token = req.params.otp;

  console.log (user, " ", token);
  const value = users[user];

  const secret = value["secret"];
  const type = value["type"];

  var ret = false;
  if (type == "hotp") {
    const counter = value["counter"];
    ret = hotp.verify({token, secret, counter});
    if (ret){
      users[user]["counter"] = counter + 1;
    }
  } else {
    ret = auth.verify({token, secret});
  }

  if (ret) {
    console.log("User authenticated successfully");
    res.status(200).send("User authenticated successfully");
  } else {
    console.log("User failed to authenticate");
    res.status(401).send("User failed to authenticate");
  }
});

const scertpath = p.join("..", "certs");
const fs = require("fs");

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