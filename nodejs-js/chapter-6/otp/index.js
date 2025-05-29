const express = require("express");
const https = require("node:https");
const app = express();

app.use(express.static('frontend'));
app.use('/@otplib/preset-browser', express.static('node_modules/@otplib/preset-browser'))

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
  const secret = auth.generateSecret();
  var value = {"secret": secret, "type": type};
  var counter = 0;
  if (type == "hotp"){
    value["counter"] = counter = 1;
  }

  users[user] = value;
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
    fs.readFileSync(p.join(scertpath, "sint.crt"))
  ])
};

const httpsServer = https.createServer(tlsopts, app);

httpsServer.listen(8443, () => {
  console.log("HTTPS server up and running on port 8443")
});