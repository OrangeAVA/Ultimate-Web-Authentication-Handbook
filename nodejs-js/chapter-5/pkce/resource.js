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
