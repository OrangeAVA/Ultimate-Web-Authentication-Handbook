const express = require("express");
const https = require("https");
const app = express();

app.use(express.static('frontend'));
app.get('/hello', (req, res) => {
  res.send('Hello, World!');
});

{
  const oclient = require("openid-client");

  const cid = process.env.GH_CLIENT_ID;
  const csecret = process.env.GH_CLIENT_SECRET;

  console.log(cid, " ", csecret);

  const config = new oclient.Configuration({
    issuer: "https://github.com",
    authorization_endpoint: "https://github.com/login/oauth/authorize",
    token_endpoint: "https://github.com/login/oauth/access_token"
  }, cid, csecret); 

  const states = new Set();

  app.get('/oauth/login', (req, res) => {
    const state = oclient.randomState();
    const params = {
      state,
      redirect_uri: "https://mysrv.local:8443/oauth/callback",
      scope: ["user"]
    }
    const url = oclient.buildAuthorizationUrl(config, params);
    states.add(state);
    res.redirect(url.href);
  });

  app.get('/oauth/logout', (req, res) => {

  });

  app.get('/oauth/callback', (req, res) => {
    const state = req.query.state;
    if (state && states.has(state)) {
      states.delete(state);
      if (req.query.error) {
        res.status(401).send(req.query.error_description);
        return;
      }
      oclient.authorizationCodeGrant(config, req).then((tokens) => {
        console.log(tokens)
        res.cookie('token', tokens.access_token, {
          httpOnly: true,
          secure: true,
          path: '/'
        });
        res.redirect('/');
      }).catch((e) => {
        res.status(401).send(e);
      })
    } else {
      res.status(400).send("The server received a bad request");
    }
  });
}

const path = require("path");
const scertpath = path.join("..", "certs");
const fs = require("fs");
const { error } = require("console");
const { emitKeypressEvents } = require("readline");

var tlsopts = {
  key:  fs.readFileSync(path.join(scertpath, "mysrv.local.key")),
  passphrase: "password",
  cert: Buffer.concat([
    fs.readFileSync(path.join(scertpath, "mysrv.local.crt")),
    fs.readFileSync(path.join(scertpath, "sint.crt"))
  ])
};

const httpsServer = https.createServer(tlsopts, app);

httpsServer.listen(8443, () => {
  console.log("HTTPS server up and running on port 8443")
});
