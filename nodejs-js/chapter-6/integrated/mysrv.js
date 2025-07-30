/**
 * @file mysrv.js
 * @description
 * Express HTTPS server with OpenID Connect authentication and session management.
 *
 * Features:
 * - Serves static files from the 'frontend' directory.
 * - Manages user sessions with express-session (2-hour expiration).
 * - Configures HTTPS using server and CA certificates.
 * - Discovers OpenID Connect configuration from a local identity provider.
 * - Implements OAuth 2.0 login and logout flows using openid-client.
 * - Handles OAuth callback for authorization code grant and stores tokens in session.
 * - Provides a /userinfo endpoint to fetch user information with the access token.
 *
 * Endpoints:
 * - GET /oauth/login: Start OAuth login.
 * - GET /oauth/logout: Start OAuth logout.
 * - GET /oauth/callback: Handle OAuth authorization code callback.
 * - GET /oauth/callback/logout: Handle post-logout callback.
 * - GET /userinfo: Return authenticated user's info.
 */
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.json());
const maxAge = 1000 * 60 * 60 * 2; // 2 hours
var session = require('express-session');
app.use(session({secret: "password", 
  cookie: {maxAge},
}));

const path = require('node:path');
app.use(express.static(path.join(__dirname, 'frontend')));
const fs = require('node:fs');
const https = require('node:https');
const { exit } = require('node:process');
// Define path to certificate directory
const certsDirectory = path.join("..", "certs");

// TLS options for HTTPS server
const tlsOptions = {
  key: fs.readFileSync(path.join(certsDirectory, "mysrv.local.key")),
  passphrase: "password",
  cert: Buffer.concat([
    fs.readFileSync(path.join(certsDirectory, "mysrv.local.crt")),
    fs.readFileSync(path.join(certsDirectory, "scas.crt"))
  ])
};

// Create and start HTTPS server
const httpsServer = https.createServer(tlsOptions, app);

var config;
const oclient = require("openid-client");

oclient.discovery(new URL("https://idp.local:8443/oidc"), "222222", "22222222")
  .then(cfg => {
    console.log("Discovery successful");
    config = cfg;
    httpsServer.listen(8444, () => {
      console.log("HTTPS server up and running on port 8444");
    });
  })
  .catch(err => {
    console.error("Discovery failed:", err);
    exit(1);
  });

const states = new Set();

app.get('/oauth/login', (req, res) => {
  const state = oclient.randomState();
  const params = {
    state,
    redirect_uri: "https://mysrv.local:8444/oauth/callback",
    scope:["openid"]
  }
  const url = oclient.buildAuthorizationUrl(config, params);
  states.add(state);
  res.redirect(url.href);
});

app.get('/oauth/logout', (req, res) => {
  if (req.session.tokens) {
    const state = oclient.randomState();
    const logoutUrl = oclient.buildEndSessionUrl(config, {
      id_token_hint: req.session.tokens.id_token,
      post_logout_redirect_uri: "https://mysrv.local:8444/oauth/callback/logout",
      logout_hint: req.session.username,
      state
    });
    states.add(state);
    res.redirect(logoutUrl.href);
  }
});

app.get('/oauth/callback/logout', (req, res) => {
  const state = req.query.state;
  if (state && states.has(state)) {
    states.delete(state);
    delete req.session.tokens;
    res.redirect('/');
  }
});

app.get('/oauth/callback', (req, res) => {
  const state = req.query.state;
  if (state && states.has(state)) {
    states.delete(state);
    if (req.query.error) {
      res.status(401).send(req.query.error_description);
      return;
    }

    surl = req.protocol+"://"+req.host+req.originalUrl;
    console.log(surl);
    url = new URL(surl);

    const params = {
      redirect_uri: "https://mysrv.local:8444/oauth/callback",
      scope: ["openid"]
    }

    oclient.authorizationCodeGrant(config, url, {
      expectedState: state
    }, params).then((tokens) => {
      console.log(tokens)
      req.session.tokens = tokens
      const idToken = tokens.id_token;
      if (idToken) {
        const payload = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString());
        req.session.username = payload.sub;
      }
      res.redirect('/');
    }).catch((e) => {
      console.log(e);
      res.status(401).send(e.message);
    })
  } else {
    res.status(400).send("The server received a bad request");
  }
});

app.get('/userinfo', (req, res) => {
  if (!req.session.tokens) {
    res.status(401).send("Unauthorized");
    return;
  }
  const token = req.session.tokens.access_token;
  oclient.fetchUserInfo(config, token, req.session.username).then((userinfo) => {
    res.json(userinfo);
  }).catch((e) => {
    console.error(e);
    res.status(500).send("Internal Server Error");
  });
}); 
