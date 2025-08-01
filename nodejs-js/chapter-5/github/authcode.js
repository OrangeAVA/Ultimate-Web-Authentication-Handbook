/**
 * @file authcode.js
 * @description
 * This file implements GitHub OAuth 2.0 Authorization Code flow using Express.js.
 * It provides endpoints for login, logout, callback handling, and fetching user resources.
 * The server runs over HTTPS and uses cookies to store access tokens securely.
 *
 * @endpoint
 * GET /hello
 *   - Returns a simple "Hello, World!" message.
 *
 * GET /oauth/login
 *   - Initiates the OAuth 2.0 login flow with GitHub.
 *   - Redirects the user to GitHub's authorization endpoint.
 *
 * GET /oauth/logout
 *   - Logs out the user by clearing the authentication token cookie.
 *   - Redirects to the home page.
 *
 * GET /oauth/callback
 *   - Handles the OAuth 2.0 callback from GitHub.
 *   - Exchanges the authorization code for an access token.
 *   - Stores the access token in a secure, HTTP-only cookie.
 *   - Redirects to the home page.
 *
 * GET /resource
 *   - Fetches the authenticated user's profile information from GitHub.
 *   - Requires a valid access token in the cookie.
 *   - Returns user information as JSON.
 *
 * @note
 * - Uses HTTPS with custom certificates.
 * - Requires environment variables GH_CLIENT_ID and GH_CLIENT_SECRET for GitHub OAuth.
 * - Uses the openid-client library for OAuth operations.
 */
const express = require("express");
const https = require("node:https");
const app = express();
const cookieParser = require('cookie-parser')
app.use(cookieParser())
app.use(express.static('frontend'));
app.get('/hello', (req, res) => {
  res.send('Hello, World!');
});

{
  const oclient = require("openid-client");

  const cid = process.env.GH_CLIENT_ID;
  const csecret = process.env.GH_CLIENT_SECRET;

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
    res.clearCookie('token');
    res.redirect('/');
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
        redirect_uri: "https://mysrv.local:8443/oauth/callback",
        scope: ["user"]
      }
      oclient.authorizationCodeGrant(config, url, {
        expectedState: state
      }, params).then((tokens) => {
        console.log(tokens)
        res.cookie('token', tokens.access_token, {
          httpOnly: true,
          secure: true,
          path: '/'
        });
        res.redirect('/');
      }).catch((e) => {
        console.log(e);
        res.status(401).send(e.message);
      })
    } else {
      res.status(400).send("The server received a bad request");
    }
  });

  app.get('/resource', (req, res) => {
    console.log(req.cookies)
    token = req.cookies.token
    if (!token){
      res.status(401).send("User not authenticated");
    } else {
      console.log(token);
      oclient.fetchProtectedResource(config, token, new URL('https://api.github.com/user'), 'GET')
        .then(response => {
          if (!response.ok) 
            res.status(500).send("Unable to collect user information")
          else 
            return response.json();
        })
        .then(v => {
          console.log(v);
          res.json(v);
        })
        .catch(e => console.error('Error:', e));
    }
  });
}

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

httpsServer.listen(8443, () => {
  console.log("HTTPS server up and running on port 8443")
});
