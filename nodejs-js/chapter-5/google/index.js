/**
 * Google OAuth 2.0 Authentication Server
 * 
 * Endpoints:
 * 
 * GET /oauth/login
 *   - Initiates OAuth login with Google.
 *   - Redirects user to Google's authorization page.
 * 
 * GET /oauth/callback
 *   - Handles the OAuth callback from Google.
 *   - Exchanges authorization code for tokens.
 *   - Stores tokens in session.
 * 
 * GET /oauth/logout
 *   - Logs out the user by destroying the session.
 *   - Redirects to home page.
 * 
 * GET /userinfo
 *   - Returns user information fetched from Google using the access token.
 *   - Requires user to be authenticated.
 * 
 * GET /idtoken
 *   - Returns decoded ID token (JWT) from session.
 *   - Requires user to be authenticated.
 * 
 * Static files served from /frontend.
 * 
 * Requires environment variables:
 *   - GOOGLE_CLIENT_ID
 *   - GOOGLE_CLIENT_SECRET
 */
const express = require("express");
const http = require("http");
const app = express();

const sess = require('express-session');
app.use(express.json());
app.use(express.static('frontend'));
app.use(sess({
  secret: "password"
}));

{
  const oclient = require("openid-client");
  const cid = process.env.GOOGLE_CLIENT_ID;
  const csecret = process.env.GOOGLE_CLIENT_SECRET;
  console.log(cid, " ", csecret);
  if (!cid || !csecret) {
    console.error("Please set the environment variables GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET");
    process.exit(1);
  }

  const states = new Set();
  var config
  oclient.discovery(new URL("https://accounts.google.com"), cid, csecret)
  .then(cnf=>{
    config=cnf;
    app.listen(8444, () => console.log('Server running on http://localhost:8444'));
  })
  .catch(e=>{
    console.error("Error discovering the OpenID Connect provider: ", e);
    process.exit(1);
  });

  app.get('/oauth/login', (req, res) => {
    const state = oclient.randomState();
    const params = {
      state,
      redirect_uri: "http://localhost:8444/oauth/callback",
      scope: ['email profile openid']
    }
    const url = oclient.buildAuthorizationUrl(config, params);
    states.add(state);
    console.log(`Login URL: ${url.href}`);
    res.redirect(url.href);
  });

  app.get('/oauth/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
  });

  const jwt = require('jsonwebtoken');

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
        redirect_uri: "http://localhost:8444/oauth/callback",
        scope: ["profile"]
      }
      oclient.authorizationCodeGrant(config, url, {
        expectedState: state
      }, params).then((tokens) => {
        req.session.tokens = tokens;
        req.session.save();
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
    const token = req.session.tokens?.access_token;
    const idtoken = req.session.tokens?.id_token;
    if (!token || !idtoken) {
      res.status(401).json({"error":"Unauthorized"});
      return;
    }
    const decoded = jwt.decode(idtoken);

    oclient.fetchUserInfo(config, token, decoded.sub)
    .then((userinfo) => {
      console.log(userinfo);
      res.json(userinfo);
    }).catch((e) => {
      console.log(e);
      res.status(401).json({"error":e.message});
    });
  });

  app.get('/idtoken', (req, res) => {
    const idtoken = req.session.tokens?.id_token;
    if (!idtoken) {
      res.status(401).json({"error":"Unauthorized"});
      return;
    }
    const decoded = jwt.decode(idtoken);
    if (!decoded) {
      res.status(500).json({"error":"Invalid ID token"});
      return;
    }
    console.log(decoded);    
    res.json(decoded);
  });
}