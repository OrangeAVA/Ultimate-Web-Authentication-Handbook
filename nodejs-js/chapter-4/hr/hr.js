/**
 * @file hr.js
 * @description
 * SAML 2.0 Service Provider implementation for an HR web application using Express.js.
 * Handles authentication, session management, and user data access via SAML with an external Identity Provider (IdP).
 * Loads and parses IdP metadata, manages certificates and keys, and exposes endpoints for SAML login, logout, assertion 
 * consumer, and user data.
 *
 * @module hr
 *
 * @see {@link https://github.com/node-saml/node-saml} for SAML library used.
 *
 * @endpoints
 * @name GET /saml/metadata
 * @description Returns the SAML Service Provider metadata XML for IdP configuration.
 * @returns {application/xml} SAML metadata.
 *
 * @name POST /saml/acs
 * @description Assertion Consumer Service endpoint for processing SAML responses and requests from the IdP.
 * Handles login and logout SAML flows.
 * @returns {302} Redirects to home page or SAML logout URL.
 *
 * @name GET /auth/login
 * @description Initiates SAML authentication by redirecting the user to the IdP login page.
 * @returns {302} Redirects to IdP SAML login URL.
 *
 * @name GET /auth/logout
 * @description Logs out the current user by clearing the session and redirects to home page.
 * @returns {302} Redirects to home page.
 *
 * @name GET /auth/user
 * @description Returns information about the currently authenticated user.
 * Requires authentication.
 * @returns {application/json} User information.
 * @returns {401} Unauthorized if not authenticated.
 *
 * @name GET /users
 * @description Returns a list of users.
 * Requires authentication.
 * - If the user is an admin (has 'hradmin' group), returns all users.
 * - Otherwise, returns only the current user's data.
 * @returns {application/json} List of users.
 * @returns {401} Unauthorized if not authenticated.
 *
 * @note
 * - Uses express-session for session management.
 * - Serves static frontend files from the 'frontend' directory.
 * - TLS server runs on https://hr.mysrv.local:8444.
 */
const path = require('node:path');
const fs = require('node:fs');
const nsdisplayName = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name';
const nsGroups = 'http://schemas.passportjs.com/groups';

function clean_cert_annots(certPath) {
  const encoding = 'utf8';
  const certRaw = fs.readFileSync(certPath, { encoding });
  const pemBlock = certRaw.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
  return pemBlock ? pemBlock[0] : '';
}

function decrypt_private_key(certPath, passphrase) {
  const { createPrivateKey } = require('crypto');
  const encoding = 'utf8';
  const encryptedKey = fs.readFileSync(certPath, { encoding });
  const privateKeyObj = createPrivateKey({ key: encryptedKey, format: 'pem', passphrase });
  return privateKeyObj.export({ format: 'pem', type: 'pkcs8' });
}

const xml2js = require('xml2js');
var idpMetadata = null;

async function read_metadata(url){
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch IdP metadata: ${res.statusText}`);
  }
  const metadata = await res.text();
  const parsed = await xml2js.parseStringPromise(metadata, { explicitArray: false });
  return parsed;
}

async function config_saml_sp(app){
  const publicCertBlock = clean_cert_annots(path.join(__dirname, 'certs', 'hr.crt'));
  const privateKey = decrypt_private_key(path.join(__dirname, 'certs', 'hr.key'), 'password');
  const publicCert = publicCertBlock.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\r?\n|\s/g, '');

  const idpMetadata = await read_metadata('https://idp.local:8443/idp/metadata');

  if (!idpMetadata) {
    throw new Error('Exiting as unable to load IdP metadata');
  }

  const idpCert = idpMetadata.EntityDescriptor.IDPSSODescriptor.KeyDescriptor.KeyInfo.X509Data.X509Certificate;
  const ssoServices = idpMetadata.EntityDescriptor.IDPSSODescriptor.SingleSignOnService;
  var entryPoint = '';
  if (Array.isArray(ssoServices)) {
    const redirectService = ssoServices.find(s => s.$.Binding.includes('HTTP-Redirect'));
    entryPoint = redirectService ? redirectService.$.Location : ssoServices[0].$.Location;
  } else {
    entryPoint = ssoServices.$.Location;
  }

  // Handle SingleLogoutService endpoints
  const sloServices = idpMetadata.EntityDescriptor.IDPSSODescriptor.SingleLogoutService;
  let logoutUrl = '';
  if (Array.isArray(sloServices)) {
    const sloRedirect = sloServices.find(s => s.$.Binding.includes('HTTP-Redirect'));
    logoutUrl = sloRedirect ? sloRedirect.$.Location : sloServices[0].$.Location;
  } else if (sloServices) {
    logoutUrl = sloServices.$.Location;
  }
    
  const {SAML} = require('@node-saml/node-saml');
  const saml = new SAML({
    callbackUrl: 'https://hr.mysrv.local:8444/saml/acs', 
    logoutCallbackUrl: 'https://hr.mysrv.local:8444/saml/acs',
    entryPoint,
    logoutUrl,
    issuer: 'https://hr.mysrv.local:8444/saml',
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    idpCert,
    publicCert,
    privateKey,
    acceptedClockSkewMs: 10000,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false
  });

  app.get('/saml/metadata', (req, res) => {
    const metadata = saml.generateServiceProviderMetadata(undefined, publicCert);
    res.type('application/xml');
    res.send(metadata);
  });

  app.post('/saml/acs', (req, res) => {
    if (req.body?.SAMLResponse) {
      saml.validatePostResponseAsync(req.body)
        .then(({ profile, loggedOut }) => {
          console.log('SAML assertion processed successfully:', profile);
          if (loggedOut) {
            console.log('User logged out via SAML');
            if (req.session?.profile) {
              console.log('Removing user session:', req.session.profile.nameID);
              delete req.session.profile;
            }
          } else {
            req.session.profile = profile;
            req.session.save();
            console.log('User session created:', profile.nameID);
          }
          return res.redirect('/');
        })
        .catch(err => {
          console.error('Error processing SAML assertion:', err);
          res.status(500).send('Internal Server Error');
        });
    } else if (req.body?.SAMLRequest) {
      saml.validatePostRequestAsync(req.body)
        .then(({ profile, loggedOut }) => {
          if (!loggedOut) throw new Error('Unexpected SAML request without logout');
          if (req.session?.profile) {
            console.log('Removing user session:', req.session.profile.nameID);
            delete req.session.profile;
          }
          console.log("Profile data:", profile);
          console.log("RelayState:", req.body.RelayState);
          return saml.getLogoutResponseUrlAsync(profile, req.body.RelayState, {}, true);
        })
        .then(logoutUrl => {
          console.log('Redirecting to SAML logout URL:', logoutUrl);
          res.redirect(logoutUrl);
        })
        .catch(err => {
          console.error('Error processing SAML request:', err);
          res.status(500).send('Internal Server Error');
        });
    }
  });

  app.get('/auth/logout', (req, res) => {
    if (!req.session?.profile) {
      console.log('No user session to log out');
      res.redirect('/');
    } else {
      saml.getLogoutUrlAsync(req.session.profile, '/')
        .then(logoutUrl => {
          console.log('Redirecting to SAML logout URL:', logoutUrl);
          res.redirect(logoutUrl);
        })
        .catch(err => {
          console.error('Error generating SAML logout URL:', err);
          delete req.session.profile;
          res.redirect('/');
        });
      console.log('Logging out user:', req.session.profile.nameID);
    }
  });

  app.get('/auth/login', (req, res) => {
    if (req.session?.profile) {
      console.log('User already logged in:', req.session.profile.nameID);
      return res.redirect('/');
    }
    const relayState = req.query.RelayState || '/';
    saml.getAuthorizeUrlAsync({relayState})
      .then(url => {
        console.log('Redirecting to SAML login URL:', url);
        res.redirect(url);
      })
      .catch(err => {
        console.error('Error generating SAML login URL:', err);
        res.status(500).send('Internal Server Error');
      });
  });

  function hasLoggedIn(req, res, next) {
    if (req.session?.profile) {
      console.log('User already authenticated:', req.session.profile.nameID);
      return next();
    } else {
      console.log('User not authenticated.');
      return res.status(401).send('Unauthorized');
    }
  }

  app.get('/auth/user', hasLoggedIn, (req, res) => {
    if (!req.session?.profile) {
      return res.status(401).send('Unauthorized');
    }
    console.log('Returning user information:', req.session.profile);
    const user = req.session.profile[nsdisplayName];
    res.json({user});
  });

  app.get('/users', hasLoggedIn, (req, res) => {
    const currentProfile = req.session?.profile;
    if (!currentProfile) {
      return res.status(401).send('Unauthorized');
    } else if (!currentProfile[nsGroups] || !currentProfile[nsGroups].includes('hradmin')) {
      return res.json(Object.values(users).filter(user => user.id === currentProfile.nameID));
    } else if (currentProfile[nsGroups].includes('hradmin')) {
      console.log('Admin user accessing all users:', currentProfile.nameID);
      return res.json(Object.values(users));
    }
    return res.status(401).erorr('Unauthorized');
  });
}

const express = require("express");
const app = express();
app.use(express.static('frontend'));
app.use(express.urlencoded({ extended: true }));

/*
app.use(
  (req, res, next) => {
    res.append('Access-Control-Allow-Origin', [
      'https://hr.mysrv.local:8444',
      'https://idp.local:8443'
    ]);
    res.append('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.append('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.append('Access-Control-Allow-Credentials', 'true');
    next();
  }
);*/

const maxAge = 1000 * 60 * 60 * 2; // 2 hours
var session = require('express-session');
app.use(session({secret: "password", 
  cookie: {maxAge},
}));

const users = {
  alice: { 
    id: "alice", 
    leaves:20 
  },
  bob:   { 
    id: "bob",   
    leaves:15
  },
  carol: { 
    id: "carol", 
    leaves:18, 
  },
  don:   { 
    id: "don",   
    leaves:22,
  }
};

config_saml_sp(app).then(() => {
  console.log('SAML Service Provider configured successfully');
  // Paths to certificate and key
  const certDir = path.join(__dirname, 'certs', 'ssl');
  const options = {
    key: fs.readFileSync(path.join(certDir, 'hr.mysrv.local.key')),
    passphrase: "password",
    cert: Buffer.concat([
      fs.readFileSync(path.join(certDir, "hr.mysrv.local.crt")),
      fs.readFileSync(path.join(certDir, "scas.crt"))
    ])
  };

  const https = require('node:https');
  https.createServer(options, app).listen(8444, 'hr.mysrv.local', () => {
    console.log('TLS server running at https://hr.mysrv.local:8444');
  });
}).catch(err => {
  console.error('Error configuring SAML Service Provider:', err);
  process.exit(1);
});