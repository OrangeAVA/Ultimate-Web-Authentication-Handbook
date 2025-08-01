/**
 * Identity Provider (IdP) server implementation for SAML authentication flows.
 * 
 * This file sets up an Express.js server that acts as a SAML IdP, handling authentication,
 * session management, user login/logout, and SAML protocol endpoints for Service Providers (SPs).
 * It supports both SP-initiated and IdP-initiated SAML flows, user management, and admin utilities.
 * 
 * Main Features:
 * - Loads and manages X.509 certificates for SAML signing/encryption.
 * - Implements user authentication with bcrypt password hashing.
 * - Tracks active sessions and user service logins.
 * - Fetches and parses SP metadata for trusted services.
 * - Handles SAML authentication and logout requests/responses.
 * - Provides admin endpoints for session and user management.
 * - Serves static frontend assets and login page.
 * - Runs over HTTPS with custom SSL certificates.
 * 
 * Exposed Endpoints:
 * 
 * GET  /saml/metadata
 *      - Returns SAML Service Provider metadata in XML format.
 * 
 * POST /saml/acs
 *      - Assertion Consumer Service endpoint for processing SAML responses and requests.
 * 
 * GET  /auth/login
 *      - Initiates SAML login flow; redirects to SAML login URL.
 * 
 * GET  /auth/logout
 *      - Initiates SAML logout flow; redirects to SAML logout URL.
 * 
 * GET  /auth/user
 *      - Returns information about the currently authenticated user (requires authentication).
 * 
 * GET  /admin/active-sessions
 *      - Lists all active user sessions (requires authentication).
 * 
 * GET  /admin/users
 *      - Returns user information; admin users see all users, others see only their own (requires authentication).
 * 
 * POST /admin/services
 *      - Fetches and parses metadata for all configured services; returns available services.
 * 
 * GET  /admin/shortcuts/:code
 *      - Performs IdP-initiated SAML login for a given service code (requires authentication).
 * 
 * ALL  /idp
 *      - SAML IdP endpoint for authentication requests; supports both GET and POST.
 * 
 * GET  /idp/metadata
 *      - Returns IdP metadata in XML format.
 * 
 * GET  /idp/logout
 *      - Initiates SAML Single Logout for the user across all logged-in services.
 * 
 * Other:
 * - Serves static files from /frontend.
 * - Handles login page rendering and authentication.
 * - Manages CORS headers for trusted SPs.
 * - Runs HTTPS server on port 8443.
 */
const fs = require('node:fs');
const path = require('node:path');
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

const express = require("express");
const app = express();
app.use(express.static('frontend'));

const maxAge = 1000 * 60 * 60 * 2; // 2 hours
var session = require('express-session');
app.use(session({secret: "password", 
  cookie: {maxAge},
}));

app.use(express.urlencoded({ extended: true }));

const xml2js = require('xml2js');

const publicCertBlock = clean_cert_annots(path.join(__dirname, 'certs', 'idp.crt'));
const privateKey = decrypt_private_key(path.join(__dirname, 'certs', 'idp.key'), 'password');

const {SAML} = require('@node-saml/node-saml');

function config_saml_sp(app){
  const publicCert = publicCertBlock.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\r?\n|\s/g, '');
  const idpCert = publicCertBlock;

  const saml = new SAML({
    callbackUrl: 'https://idp.local:8443/saml/acs', 
    logoutCallbackUrl: 'https://idp.local:8443/saml/acs',
    entryPoint: 'https://idp.local:8443/idp',
    logoutUrl: 'https://idp.local:8443/idp/logout',
    issuer: 'https://idp.local:8443/saml',
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

  app.post('/saml/acs', express.urlencoded({ extended: false }), (req, res) => {
    if (req.body?.SAMLResponse) {
      saml.validatePostResponseAsync(req.body)
        .then(({ profile, loggedOut }) => {
          console.log('SAML assertion processed successfully:', profile);
          if (loggedOut) {
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
    } else {
      console.error('Invalid SAML request: neither SAMLResponse nor SAMLRequest found');
      res.status(400).send('Bad Request: Missing SAMLResponse or SAMLRequest');
    }
  });

  app.get('/auth/logout', (req, res) => {
    if (!req.session?.profile) {
      console.log('No user session to log out');
      return res.redirect('/');
    }
    console.log('Logging out user:', req.session.profile.nameID);
    saml.getLogoutUrlAsync(req.session.profile, req.query.RelayState || '/')
      .then(logoutUrl => {
        console.log('Redirecting to SAML logout URL:', logoutUrl);
        res.redirect(logoutUrl);
      })
      .catch(err => {
        console.error('Error generating SAML logout URL:', err);
        res.status(500).send('Internal Server Error');
      });
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
    console.log('Returning user information:', req.session.profile);
    const user = req.session.profile[nsdisplayName];
    res.json({user});
  });

  // Utility endpoint to view all active sessions (for admin/debug)
  app.get('/admin/active-sessions', hasLoggedIn, (req, res) => {    
    res.json(Array.from(activeSessions.entries()).map(([sid, info]) => ({
      sessionId: sid,
      ...info
    })));
  });

  app.get('/admin/users', hasLoggedIn, (req, res) => {
    const currentProfile = req.session?.profile;
    if (!currentProfile) {
      return res.status(401).send('Unauthorized');
    } else if (!currentProfile[nsGroups] || !currentProfile[nsGroups].includes('itadmin')) {
      return res.json(Object.values(users).filter(user => user.id === currentProfile.nameID));
    } else if (currentProfile[nsGroups].includes('itadmin')) {
      console.log('Admin user accessing all users:', currentProfile.nameID);
      return res.json(users);
    }
    return res.status(401).erorr('Unauthorized');
  });

  app.post('/admin/services', (req, res) => {
    (async () => {
      for (const service of services) {
        try {
          const resp = await fetch(service.metadataURL, { timeout: 5000 });
          if (!resp.ok) {
            throw new Error(`Failed to fetch metadata: ${resp.status} ${resp.statusText}`);
          }
          const data = await resp.text();
          const parsed = await xml2js.parseStringPromise(data, { explicitArray: false});
          console.log(`Parsed metadata for ${service.code}`);
          service.metadata = parsed;
          service.error = null;
          console.log('Logged in services:', req.session.services);
          service.loggedIn = !!req.session.profile && !! req.session.services?.includes(service.entityID);
          service.hasLogout = !!service.metadata.EntityDescriptor?.SPSSODescriptor?.SingleLogoutService;
        } catch (err) {
          console.error(`Error fetching metadata for ${service.code}`);
          service.error = err.message || 'Unknown error';
        }
      }
      return services;
    })().then((services) => {
      const results = services.filter(service => service.error === null);
      res.json(results);
    }).catch((err) => {
      console.error('Error fetching service metadata:', err);
      res.status(500).json({ error: 'Failed to fetch service metadata' });
    });
  });

  function postIDPInitiatedSAMLResponse(opts, user, acsUrl, res) {

    samlp.getSamlResponse(opts, user, function (err, SAMLResponse) {
      if (err) return next(err);
      console.log('Generated SAML Response:', SAMLResponse);
      const response = new Buffer.from(SAMLResponse);
      const token = response.toString('base64');
      const form = `
        <html>
          <head>
            <title>Working...</title>
          </head>
          <body>
            <form method="post" name="hiddenform" action="${acsUrl}">
              <input type="hidden" name="SAMLResponse" value="${token}">
                <input type="hidden" name="RelayState" value="/">
                <noscript>
                    <p>
                        Script is disabled. Click Submit to continue.
                    </p><input type="submit" value="Submit">
                </noscript>
            </form>
            <script language="javascript" type="text/javascript">
                window.setTimeout(function(){document.forms[0].submit();}, 0);
            </script>
          </body>
        </html>
      `;

      res.set('Content-Type', 'text/html');
      res.send(form);
    });
  }

  app.get('/admin/shortcuts/:code', hasLoggedIn, (req, res) => {
    const service = services.find(s => s.code === req.params.code);
    if (!service) {
      return res.status(404).send('Service not found');
    }
    if (!service.metadata || !service.metadata.EntityDescriptor || !service.metadata.EntityDescriptor.SPSSODescriptor) {
      return res.status(500).send('Service metadata not available');
    }
    const acsUrl = service.metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService.$.Location;
    if (!acsUrl) {
      return res.status(500).send('Assertion Consumer Service URL not found in metadata');
    }

    const opts = {
      issuer: 'https://idp.local:8443/idp',
      cert: publicCertBlock,
      key: privateKey,
      audience: service.entityID,
      nameID: req.session.user.id,
      sessionIndex: req.session.sessionIndex,
      attributes: {
        [nsdisplayName]: req.session.user.displayName,
        [nsGroups]: req.session.user.groups || []
      },
      signResponse: false,
      signAssertion: true,
    }
    const user = req.session.user;
    if (service.hasLogout && !req.session.services.includes(service.entityID)) {
      req.session.services.push(service.entityID);
    }
    postIDPInitiatedSAMLResponse(opts, user, acsUrl, res);
  });
}

config_saml_sp(app);

const services = [
  {
    code: 'hr',
    entityID: 'https://hr.mysrv.local:8444/saml',
    metadataURL: 'https://hr.mysrv.local:8444/saml/metadata',
    displayName: 'HR Application',
    description: 'Human Resources Management System',
    metadata : {},
    error: null,
    hasLogout: false
  },
  {
    code: 'finance',
    entityID: 'https://finance.mysrv.local:8445/saml',
    metadataURL: 'https://finance.mysrv.local:8445/saml/metadata',
    displayName: 'Finance Application',
    description: 'Finance Management System',
    metadata : {},
    error: null,
    hasLogout: false
  },
  {
    code: 'idpportal',
    entityID: 'https://idp.local:8443/saml',
    metadataURL: 'https://idp.local:8443/saml/metadata',
    displayName: 'Identity Provider Portal',
    description: 'Identity Provider for SAML authentication',
    metadata : {},
    error: null,
    hasLogout: false
  }
];

// Define the users and their groups
const users = {
  alice: { 
    id: "alice", 
    name: { givenName: "Alice", familyName: "Smith" }, 
    displayName: "Alice Smith", 
    emails: [{value: "alice@example.com"}], 
    groups: ["users", "hradmin"] 
  },
  bob:   { 
    id: "bob",   
    name: { givenName: "Bob", familyName: "Doe" }, 
    displayName: "Bob Doe",   
    emails: [{value: "bob@example.com"}],   
    groups: ["users", "financeadmin"] 
  },
  carol: { 
    id: "carol", 
    name: { givenName: "Carol", familyName: "Smith" }, 
    displayName: "Carol Smith", 
    emails: [{value: "carol@example.com"}], 
    groups: ["users", "itadmin"] 
  },
  don:   { 
    id: "don",   
    name: { givenName: "Don", familyName: "Doe" }, 
    displayName: "Don Doe",   
    emails: [{value: "don@example.com"}],   
    groups: ["users"] 
  }
};

const bcrypt = require('bcrypt');
const shadowPasswords = {};
// Hash the password "password" for all users and store in shadowPasswords
Object.entries(users).forEach(([username, user]) => {
  shadowPasswords[username] = bcrypt.hashSync("password", 10);
});
function verify(username, password) {
  const hash = shadowPasswords[username];
  if (!hash) return false;
  return bcrypt.compareSync(password, hash);
}

const activeSessions = new Map();

app.use((req, res, next) => {
  res.on('finish', () => {
    const now = new Date();
    for (const [sid, info] of activeSessions.entries()) {
      if (info.expiryTime <= now) {
        activeSessions.delete(sid);
      }
    }
    if (req.session && req.session.id) {
      if (req.session.user) {
        // Only add if session.id is not already in activeSessions
        if (!activeSessions.has(req.session.id)) {
          activeSessions.set(req.session.id, {
            username: req.session.user.id,
            displayName: req.session.user.displayName,
            loginTime: now,
            expiryTime: new Date(now.getTime() + maxAge),
            ip: req.ip
          });
        }
      } else {
        activeSessions.delete(req.session.id);
      }
    }
  });
  next();
});

function render_login_page(req, res, failed= false) {
  console.log('Rendering login page');
  const loginPath = path.join(__dirname, 'frontend', 'login.html');
  let loginHtml = fs.readFileSync(loginPath, 'utf8');
  // Build hidden inputs for all query parameters
  const paramsSource = Object.assign({}, req.method === 'POST' ? req.body : req.query);
  delete paramsSource.username;
  delete paramsSource.password;
  const params = Object.entries(paramsSource)
    .map(([key, value]) => `<input type="hidden" name="${key}" value="${String(value).replace(/"/g, '&quot;')}" />`)
    .join('\n');
  loginHtml = loginHtml.replace(/<\/form>/i, params + '\n</form>\n');
  if (failed) {
    loginHtml = loginHtml.replace(
      /(<\/form>)/i,
      `<div style="color:red;margin-top:1em;">Login failed. Please try again.</div>\n$1`
    );
  }
  return res.send(loginHtml);
}

const crypto = require('node:crypto');
function authenticate(req, res, next) {
  if (req.session?.user) {
    console.log(`${req.session.user.id} already authenticated:`);
    return next();
  }
  const {username, password} = req.method === 'POST' ? req.body : req.query;
  if (!username || !password){
    return render_login_page(req, res);
  }
  console.log('Authenticating user:', username);
  if (!verify(username, password)) {
    console.log('Incorrect password for the user:', username);
    return render_login_page(req, res, true);
  }
  req.session.user = users[username];
  req.session.sessionIndex = crypto.randomUUID();
  if (!req.session.services) {
    req.session.services = [];
  }
  return next();
}

const samlp = require('samlp');

app.all('/idp', authenticate, (req, res, next) => {
  const getPostURL = (audience, samldom, req, callback) => {
    const service = Object.values(services).find(s => s.entityID === audience);
    if (!service) {
      console.warn('Audience not found in trusted services:', audience);
      return callback(new Error('Untrusted Service Provider'), null);
    }
    if (service.hasLogout && !req.session.services.includes(audience)) {
      req.session.services.push(audience);
    }
    const acsUrl = samldom && samldom.documentElement && samldom.documentElement.getAttribute('AssertionConsumerServiceURL');
    if (acsUrl) {
      return callback(null, acsUrl);
    }

    const postUrl = service.metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService.$.Location;
    if (postUrl) {
      return callback(null, postUrl);
    } else {
      // fallback: try to guess from entityID
      return callback(null, service.entityID.replace('/saml', '/saml/acs'));
    }
  };
  const getUserFromRequest = (req) => {return req.session?.user};

  samlp.auth({
    issuer:     'https://idp.local:8443/idp',
    cert:       publicCertBlock,
    key:        privateKey,
    sessionIndex: req.session.sessionIndex,
    getPostURL,
    getUserFromRequest,
    signResponse: false,
    signAssertion: true
  })(req, res, next);
});

app.get('/idp/metadata', samlp.metadata({
  issuer:   'https://idp.local:8443/idp',
  redirectEndpointPath: '/idp',
  postEndpointPath: '/idp',
  logoutEndpointPaths: { 
    redirect: '/idp/logout'
  },
  cert:     publicCertBlock
}));

const getSessionParticipants = function () {
  const libpath = require.resolve('samlp');
  const libdir = path.dirname(libpath);
  const SessionParticipants = require(path.join(libdir, 'sessionParticipants'));
  return function (spdata) {
    return new SessionParticipants(spdata);
  };
}();

app.get('/idp/logout', (req, res, next) => {
  if (!req.session?.user || !req.session.services || req.session.services.length === 0) {
    console.log('No user session to log out');
    return res.redirect('/');
  }

  console.log('Logging out user:', req.session.user.id);
  const nameId = req.session.user.id;
  const code = req.query?.service || req.body?.service;
  const entityID = code ? (services.find(s => s.code === code)?.entityID) : null;
  const svss = entityID ? [entityID] : req.session.services;

  req.session.sessionParticipantsData = req.session.sessionParticipantsData || svss.map(serviceProviderId => {
    const service = services.find(s => s.entityID === serviceProviderId)
    const spDesc = service.metadata.EntityDescriptor.SPSSODescriptor;
    if (!spDesc.SingleLogoutService || !spDesc.SingleLogoutService.$ || !spDesc.SingleLogoutService.$.Location) {
      // Skip services without SingleLogoutService
      return null;
    }
    const serviceProviderLogoutURL = spDesc.SingleLogoutService.$.Location;
    const binding = spDesc.SingleLogoutService.$.Binding;
    const nameIdFormat = spDesc.NameIDFormat;
    const cert = spDesc?.KeyDescriptor["ds:KeyInfo"]["ds:X509Data"]["ds:X509Certificate"];
  
    return {
      serviceProviderId,
      sessionIndex: req.session.sessionIndex,
      nameId,
      nameIdFormat,
      serviceProviderLogoutURL,
      binding,
      cert
    };
  }).filter(n => n);

  if (!req.session.sessionParticipantsDataBkp) {
    req.session.sessionParticipantsDataBkp = structuredClone(req.session.sessionParticipantsData);
  }

  const options = {
    deflate: true,
    issuer: 'https://idp.local:8443/idp',
    cert: publicCertBlock,
    key: privateKey,
    sessionIndex: req.session.sessionIndex,
    nameId,
    sessionParticipants: getSessionParticipants(req.session.sessionParticipantsData),
    clearIdPSession: function (cb){
      // Remove the services in sessionParticipantsDataBkp from req.session.services
      if (req.session.sessionParticipantsDataBkp && Array.isArray(req.session.sessionParticipantsDataBkp)) {
        const toRemove = req.session.sessionParticipantsDataBkp.map(sp => sp.serviceProviderId);
        req.session.services = req.session.services.filter(sid => !toRemove.includes(sid));
        delete req.session.sessionParticipantsData;
        delete req.session.sessionParticipantsDataBkp;
      }
      // If there are no more services in the session, clear user session
      if (!req.session.services || req.session.services.length === 0 ) {
        console.log('No logged in SPs');
        delete req.session.user;
        delete req.session.sessionIndex;
        delete req.session.services;
      }
      return cb();
    }
  };
  req.body = req.body || {};
  samlp.logout(options)(req, res, function (err) {
    if (err) {
      console.error('Error during SAML logout:', err);
      return res.status(400).send(err.message || 'SAML Logout Error');
    }
    req.session.sessionParticipantsData = options.sessionParticipants._participants;
    next();
  });
});

app.use(
  (req, res, next) => {
    res.append('Access-Control-Allow-Origin', [
      'https://hr.mysrv.local:8444',
      'https://finance.mysrv.local:8445',
      'https://idp.local:8443'
    ]);
    res.append('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.append('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.append('Access-Control-Allow-Credentials', 'true');
    next();
  }
);

// Paths to certificate and key
const certDir = path.join(__dirname, 'certs', 'ssl');
const options = {
  key: fs.readFileSync(path.join(certDir, 'idp.local.key')),
  passphrase: "password",
  cert: Buffer.concat([
    fs.readFileSync(path.join(certDir, "idp.local.crt")),
    fs.readFileSync(path.join(certDir, "scas.crt"))
  ])
};

const https = require('node:https');
https.createServer(options, app).listen(8443, 'idp.local', () => {
  console.log('TLS server running at https://idp.local:8443');
});