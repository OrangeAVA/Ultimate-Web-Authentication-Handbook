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
  const publicCertBlock = clean_cert_annots(path.join(__dirname, 'certs', 'finance.crt'));
  const privateKey = decrypt_private_key(path.join(__dirname, 'certs', 'finance.key'), 'password');
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

  const {SAML} = require('@node-saml/node-saml');
  const saml = new SAML({
    callbackUrl: 'https://finance.mysrv.local:8445/saml/acs',
    issuer: 'https://finance.mysrv.local:8445/saml',
    idpCert,
    publicCert,
    privateKey,
    entryPoint,
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
    saml.validatePostResponseAsync(req.body)
      .then(({ profile, loggedOut }) => {
        console.log('SAML assertion processed successfully:', profile);
        req.session.profile = profile;
        if (loggedOut) {
          console.log('User logged out via SAML');
          req.session?.destroy();
        }
        return res.redirect('/');
      })
      .catch(err => {
        console.error('Error processing SAML assertion:', err);
        res.status(500).send('Internal Server Error');
      });
  });

  app.get('/auth/logout', (req, res) => {
    if (!req.session?.profile) {
      console.log('No user session to log out');
    } else {
      console.log('Logging out user:', req.session.profile.nameID);
    }
    delete req.session.profile;
    res.redirect('/');
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
    } else if (!currentProfile[nsGroups] || !currentProfile[nsGroups].includes('financeadmin')) {
      return res.json(Object.values(users).filter(user => user.id === currentProfile.nameID));
    } else if (currentProfile[nsGroups].includes('financeadmin')) {
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

const maxAge = 1000 * 60 * 60 * 2; // 2 hours
var session = require('express-session');
app.use(session({secret: "password", 
  cookie: {maxAge},
}));

const users = {
  alice: { 
    id: "alice", 
    salary:1000 
  },
  bob:   { 
    id: "bob",   
    salary:2000
  },
  carol: { 
    id: "carol", 
    salary:3000, 
  },
  don:   { 
    id: "don",   
    salary:4000,
  }
};


config_saml_sp(app).then(() => {
  console.log('SAML Service Provider configured successfully');
  // Paths to certificate and key
  const certDir = path.join(__dirname, 'certs', 'ssl');
  const options = {
    key: fs.readFileSync(path.join(certDir, 'finance.mysrv.local.key')),
    passphrase: "password",
    cert: Buffer.concat([
      fs.readFileSync(path.join(certDir, "finance.mysrv.local.crt")),
      fs.readFileSync(path.join(certDir, "scas.crt"))
    ])
  };

  const https = require('node:https');
  https.createServer(options, app).listen(8445, 'finance.mysrv.local', () => {
    console.log('TLS server running at https://finance.mysrv.local:8445');
  });
}).catch(err => {
  console.error('Error configuring SAML Service Provider:', err);
  process.exit(1);
});

