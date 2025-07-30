const { register, getCredential } = require("./users");

const fido = require("fido2-lib");
const fido2lib = new fido.Fido2Lib({
  rpId: "idp.local",
  rpName: "IDP Local"
});

const {Base64} = require('js-base64');

async function registerBeginWebAuthn(username) {
  const pkcc = await fido2lib.attestationOptions();
  pkcc.user.id = pkcc.user.name = pkcc.user.displayName = username;
  pkcc.challenge = Base64.fromUint8Array(new Uint8Array(pkcc.challenge), true);
  return pkcc;
}

async function registerFinishWebAuthn(username, challenge, ccdata) {
  const attresp = {
    id: Base64.toUint8Array(ccdata.id).buffer,
    rawId: Base64.toUint8Array(ccdata.rawId).buffer,
    response: {
      attestationObject: ccdata.response.attestationObject,
      clientDataJSON: ccdata.response.clientDataJSON
    }
  }

  const r = await fido2lib.attestationResult(attresp, {
    challenge,
    origin: "https://idp.local:8443",
    factor: "either"
  });
  if (r.audit.validExpectations && r.audit.validRequest && r.audit.complete){
    console.log(r.authnrData);
    credId = Base64.fromUint8Array(new Uint8Array(r.authnrData.get('credId')));
    register('webauthn', username, {
      credId,
      "counter": r.authnrData.get('counter'),
      "credentialPublicKeyPem": r.authnrData.get('credentialPublicKeyPem'),
    });
    return true
  }
  return false;
}

async function authBeginWebAuthn(username) {
  const pkcr = await fido2lib.assertionOptions();
  const cred = getCredential('webauthn', username);
  pkcr.allowCredentials = [{
    type: "public-key",
    id: cred.credId
  }];
  pkcr.challenge = Base64.fromUint8Array(new Uint8Array(pkcr.challenge), true);
  return pkcr;
}

async function authFinishWebAuthn(username, challenge, crdata) {
  const assresp = {
    id: Base64.toUint8Array(crdata.id).buffer,
    rawId: Base64.toUint8Array(crdata.rawId).buffer,
    response: {
      authenticatorData: crdata.response.authenticatorData,
      clientDataJSON: crdata.response.clientDataJSON,
      signature: crdata.response.signature
    }
  };

  cred = getCredential('webauthn', username);

  const publicKey = cred.credentialPublicKeyPem;
  const prevCounter = cred.counter;

  const r = await fido2lib.assertionResult(assresp, {
    challenge,
    origin: "https://idp.local:8443",
    factor: "either",
    publicKey,
    prevCounter,
    userHandle: null
  });

  if (r.audit.validExpectations && r.audit.validRequest && r.audit.complete){
    cred.counter = r.authnrData.get('counter');
    return true;
  }
  return false;
}

module.exports = { registerBeginWebAuthn, registerFinishWebAuthn, authBeginWebAuthn, authFinishWebAuthn };