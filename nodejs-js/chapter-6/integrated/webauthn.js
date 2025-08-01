
/**
 * WebAuthn integration module for user registration and authentication.
 * 
 * This file provides functions to handle the WebAuthn (FIDO2) registration and authentication flows,
 * including generating attestation and assertion options, and verifying responses from authenticators.
 * It uses the `fido2-lib` library for FIDO2 operations and manages user credentials via helper functions.
 * 
 * Exports:
 * - registerBeginWebAuthn: Initiates WebAuthn registration for a user.
 * - registerFinishWebAuthn: Completes WebAuthn registration after receiving attestation response.
 * - authBeginWebAuthn: Initiates WebAuthn authentication for a user.
 * - authFinishWebAuthn: Completes WebAuthn authentication after receiving assertion response.
 */
const { register, getCredential } = require("./users");

const fido = require("fido2-lib");
const fido2lib = new fido.Fido2Lib({
  rpId: "idp.local",
  rpName: "IDP Local"
});

const {Base64} = require('js-base64');

/**
 * Initiates the WebAuthn registration process for a given username.
 * Generates attestation options and encodes the challenge in base64url.
 * 
 * @async
 * @param {string} username - The username for which to begin registration.
 * @returns {Promise<Object>} The attestation options to be sent to the client.
 */
async function registerBeginWebAuthn(username) {
  const pkcc = await fido2lib.attestationOptions();
  pkcc.user.id = pkcc.user.name = pkcc.user.displayName = username;
  pkcc.challenge = Base64.fromUint8Array(new Uint8Array(pkcc.challenge), true);
  return pkcc;
}

/**
 * Completes the WebAuthn registration process.
 * Verifies the attestation response and registers the credential for the user.
 * 
 * @async
 * @param {string} username - The username for which to finish registration.
 * @param {string} challenge - The original challenge sent to the client.
 * @param {Object} ccdata - The attestation response from the client.
 * @returns {Promise<boolean>} True if registration is successful, false otherwise.
 */
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

/**
 * Initiates the WebAuthn authentication process for a given username.
 * Generates assertion options and encodes the challenge in base64url.
 * 
 * @async
 * @param {string} username - The username for which to begin authentication.
 * @returns {Promise<Object>} The assertion options to be sent to the client.
 */
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

 
/**
 * Completes the WebAuthn authentication process.
 * Verifies the assertion response and updates the credential counter.
 * 
 * @async
 * @param {string} username - The username for which to finish authentication.
 * @param {string} challenge - The original challenge sent to the client.
 * @param {Object} crdata - The assertion response from the client.
 * @returns {Promise<boolean>} True if authentication is successful, false otherwise.
 */
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