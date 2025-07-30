/**
 * @file users.js
 * @description
 * This module provides a simple in-memory user store and credential management for authentication purposes.
 * It supports password, OTP (One-Time Password), and WebAuthn credentials.
 * 
 * Features:
 * - Defines a set of sample users with basic profile information and group memberships.
 * - Stores hashed passwords and other credentials in a shadow object.
 * - Provides functions to validate credentials, register new credentials, and check credential existence.
 * - Implements a findAccount function for integration with authentication frameworks (e.g., OpenID Connect).
 * - Integrates with the 'bcrypt' library for password hashing and 'otplib' for OTP generation and validation.
 * 
 * Exported functions:
 * - findAccount: Retrieves user account information and claims.
 * - register: Registers OTP or WebAuthn credentials for a user.
 * - validate: Validates password, OTP, or WebAuthn credentials.
 * - hasCredential: Checks if a user has a specific type of credential.
 * - generateSecret: Generates a secret for OTP registration.
 */
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

const bcrypt = require("bcrypt");
const defaultPassword = "password";
const saltRounds = 10;

const shadow = {};

for (const username of Object.keys(users)) {
  const hash = bcrypt.hashSync(defaultPassword, saltRounds);
  shadow[username] = { password: hash };
}

const otplib = require('otplib');
const auth = otplib.authenticator;

async function validate(type, username, data) {
  const user = users[username];
  if (!user) return false;
  const cred = shadow[username];
  if (!cred) return false;
  switch (type) {
    case "password": 
      return await bcrypt.compare(data, cred.password);
    case "otp":
      return auth.verify({token: data, secret: cred.otp, window: 3});
    case "webauthn": {
      return !!cred.webauthn;
    }
    default:
      return false;
  }
}

function register(type, username, data) {
  if (!users[username]) return false;
  if (!shadow[username]) shadow[username] = {};
  switch (type) {
    case "otp":
      if (auth.verify({...data, window: 3})) {
        shadow[username].otp = data.secret;
        return true;
      }
      break
    case "webauthn":
      shadow[username].webauthn = data;
      return true;
    default:
      return false;
  }
  return false;
}

function hasCredential(type, username) {
  if (!username || !shadow[username]) return false;
  switch (type) {
    case "password":
      return !!shadow[username].password;
    case "otp":
      return !!shadow[username].otp;
    case "webauthn":
      return !!shadow[username].webauthn;
    default:
      return false;
  }
}

function getCredential(type, username) {
  if (!username || !shadow[username]) return null;
  switch (type) {
    case "password":
      return shadow[username].password;
    case "otp":
      return shadow[username].otp;
    case "webauthn":
      return shadow[username].webauthn || [];
    default:
      return null;
  }
}

/**
 * Finds a user account by identifier.
 * Exported from the users module.
 * @function
 * @param {string} accountId - The account identifier.
 * @returns {Promise<Object|null>} The account object or null if not found.
 */
async function findAccount(_ctx, id) {
  const user = users[id];
  if (!user) return undefined;
  return {
    accountId: id,
    async claims() {
      return {
        sub: id,
        name: user.displayName,
        email: user.emails[0].value,
        groups: user.groups
      };
    }
  };
}

const hotp = otplib.hotp;
function generateSecret() {
  return auth.generateSecret();
}

module.exports = {
  findAccount,
  register,
  validate,
  hasCredential,
  getCredential,
  generateSecret
};