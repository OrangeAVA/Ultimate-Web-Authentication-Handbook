/**
 * @file interaction.js
 * @module interaction
 * @description
 * This module defines the interaction policy and interaction routes for an OIDC provider.
 * It handles multi-step authentication flows including username, password, OTP, and WebAuthn,
 * as well as registration for OTP and WebAuthn credentials. The module also manages consent
 * interactions and integrates with user credential validation and registration logic.
 *
 * @requires oidc-provider
 * @requires ./users
 * @requires fs
 * @requires path
 * @requires body-parser
 *
 * @exports setupInteractionPolicy
 * @exports setupInteractions
 * @exports findAccount
 */
const { interactionPolicy } = require("oidc-provider");
const { hasCredential, validate, register, findAccount, generateSecret } = require("./users");
const fs = require('node:fs');
const path = require('node:path');
const { Prompt, Check, base } = interactionPolicy;
const {urlencoded} = require("body-parser");

/**
 * Sets up the interaction policy for the OIDC provider.
 * Defines prompts and checks for username, password, OTP, and WebAuthn authentication steps.
 * @function
 * @returns {interactionPolicy.Policy} The configured interaction policy.
 */
function setupInteractionPolicy() {
  const policy = base();

  policy.add(
    new Prompt(
      { name: 'username', requestable: true },
      new Check('username', 'missing username', ctx => !ctx.oidc.session?.accountId && !ctx.oidc.result?.username)
      ), 0
  );

  policy.add(
    new Prompt(
      { name: 'password', requestable: true },
      new Check('no_otp', 'no otp is registered', ctx =>
        !ctx.oidc.session?.accountId && !ctx.oidc.result.password && !hasCredential('otp', ctx.oidc.result?.username)
      ),
      new Check('no_webauthn', 'no webauthn token is registered', ctx =>
        !ctx.oidc.session?.accountId && !ctx.oidc.result.password && !hasCredential('webauthn',  ctx.oidc.result?.username)
      )
    ), 1
  );

  policy.add(
    new Prompt(
      { name: 'otp', requestable: true }, 
      new Check('invalid_otp', 'missing or invalid otp', 
        ctx => !ctx.oidc.session?.accountId && !ctx.oidc.result.otp && hasCredential('otp',  ctx.oidc.result?.username)
      )
    ), 2
  );

  policy.add(
    new Prompt(
      { name: 'webauthn', requestable: true }, 
      new Check('invalid_webauthn', 'missing or invalid webauthn', 
        ctx => !ctx.oidc.session?.accountId && !ctx.oidc.result.webauthn && hasCredential('webauthn', ctx.oidc.result?.username)
      )
    ), 3
  );

  policy.add(
    new Prompt(
      { name: 'otp_reg', requestable: true }, ctx => { 
        return { 
          secret: generateSecret(),
          username: ctx.oidc.session.accountId, 
        };
      },
      new Check('authenticated', 'user is authenticated', 
        ctx => ctx.oidc.session?.accountId && !ctx.oidc.result.otp_reg?.skipped &&!hasCredential('otp', ctx.oidc.session.accountId)
      )
    ), 5
  );
/*
  policy.add(
    new Prompt(
      { name: 'webauthn_reg', requestable: true }, 
      new Check('authenticated', 'user is authenticated', 
        ctx => ctx.oidc.result.login?.accountId && !hasCredential('webauthn', ctx.oidc.result.username)
      )
    ), 6
  );
*/
  return policy;
}


/**
 * Sets up Express routes for handling OIDC interactions.
 * Handles GET and POST requests for interaction prompts, abort, and skip actions.
 * Processes user input for authentication and registration steps, and manages consent grants.
 * @function
 * @param {Provider} provider - The OIDC provider instance.
 * @param {Express.Application} app - The Express application instance.
 */
function setupInteractions(provider, app) {
  app.get('/interaction/:uid', async (req, res) => {
    const interactionDetails = await provider.interactionDetails(req, res);
    const {uid, prompt, params, session, lastSubmission} = interactionDetails;
    const viewFilePath = path.join(__dirname, 'views', `${prompt.name}.html`);
    if (!fs.existsSync(viewFilePath)) {
      return res.status(404).send('Interaction view not found');
    } else {
      let data = fs.readFileSync(viewFilePath, 'utf8');
      data = data.replace('<UID>', `${uid}`);
      if (prompt.name === 'otp_reg' || prompt.name === 'webauthn_reg') {
        data = data.replace('{RESULT}', JSON.stringify(prompt.details || {}));
      } else if (prompt.name === 'consent') {
        const client = await provider.Client.find(params.client_id);
        const scopes = JSON.stringify(params.scope.split(' '));
        data = data.replace('{RESULT}', `{
          clientName: \'${client.clientName}\',
          clientUri: \'${client.clientUri}\',
          scopes: ${scopes},
          username: \'${lastSubmission.username}\'
        }`);
      } else {
        data = data.replace('{RESULT}', JSON.stringify(lastSubmission||{}));
      }
      res.setHeader('Content-Type', 'text/html');
      return res.send(data);
    }
  });

  app.get('/interaction/:uid/abort', async (req, res) => {
    return provider.interactionFinished(req, res, {
        error: 'access_denied',
        error_description: 'End-User aborted interaction',
      },
      { mergeWithLastSubmission: false }
    );
  });

  app.get('/interaction/:uid/skip', async (req, res) => {
    const {prompt} = await provider.interactionDetails(req, res);
    return provider.interactionFinished(req, res, {
      [prompt.name]: {skipped: true}}, 
      {mergeWithLastSubmission: true}
    );  
  });

  app.post('/interaction/:uid', urlencoded({ extended: false }), async (req, res) => {
    const { uid } = req.params;
    const interactionDetails = await provider.interactionDetails(req, res);
    const { prompt, params, session, grantId, lastSubmission } = interactionDetails;
    let result; 
    let merge = true;
    switch (prompt.name) {
      case 'username': {
        const { username } = req.body;
        if (!username) {
          return res.status(400).send('Username is required');
        } else {
          result = { username };
          merge = true;
        }
        break
      }
      case 'password': {
        const { password } = req.body;
        if (!password) {
          return res.status(400).send('Password is required');
        } else { 
          passed = await validate('password', lastSubmission.username, password);
          result = { password: passed };
        }
        break;
      }
      case 'otp': {
        const { otp } = req.body;
        if (!otp) {
          return res.status(400).send('OTP is required');
        } else {
          passed = await validate('otp', lastSubmission.username, otp);
          result = { otp: passed };
        }
        break;
      }
      case 'webauthn': {
        const { webauthn } = req.body;
        if (!webauthn) {
          return res.status(400).send('WebAuthn token is required');
        } else {
          passed = await validate('webauthn', lastSubmission.username, webauthn);
          result = { webauthn: passed };
        }
        break;
      }
      case 'login': {
        if (lastSubmission.password) {
          const scopes = params.scope.split(' ');
          result = { 
            login: { 
              accountId: lastSubmission.username     
            } 
          };
        } else {
            return res.status(400).send('Invalid login or password');
        }
        break;
      }
      case 'otp_reg': {
        const { otp, secret } = req.body;
        if (!otp || !secret) {
          return res.status(400).send('OTP and secret are required for registration');
        } else {
          register('otp', lastSubmission.username, {token: otp, secret});
          result = {};
        }
        break;
      }
      case 'webauthn_reg': {
        //const { webauthn } = req.body;
        webauthn = true;
        if (!webauthn) {
          return res.status(400).send('WebAuthn token is required for registration');
        } else {
          const registered = register('webauthn', lastSubmission.username, webauthn);
          if (registered) {
            result = { webauthn_reg: true };
          } else {
            return res.status(400).send('Failed to register WebAuthn token');
          }
        }
        break;
      }
      case 'consent': {
        let grant;
        if (grantId) {
          // we'll be modifying existing grant in existing session
          grant = await provider.Grant.find(grantId);
        } else {
          // we're establishing a new grant
          grant = new provider.Grant({
            accountId: session.accountId,
            clientId: params.client_id,
          });
        }
        const details = prompt.details || {};
        if (details.missingOIDCScope) {
          grant.addOIDCScope(details.missingOIDCScope.join(' '));
        }
        if (details.missingOIDCClaims) {
          grant.addOIDCClaims(details.missingOIDCClaims);
        }
        if (details.missingResourceScopes) {
          for (const [indicator, scope] of Object.entries(details.missingResourceScopes)) {
            grant.addResourceScope(indicator, scope.join(' '));
          }
        }
        result = { consent: { grantId: await grant.save()}};
        break;
      }
      default: 
        return res.status(501).send('Interaction not implemented');
    }
    await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: merge });
  });
}

module.exports = { setupInteractionPolicy, setupInteractions, findAccount };