## Differences from the [nodejs-js](../nodejs-js) samples

Welcome to our Python and JavaScript sample projects. Below are key changes
and differences compared to the [nodejs-js](../nodejs-js) samples:

1. We use simple HTML and JavaScript, without frameworks. The JS files are
  linked from the [nodejs-js](../nodejs-js/) samples.
2. Appendices A and B are not included, as they are not relevant to Node.js or
  JavaScript development.
3. We use Python-based command-line clients instead of native apps:
  - Chapter 5 – GitHub device binding
  - Chapter 5 – PKCE client
4. We closely map `python-js` to `nodejs-js`, but some libraries provide extra
  features:
  - **Session Management:** We use `Flask` and its default session management
    in most examples, instead of custom session implementations.
  - **SAML [Chapter 4](chapter-4):** The `pysamlv2` SAML library offers an
    extensive Single Logout (SLO) framework. Our sample demonstrates several
    use cases for these capabilities.
