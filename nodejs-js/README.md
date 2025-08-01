## Differences from the (go-flutter)[../go-flutter] samples.
Welcome to our Node.js and JavaScript sample projects. Below are some key changes
and differences compared to the (go-flutter)[../go-flutter] samples:

1. We use simple HTML and JavaScript without any specific frameworks.
2. Appendices A and B are not included, as they are not relevant to Node.js or
   JavaScript development.
3. We use Node.js-based command-line clients instead of developing native
   applications, such as:
   1. Chapter 5 – GitHub device binding
   2. Chapter 5 – PKCE client
4. While we aimed to closely map the functionality of the `nodejs-js` version to
   the `go-flutter` version, some libraries provided additional features that we
   chose to include. Notable examples include:
   1. Session Management: We use `express-session` in most examples instead of
      custom session implementations.
   2. SAML (Chapter 4): The `samlp` SAML library offers an extensive Single
      Logout (SLO) framework. Our sample demonstrates several use cases for these
      capabilities.
   3. OIDC Logout (Chapter 6): In the `integrated` demo, we use the
      `oidc-provider` library, which enables us to showcase the following
      additional features:
      1. Defining authentication policies using rules and prompts
      2. OIDC logout, allowing you to log in again and observe the effects of the
         policy