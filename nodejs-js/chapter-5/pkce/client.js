// Import required modules
const oclient = require("openid-client");
const openurl = require("openurl");
const readline = require("node:readline");
const jwt = require('jsonwebtoken');

// Main async function to handle the PKCE OAuth2 flow
async function main() {
  // Discover OIDC configuration from the identity provider
  const config = await oclient.discovery(new URL("https://idp.local:8443/oidc"), "222222");

  // Generate PKCE code verifier and challenge
  const code_verifier = oclient.randomPKCECodeVerifier();
  const code_challenge = await oclient.calculatePKCECodeChallenge(code_verifier);

  // Define OAuth2 parameters
  const redirect_uri = "https://mysrv.local:8444/";
  const scope = "openid";
  const sMetadata = config.serverMetadata();

  // Build the authorization URL and open it in the browser
  const redirectTo = oclient.buildAuthorizationUrl(config, {
    redirect_uri,
    scope,
    code_challenge,
    code_challenge_method: 'S256',
    grant_type: 'authorization_code',
    response_type: 'code',
  });
  console.log(`Login URL: ${redirectTo.href}`);
  openurl.open(redirectTo.href);

  // Prompt user to enter the authorization code from the redirect
  const code = await new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    rl.question("Enter the code received in the redirect: ", (input) => {
      resolve(input.trim());
      rl.close();
    });
  });

  // Exchange the authorization code for tokens
  const url = new URL(`${redirect_uri}?code=${code}&iss=${sMetadata.issuer}`);
  const tokens = await oclient.authorizationCodeGrant(
    config,
    url,
    { pkceCodeVerifier: code_verifier },
    { scope }
  );
  console.log("Tokens received:", tokens);

  // Decode and display the ID token
  const decoded = jwt.decode(tokens.id_token);
  console.log("Decoded ID Token:", decoded);

  // Fetch and display user info
  const userinfo = await oclient.fetchUserInfo(config, tokens.access_token, decoded.sub);
  console.log("User Info:", userinfo);

  // Periodically refresh the access token using the refresh token
  while (true) {
    const expiresIn = tokens.expires_in || 3600; // Default to 1 hour if not provided
    console.log(`Waiting for ${expiresIn} seconds before refreshing token...`);
    await new Promise(resolve => setTimeout(resolve, expiresIn * 1000));
    console.log("Refreshing token...");
    const refreshed = await oclient.refreshTokenGrant(config, tokens.refresh_token, { scope });
    console.log("Refreshed tokens:", refreshed);
    tokens.access_token = refreshed.access_token;
    tokens.id_token = refreshed.id_token;
    tokens.refresh_token = refreshed.refresh_token;
    tokens.expires_in = refreshed.expires_in;
  }
}

// Run the main function and handle errors
main().catch((e) => {
  console.error("Error:", e);
});
