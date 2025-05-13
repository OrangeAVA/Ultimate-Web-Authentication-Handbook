const oclient = require("openid-client");
const cid = process.env.GH_CLIENT_ID;
console.log(cid);

async function doDeviceWorkflow() {
  const config = new oclient.Configuration({
    issuer: "https://github.com",
    authorization_endpoint: "https://github.com/login/oauth/authorize",
    token_endpoint: "https://github.com/login/oauth/access_token",
    device_authorization_endpoint: "https://github.com/login/device/code"
  }, cid); 
  const scope = ["user"];

  const dares =
    await oclient.initiateDeviceAuthorization(config, { scope });
  console.log(`Go to the URL: ${dares.verification_uri}`);
  console.log(`Enter the device code: ${dares.user_code}`);
  console.log(`Expires in secs: ${dares.expires_in}`);
  console.log(`Try interval in secs: ${dares.interval}`);

  // This code seems to be failing for no apparent reason. 
  // We will run our own polling loop for now. 
  // const tokenres = await oclient.pollDeviceAuthorizationGrant(config, dares, {scope});

  async function downloadToken(){
    const response = await fetch("https://github.com/login/oauth/access_token", {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: cid,
        device_code: dares.device_code,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code"
      }),
    });
    if (response.ok)
      return response.json();
    else
      throw new Error("failed to download token");
  }

  stime = new Date();
  var interval = dares.interval?? 5;

  var resv;

  (async function loop() {
    if((new Date() - stime) > dares.expires_in*1000) {
      console.log(`Device code expired. Exiting the loop.`); 
      return;
    }
    setTimeout(async () => {
      console.log(`Requesting token after ${interval} seconds`); 
      resv = await downloadToken();
      if (resv.error) {
        if (resv.error == "slow_down"){
          interval += 5; 
          await loop();
        } else if (resv.error == "authorization_pending"){
          await loop();
        } else {
          throw new Error(resv.error_description);
        }
      }
      if (resv.access_token){
        const resp = await oclient.fetchProtectedResource(config, resv.access_token, new URL("https://api.github.com/user"), "GET")
        console.log(await resp.json());
      }
    }, interval*1000);
  })().catch(async e => {
    console.log(e);
  });
}

doDeviceWorkflow();
