
/**
 * @fileoverview Express server implementing basic authentication using PBKDF2 password hashing.
 * 
 * This server reads user credentials from a JSON file ('password.json'), and exposes a single endpoint `/basicauth`
 * that requires HTTP Basic Authentication. Passwords are verified using PBKDF2 with a static salt and configuration.
 * 
 * Endpoints:
 * @endpoint GET /basicauth
 *   - Requires HTTP Basic Authentication header.
 *   - Verifies username and password against stored hash in 'password.json'.
 *   - Responds with 401 Unauthorized if authentication fails, or a success message if authenticated.
 * 
 * Usage:
 *   Start the server and access http://localhost:8080/basicauth with Basic Auth credentials.
 * 
 * Note:
 *   - Passwords are hashed using PBKDF2 with SHA-1, 4096 iterations, and a static salt ('12345678').
 *   - This implementation is for educational purposes and should not be used in production as-is.
 */
const express = require('express');
const app = express();
const crypto = require('crypto');
const fs = require('fs');
const data = fs.readFileSync('password.json', 'utf8');
const users = JSON.parse(data);

app.get('/basicauth', (req, res) => {
  const authheader = req.headers.authorization;
  console.log(req.headers);
  if (!authheader) {
    res
      .setHeader('WWW-Authenticate', 'Basic')
      .status(401)
      .send("User not authenticated");
    return;
  }

  const auth = new Buffer.from(authheader.split(' ')[1],'base64').toString().split(':');
  const user = auth[0];
  const pass = auth[1];

  if (user && pass) {
    console.log("user: %s password: %s", user, pass)
    const tkey = users[user];
    if (tkey){
      crypto.pbkdf2(pass, '12345678', 4096, 20, 'sha1', (err, key) => {
        const skey = Array.from(key).map((b) => b.toString(16).padStart(2, "0")).join("")
        if (err || skey != tkey){
          res
            .setHeader('WWW-Authenticate', 'Basic')
            .status(401)
            .send("User not authenticated");
        } else {
          res.send(`User ${user} authenticated successfully`);
        }
      });
    } 
  } else {
    res
      .setHeader('WWW-Authenticate', 'Basic')
      .status(401)
      .send("User not authenticated");
  }
});

app.listen(8080, () => console.log('Server running on http://localhost:8080'));