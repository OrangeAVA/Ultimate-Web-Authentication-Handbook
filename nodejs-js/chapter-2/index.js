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