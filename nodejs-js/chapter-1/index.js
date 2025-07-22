/**
 * @fileoverview Express server demonstrating basic authentication, cookie-based visit counting, and session management.
 *
 * @module index
 *
 * @description
 * This file sets up an Express server with several routes:
 * - `/hello`: Returns a simple "Hello, World!" message.
 * - `/count`: Tracks the number of visits using a cookie named 'count'.
 * - `/session`: Tracks the number of visits per session using a session cookie and an in-memory map.
 * - `/basicauth`: Implements HTTP Basic Authentication for the user 'jdoe' with password 'password'.
 *
 * @endpoint
 * @function /hello
 * @description Responds with "Hello, World!".
 *
 * @endpoint
 * @function /count
 * @description Increments and returns the visit count using a cookie named 'count'.
 *
 * @endpoint
 * @function /session
 * @description Increments and returns the visit count per session using a session cookie and a server-side map.
 *
 * @endpoint
 * @function /basicauth
 * @description Implements HTTP Basic Authentication. Only authenticates user 'jdoe' with password 'password'.
 *
 * @listens 8080
 * @description Starts the server on port 8080.
 */
const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();

app.get('/hello', (req, res) => {
  res.send('Hello, World!');
});

app.use(cookieParser());
app.get('/count', (req, res) => {
  if (req.cookies.count) {
    count = parseInt(req.cookies.count)+1
  } else {
    count = 1
  }
  res.cookie('count', count, { httpOnly: true });
  res.send(`You have visited: ${count} times.`);
});

const { v4: uuidv4 } = require('uuid');
const cmap = new Map()
app.get('/session', (req, res) => {
  sess = "";
  count = 1;
  if (req.cookies.session) {
    sess = req.cookies.session;
    acount = cmap.get(sess);
    if (acount){
      count = parseInt(acount)+1;
    }
  } else {
    sess = uuidv4();
  }
  cmap.set(sess, count);
  res.cookie('session', sess, { httpOnly: true });
  res.send(`You have visited: ${count} times.`);
});

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

  if (user == 'jdoe' && pass == 'password') {
    res.send(`User ${user} authenticated successfully`);
  } else {
    res
      .setHeader('WWW-Authenticate', 'Basic')
      .status(401)
      .send("User not authenticated");
  }
});

app.listen(8080, () => console.log('Server running on http://localhost:8080'));