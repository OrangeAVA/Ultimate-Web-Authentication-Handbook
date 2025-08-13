"""
@fileoverview
Flask server demonstrating basic authentication, cookie-based visit counting, and session management.

This module sets up a Flask server with several routes:
- `/hello`: Returns a simple "Hello, World!" message.
- `/count`: Tracks the number of visits using a cookie named 'count'.
- `/session`: Tracks the number of visits per session using a session cookie and an in-memory map.
- `/basicauth`: Implements HTTP Basic Authentication for the user 'jdoe' with password 'password'.

Endpoints:
  /hello
    Responds with "Hello, World!".

  /count
    Increments and returns the visit count using a cookie named 'count'.

  /session
    Increments and returns the visit count per session using a session cookie and a server-side map.

  /basicauth
    Implements HTTP Basic Authentication. Only authenticates user 'jdoe' with password 'password'.

Server:
  Listens on port 8080.
"""

import base64
import uuid
from flask import Flask, request, make_response, session, redirect

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# In-memory session visit count map
session_visits = {}

USERNAME = 'jdoe'
PASSWORD = 'password'

def check_auth(auth_header):
  if not auth_header or not auth_header.startswith('Basic '):
    return False
  try:
    encoded = auth_header.split(' ', 1)[1]
    decoded = base64.b64decode(encoded).decode('utf-8')
    username, password = decoded.split(':', 1)
    return username == USERNAME and password == PASSWORD
  except Exception:
    return False

def require_basic_auth(view_func):
  def wrapper(*args, **kwargs):
    auth = request.headers.get('Authorization')
    if not check_auth(auth):
      resp = make_response('Unauthorized', 401)
      resp.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
      return resp
    return view_func(*args, **kwargs)
  wrapper.__name__ = view_func.__name__
  return wrapper

@app.route('/hello')
def hello():
  return 'Hello, World!'

@app.route('/count')
def count():
  count = int(request.cookies.get('count', 0)) + 1
  resp = make_response(f'Visit count: {count}')
  resp.set_cookie('count', str(count), httponly=True)
  return resp

@app.route('/session')
def session_count():
  sid = session.get('sid')
  if not sid:
    sid = str(uuid.uuid4())
    session['sid'] = sid
  session_visits[sid] = session_visits.get(sid, 0) + 1
  return f'Session visit count: {session_visits[sid]}'

@app.route('/basicauth')
@require_basic_auth
def basicauth():
  return 'You are authenticated as jdoe.'

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080, debug=True)
