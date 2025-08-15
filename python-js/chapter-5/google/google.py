import os
import requests
from flask import Flask, redirect, request, session, url_for, send_from_directory, jsonify
from urllib.parse import urlencode
import jwt 

app = Flask(__name__, static_folder='frontend')
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')

GOOGLE_CLIENT_ID = os.environ['GOOGLE_CLIENT_ID']
GOOGLE_CLIENT_SECRET = os.environ['GOOGLE_CLIENT_SECRET']
GOOGLE_AUTH_URI = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URI = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_URI = 'https://openidconnect.googleapis.com/v1/userinfo'
REDIRECT_URI = 'http://localhost:8444/oauth/callback'
SCOPES = ['openid', 'email', 'profile']

@app.route('/oauth/login')
def oauth_login():
  params = {
    'client_id': GOOGLE_CLIENT_ID,
    'redirect_uri': REDIRECT_URI,
    'response_type': 'code',
    'scope': ' '.join(SCOPES),
    'access_type': 'offline',
    'prompt': 'consent'
  }
  return redirect(f"{GOOGLE_AUTH_URI}?{urlencode(params)}")

@app.route('/oauth/callback')
def oauth_callback():
  code = request.args.get('code')
  if not code:
    return 'Missing code', 400
  data = {
    'code': code,
    'client_id': GOOGLE_CLIENT_ID,
    'client_secret': GOOGLE_CLIENT_SECRET,
    'redirect_uri': REDIRECT_URI,
    'grant_type': 'authorization_code'
  }
  resp = requests.post(GOOGLE_TOKEN_URI, data=data)
  if resp.status_code != 200:
    return 'Token exchange failed', 400
  tokens = resp.json()
  session['tokens'] = tokens
  return redirect('/')

@app.route('/oauth/logout')
def oauth_logout():
  session.clear()
  return redirect('/')

def is_authenticated():
  return 'tokens' in session and 'access_token' in session['tokens']

@app.route('/userinfo')
def userinfo():
  if not is_authenticated():
    return jsonify({'error': 'Unauthorized'}), 401
  headers = {'Authorization': f"Bearer {session['tokens']['access_token']}"}
  resp = requests.get(GOOGLE_USERINFO_URI, headers=headers)
  if resp.status_code != 200:
    return jsonify({'error': 'Failed to fetch userinfo'}), 400
  return jsonify(resp.json())

@app.route('/idtoken')
def idtoken():
  if not is_authenticated():
    return jsonify({'error': 'Unauthorized'}), 401
  id_token = session['tokens'].get('id_token')
  if not id_token:
    return jsonify({'error': 'No ID token'}), 400
  decoded = jwt.decode(id_token, options={"verify_signature": False})
  return jsonify(decoded)

@app.route('/<path:path>')
def serve_frontend(path):
  return send_from_directory(app.static_folder, path)

@app.route('/')
def index():
  return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
  app.run(host='localhost', port=8444, debug=True)