# Flask app implementing GitHub OAuth2 Authorization Code flow for dev use.
# Requires GH_CLIENT_ID and GH_CLIENT_SECRET environment variables.
# Serves static frontend files and a simple index at '/'.
# /oauth/login redirects to GitHub authorize endpoint (scope: read:user).
# /oauth/callback exchanges the code for a JSON access token and stores
# it in an HttpOnly, Secure cookie named 'gh_access_token' (SameSite=Lax).
# /oauth/logout clears the access token cookie.
# /resource reads the cookie and calls GitHub's user API with the token.
# Builds a TLS chain by concatenating server cert and intermediate CA, then
# starts Flask on port 8443 with a TLS context using the chain file and key.
# Notes: short request timeouts, hard-coded redirect_uri and cert paths, and
# storing raw tokens in cookies is suitable only for demos, not production.

import os
import ssl
from flask import Flask, redirect, request, make_response, jsonify
import requests
from urllib.parse import urlencode

app = Flask(__name__)

# Configuration
GH_CLIENT_ID = os.environ.get('GH_CLIENT_ID')
GH_CLIENT_SECRET = os.environ.get('GH_CLIENT_SECRET')

if not GH_CLIENT_ID or not GH_CLIENT_SECRET:
  raise SystemExit("GH_CLIENT_ID and GH_CLIENT_SECRET environment variables must be set and non-blank.")

GH_AUTH_URL = "https://github.com/login/oauth/authorize"
GH_TOKEN_URL = "https://github.com/login/oauth/access_token"
GH_USER_API = "https://api.github.com/user"
REDIRECT_URI = "https://mysrv.local:8443/oauth/callback"
COOKIE_NAME = "gh_access_token"

# Endpoints

app.static_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), 'frontend'))

@app.route('/hello')
def hello():
  return "Hello, World!"

@app.route('/')
def index():
  return app.send_static_file('index.html'), 200

@app.route('/<path:filename>')
def static_files(filename):
  return app.send_static_file(filename), 200

@app.route('/oauth/login')
def oauth_login():
  params = {
    "client_id": GH_CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "scope": "read:user",
    "response_type": "code"
  }
  url = f"{GH_AUTH_URL}?{urlencode(params)}"
  return redirect(url)

@app.route('/oauth/logout')
def oauth_logout():
  resp = make_response(redirect('/'))
  resp.set_cookie(COOKIE_NAME, '', expires=0, httponly=True, secure=True, samesite='Lax')
  return resp

@app.route('/oauth/callback')
def oauth_callback():
  code = request.args.get('code')
  if not code:
    return "Missing code", 400

  data = {
    "client_id": GH_CLIENT_ID,
    "client_secret": GH_CLIENT_SECRET,
    "code": code,
    "redirect_uri": REDIRECT_URI
  }
  headers = {'Accept': 'application/json'}
  token_resp = requests.post(GH_TOKEN_URL, data=data, headers=headers, timeout=10)
  token_json = token_resp.json()
  access_token = token_json.get('access_token')
  if not access_token:
    return "Failed to obtain access token", 400

  resp = make_response(redirect('/'))
  resp.set_cookie(COOKIE_NAME, access_token, httponly=True, secure=True, samesite='Lax')
  return resp

@app.route('/resource')
def resource():
  access_token = request.cookies.get(COOKIE_NAME)
  if not access_token:
    return jsonify({"error": "Unauthorized"}), 401

  headers = {
    "Authorization": f"token {access_token}",
    "Accept": "application/json"
  }
  user_resp = requests.get(GH_USER_API, headers=headers, timeout=10)
  if user_resp.status_code != 200:
    return jsonify({"error": "Failed to fetch user info"}), 400
  return jsonify(user_resp.json())

# Update SSL certificate and key paths        
CERTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'certs'))
SERVER_CERT = os.path.join(CERTS_DIR, 'mysrv.local.crt')
SERVER_KEY = os.path.join(CERTS_DIR, 'mysrv.local.key')
CA_CERT = os.path.join(CERTS_DIR, 'sint.crt')

# Combine server cert and intermediate CA into a chain file
CHAIN_CERT = os.path.join(CERTS_DIR, 'mysrv.local.chain.crt')
if not os.path.exists(CHAIN_CERT):
  with open(CHAIN_CERT, 'w') as chain:
    with open(SERVER_CERT, 'r') as sc:
      chain.write(sc.read())
    with open(CA_CERT, 'r') as ca:
      chain.write('\n')
      chain.write(ca.read())
      
if __name__ == '__main__':
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain(CHAIN_CERT, SERVER_KEY, password="password")
  app.run(host='0.0.0.0', port=8443, ssl_context=context)