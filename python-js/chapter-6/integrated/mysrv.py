from flask import Flask, session, redirect, url_for, request, send_from_directory, jsonify
from flask_session import Session
import os
import ssl
import requests
import secrets
import string
import base64
import hashlib
import urllib.parse

app = Flask(__name__, static_folder='frontend')
app.secret_key = os.environ.get('SECRET_KEY', 'change_this_secret')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 7200  # 2 hours
Session(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Update SSL certificate and key paths
SSL_CERTS_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'certs'))
SERVER_ROOT = os.path.abspath(os.path.join(SSL_CERTS_DIR, 'sroot.crt'))

# OpenID Connect configuration
OIDC_ISSUER = 'https://idp.local:8443/oidc'
OIDC_CLIENT_ID = '580120' # Replace with your actual client ID
OIDC_REDIRECT_URI = 'https://mysrv.local:8444/oauth/callback'
OIDC_LOGOUT_REDIRECT_URI = 'https://mysrv.local:8444/oauth/callback/logout'

# Discover endpoints
def get_metadata():
  resp = requests.get(f'{OIDC_ISSUER}/.well-known/openid-configuration', verify=SERVER_ROOT)
  resp.raise_for_status()
  return resp.json()

metadata = get_metadata()
AUTHORIZATION_ENDPOINT = metadata['authorization_endpoint']
TOKEN_ENDPOINT = metadata['token_endpoint']
USERINFO_ENDPOINT = metadata['userinfo_endpoint']
END_SESSION_ENDPOINT = metadata.get('end_session_endpoint')

def generate_code_verifier():
  return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(verifier):
  digest = hashlib.sha256(verifier.encode('utf-8')).digest()
  return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')

@app.route('/')
def serve_index():
  return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
  return send_from_directory(app.static_folder, filename)

@app.route('/oauth/login')
def oauth_login():
  code_verifier = generate_code_verifier()
  code_challenge = generate_code_challenge(code_verifier)
  session['code_verifier'] = code_verifier
  params = {
    'response_type': 'code',
    'client_id': OIDC_CLIENT_ID,
    'redirect_uri': OIDC_REDIRECT_URI,
    'scope': 'openid profile email',
    'code_challenge': code_challenge,
    'code_challenge_method': 'S256'
  }
  url = AUTHORIZATION_ENDPOINT + '?' + urllib.parse.urlencode(params)
  return redirect(url)

@app.route('/oauth/callback')
def oauth_callback():
  code = request.args.get('code')
  code_verifier = session.get('code_verifier')
  if not code or not code_verifier:
    return redirect('/')
  data = {
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': OIDC_REDIRECT_URI,
    'client_id': OIDC_CLIENT_ID,
    'code_verifier': code_verifier
  }
  resp = requests.post(TOKEN_ENDPOINT, data=data, verify=SERVER_ROOT)
  if resp.status_code != 200:
    return jsonify({'error': 'Token exchange failed'}), 400
  token = resp.json()
  session['token'] = token
  # Get userinfo
  headers = {'Authorization': f"Bearer {token['access_token']}"}
  userinfo_resp = requests.get(USERINFO_ENDPOINT, headers=headers, verify=SERVER_ROOT)
  if userinfo_resp.status_code == 200:
    session['user'] = userinfo_resp.json()
  else:
    session['user'] = {}
  return redirect('/')

@app.route('/oauth/logout')
def oauth_logout():
  id_token = session.get('token', {}).get('id_token')
  if not id_token or not END_SESSION_ENDPOINT:
    session.clear()
    return redirect('/')
  params = {
    'id_token_hint': id_token,
    'post_logout_redirect_uri': OIDC_LOGOUT_REDIRECT_URI
  }
  session.clear()
  url = END_SESSION_ENDPOINT + '?' + urllib.parse.urlencode(params)
  return redirect(url)

@app.route('/oauth/callback/logout')
def oauth_callback_logout():
  return redirect('/')

@app.route('/userinfo')
def userinfo():
  token = session.get('token')
  if not token:
    return jsonify({'error': 'Not authenticated'}), 401
  headers = {'Authorization': f"Bearer {token['access_token']}"}
  resp = requests.get(USERINFO_ENDPOINT, headers=headers, verify=SERVER_ROOT)
  if resp.status_code == 200:
    return jsonify(resp.json())
  return jsonify({'error': 'Failed to fetch userinfo'}), 400

SSL_CERT = os.path.join(SSL_CERTS_DIR, 'mysrv.local.crt')
SSL_KEY = os.path.join(SSL_CERTS_DIR, 'mysrv.local.key')

CHAIN_CERT = os.path.join(SSL_CERTS_DIR, 'mysrv.local.chain.crt')
SSL_CA_CERTS = [
  os.path.join(SSL_CERTS_DIR, 'sint.crt')
]
if not os.path.exists(CHAIN_CERT):
  with open(CHAIN_CERT, 'w') as chain:
    # Write server cert
    with open(SSL_CERT, 'r') as sc:
      chain.write(sc.read())
      chain.write('\n')
    # Write intermediate and root certs
    for ca_cert in SSL_CA_CERTS:
      with open(ca_cert, 'r') as ca:
        chain.write(ca.read())
        chain.write('\n')

if __name__ == '__main__':
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain(CHAIN_CERT, SSL_KEY, password='password')
  app.run(host='0.0.0.0', port=8444, ssl_context=context)