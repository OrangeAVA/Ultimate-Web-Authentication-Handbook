# ==============================================================================
# Finance Service Provider (SP) with SAML2 Authentication - Flask Application
# ==============================================================================
# This Flask app implements a SAML2 Service Provider (SP) for a finance portal,
# enabling secure authentication and authorization via an external Identity
# Provider (IdP). It serves static frontend assets, exposes SAML endpoints,
# and provides user-specific finance data.
#
# Key Features and Components:
# ----------------------------
# - SSL/TLS Configuration:
#   Loads server and CA certificates for secure HTTPS communication.
# - SAML2 SP Configuration:
#   Loads and manages SAML2 metadata, keys, and certificates. Fetches IdP
#   metadata if not present locally. Generates and serves SP metadata for IdP.
# - Endpoints:
#   - /saml/metadata: Serves SP metadata XML for IdP consumption.
#   - /saml/acs: Assertion Consumer Service endpoint; processes SAML responses
#     from IdP, authenticates users, and stores user profile in session.
#   - /auth/login: Initiates SAML authentication by redirecting users to IdP.
#   - /auth/logout: Logs out the user by clearing the session. No SAML logout is
#     initiated.
#   - /auth/user: Returns info about the currently authenticated user.
#   - /users: Returns finance data. Admins see all users; regular users see
#     only their own data.
#   - / and /<path:path>: Serves static frontend files.
# - User Data Access:
#   User finance data is protected; access is determined by group membership
#   in the SAML assertion.
# - Security:
#   Private keys are decrypted at runtime for SAML operations. All sensitive
#   endpoints require valid SAML authentication.
# - Startup:
#   Runs the Flask app with SSL/TLS enabled, serving on port 8445.
#
# Intended Usage:
# ---------------
# This app is for environments requiring federated authentication (e.g.,
# enterprise finance portals) and demonstrates best practices for integrating
# SAML2 authentication in Python web applications. 
# 
# Authentication sessions are managed in the Flask session. We do not use the 
# WSGI interface for session management here. However, if you are interested in
# using the WSGI interface, refer to the PySAML2 examples: 
# https://github.com/IdentityPython/pysaml2/tree/master/example
# ==============================================================================

from flask import Flask, request, redirect, session, jsonify, send_from_directory
import requests
import os
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string
import sys

FRONTEND_STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'frontend'))
app = Flask(__name__, static_folder=FRONTEND_STATIC_DIR)
app.secret_key = os.environ.get('IDP_SECRET_KEY', 'change_this_secret')

# Update SSL certificate and key paths        
SSL_CERTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'certs', 'ssl'))
SSL_SERVER_CERT = os.path.join(SSL_CERTS_DIR, 'finance.mysrv.local.crt')
SSL_SERVER_KEY = os.path.join(SSL_CERTS_DIR, 'finance.mysrv.local.key')
SSL_CA_CERT = os.path.join(SSL_CERTS_DIR, 'scas.crt')

# Update certificate and key paths for SAML2 IdP
CERTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'certs'))
def decrypt_key(encrypted_key_path, password):
  fpath = os.path.join(CERTS_DIR, 'finance.dec.key')
  if not os.path.exists(fpath):
    with open(encrypted_key_path, 'rb') as f:
      encrypted_data = f.read()
    private_key = serialization.load_pem_private_key(
      encrypted_data,
      password=password.encode(),
      backend=default_backend()
    )
    with open(fpath, 'wb') as f:
      f.write(
        private_key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=serialization.NoEncryption()
        )
      )
  return fpath

SP_KEY = decrypt_key(os.path.join(CERTS_DIR, 'finance.key'), 'password')
SP_CERT = os.path.join(CERTS_DIR, 'finance.crt')
SP_CA_CERT = os.path.join(CERTS_DIR, 'finance.crt')

IDP_METADATA_URL = 'https://idp.local:8443/idp/metadata'
IDP_METADATA_PATH = os.path.join(os.path.dirname(__file__), 'idp.xml')

def get_sp_config():
  """
  Generates and returns the SAML metadata XML for the finance Service Provider.
  """
  if not os.path.exists(IDP_METADATA_PATH):
    try:
      response = requests.get(IDP_METADATA_URL, timeout=5, verify=SSL_CA_CERT)
      response.raise_for_status()
      with open(IDP_METADATA_PATH, 'w') as f:
        f.write(response.text)
    except Exception as e:
      print(f"Error fetching IdP metadata: {e}. Make sure the IdP is reachable.")
      sys.exit(1)
  sp_config = {
    "logging": {
      "version": 1,
      "formatters": {
        "simple": {
          "format": "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s] %(message)s",
        },
      },
      "handlers": {
        "stdout": {
          "class": "logging.StreamHandler",
          "stream": "ext://sys.stdout",
          "level": "DEBUG",
          "formatter": "simple",
        },
      },
      "loggers": {
        "saml2": {
          "level": "DEBUG"
        },
      },
      "root": {
        "level": "DEBUG",
        "handlers": [
          "stdout",
        ],
      },
    },
    'entityid': 'https://finance.mysrv.local:8445/saml',
    'description': 'Finance Service Provider',
    'service': {
      'sp': {
        'endpoints': {
          'assertion_consumer_service': [
            ('https://finance.mysrv.local:8445/saml/acs', BINDING_HTTP_POST),
          ]
        },
        'allow_unsolicited': True,
        'authn_requests_signed': True,
        'want_response_signed': True,
      }
    },
    'metadata': {
      'local': [
        IDP_METADATA_PATH
      ]
    },
    'allow_unknown_attributes': True,
    'key_file': SP_KEY,
    'cert_file': SP_CERT,
    'ca_certs': SP_CA_CERT,
    'xmlsec_path': 'xmlsec1',
    'debug': 1,
  }
  return SPConfig().load(sp_config)

sp = Saml2Client(config=get_sp_config())
# Generate SP metadata XML for idpportal and store in finance.xml
SP_METADATA_PATH = os.path.join(os.path.dirname(__file__), 'finance.xml')
if not os.path.exists(SP_METADATA_PATH):
  sp_metadata_bytes = create_metadata_string(None, sp.config)
  with open(SP_METADATA_PATH, 'wb') as f:
    f.write(sp_metadata_bytes)

# --- SAML endpoints ---

@app.route('/saml/metadata', methods=['GET'])
def saml_metadata():
  # Return SP metadata XML
  with open(SP_METADATA_PATH, 'r') as f:
    metadata_str = f.read()
  return metadata_str, 200, {'Content-Type': 'application/xml'}

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
  # Parse and verify SAML response
  saml_response = request.form.get('SAMLResponse')
  if not saml_response:
    return jsonify({'error': 'Missing SAMLResponse'}), 400
  try:
    # Decode and parse the SAML response
    authn_response = sp.parse_authn_request_response(
      saml_response,
      BINDING_HTTP_POST
    )
    # Log if in_response_to is missing (IdP-initiated SSO)
    if not getattr(authn_response, 'in_response_to', None):
      app.logger.info("IdP-initiated authentication detected: no in_response_to in SAML response.")
    # Extract user info from the assertion
    if authn_response and authn_response.ava:
      session['user_profile'] = authn_response.ava
      return redirect('/')
    else:
      return jsonify({'error': 'Invalid SAML assertion'}), 401
  except Exception as e:
    return jsonify({'error': str(e)}), 400

@app.route('/auth/login', methods=['GET'])
def auth_login():
  # Initiate SAML login flow
  # Create SAML AuthnRequest using sp
  reqid, info = sp.prepare_for_authenticate(
    binding=BINDING_HTTP_REDIRECT,
    nameid_format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
  )
  # Redirect user to IdP SSO URL with SAMLRequest
  url = info['headers'][0][1]
  return redirect(url)

@app.route('/auth/logout', methods=['GET'])
def auth_logout():
  """Logs out the current user by destroying their session."""
  session.clear()
  return redirect('/')

@app.route('/auth/user', methods=['GET'])
def auth_user():
  """Returns information about the currently authenticated user."""
  user = session.get('user_profile')
  if not user:
    return "Unauthorized", 401
  return jsonify({'user': user['displayName']})

USERS = {
  "alice": { 
    "id": "alice", 
    "salary":1000 
  },
  "bob":   { 
    "id": "bob",   
    "salary":2000
  },
  "carol": { 
    "id": "carol", 
    "salary":3000, 
  },
  "don":   { 
    "id": "don",   
    "salary":4000,
  }
};

@app.route('/users', methods=['GET'])
def users():
  """Returns user data. Admins see all users; regular users see only their own data."""
  user = session.get('user_profile')
  if not user:
    return "Unauthorized", 401
  user_id = user.get('uid')
  user_info = USERS.get(user_id[0])
  if not user_info:
    return jsonify({'error': 'User not found'}), 404

  # Check if user is in admin groups
  groups = user.get('groups', [])
  if 'financeadmin' in groups:
    users_data = list(USERS.values())
  else:
    users_data = [user_info]
  return jsonify(users_data)

@app.route('/', methods=['GET'])
def serve_index():
  return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>', methods=['GET'])
def serve_frontend(path):
    # Serve static frontend assets
    return send_from_directory(app.static_folder, path)

# Combine server cert and intermediate CA into a chain file
SSL_CHAIN_CERT = os.path.join(SSL_CERTS_DIR, 'finance.mysrv.local.chain.crt')
if not os.path.exists(SSL_CHAIN_CERT):
  with open(SSL_CHAIN_CERT, 'w') as chain:
    with open(SSL_SERVER_CERT, 'r') as sc:
      chain.write(sc.read())
    with open(SSL_CA_CERT, 'r') as ca:
      chain.write('\n')
      chain.write(ca.read())
      
if __name__ == '__main__':
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain(SSL_CHAIN_CERT, SSL_SERVER_KEY, password="password")
  app.run(host='0.0.0.0', port=8445, ssl_context=context)