
# idp.py - SAML2 Identity Provider (IdP) and Service Provider (SP) Portal using Flask
#
# This file implements a SAML2 Identity Provider (IdP) and a Service Provider (SP) portal for authentication and
# single sign-on (SSO) using Flask. It provides endpoints for SAML metadata, authentication, logout, user management,
# and service administration. The IdP supports both SP-initiated and IdP-initiated SAML flows, manages user sessions,
# and handles SAML assertions and logout requests/responses.
#
# Endpoints:
# ----------
# /saml/metadata [GET]
#   Returns the SAML metadata XML for the SP portal.
# /saml/acs [POST]
#   Assertion Consumer Service endpoint. Receives and verifies SAML responses from the IdP.
# /saml/logout [GET]
#   Handles SAML logout requests and responses from the SP.
# /auth/login [GET]
#   Initiates SAML login flow for the SP portal.
# /auth/logout [GET]
#   Logs out the current user from the SP portal and sends a SAML logout request to the IdP.
# /auth/user [GET]
#   Returns information about the currently authenticated user.
# /admin/active-sessions [GET]
#   Lists active user sessions (not implemented).
# /admin/users [GET]
#   Returns user information. Only accessible to users in the 'itadmin' group.
# /admin/services [POST]
#   Fetches and parses SAML metadata for all configured services.
# /admin/shortcuts/<code> [GET]
#   Performs IdP-initiated SAML login for the service identified by <code>.
# /idp [GET, POST]
#   Main IdP endpoint. Handles SAML authentication requests and IdP-initiated logins.
# /idp/metadata [GET]
#   Returns the SAML metadata XML for the IdP.
# /idp/logout [GET]
#   Handles IdP-initiated logout for a specific service or SAML logout requests.
# / [GET]
#   Serves the index.html frontend page.
# /<path:path> [GET]
#   Serves static frontend assets.
#
# Other Features:
# ---------------
# - In-memory user database with password hashing.
# - SAML2 configuration for IdP and SP portal.
# - Fetches and manages SAML metadata for multiple services.
# - Tracks logged-in services per user session.
# - Handles SAML authentication and logout flows.
# - SSL/TLS configuration for secure communication.

from flask import Flask, g, request, jsonify, send_from_directory, redirect, session
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
import ssl

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.s_utils import deflate_and_base64_encode, decode_base64_and_inflate, success_status_factory
from saml2.config import IdPConfig
from saml2.server import Server
from saml2.metadata import create_metadata_string, entity_descriptor
from saml2.client import Saml2Client
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT
from saml2.population import Population

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from saml2.config import SPConfig
from bs4 import BeautifulSoup
import requests
from xml.etree import ElementTree as ET
from saml2.saml import NameID
import logging

# Update SSL certificate and key paths        
SSL_CERTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'certs', 'ssl'))
SSL_CERT = os.path.join(SSL_CERTS_DIR, 'idp.local.crt')
SSL_KEY = os.path.join(SSL_CERTS_DIR, 'idp.local.key')
SSL_CA_CERT = os.path.join(SSL_CERTS_DIR, 'scas.crt')

# Update certificate and key paths for SAML2 IdP
CERTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'certs'))
def decrypt_key(encrypted_key_path, password):
  fpath = os.path.join(CERTS_DIR, 'idp.dec.key')
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

IDP_KEY = decrypt_key(os.path.join(CERTS_DIR, 'idp.key'), 'password')
IDP_CERT = os.path.join(CERTS_DIR, 'idp.crt')
IDP_CA_CERT = os.path.join(CERTS_DIR, 'idp.crt')

# SAML2 IdP configuration
def get_idp_config():
  config = {
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
    'entityid': 'https://idp.local:8443/idp',
    'description': 'Example PySAML2 IdP',
    'service': {
      'idp': {
        'name': 'Example IdP',
        'want_authn_requests_signed': True,
        'endpoints': {
          'single_sign_on_service': [
            ('https://idp.local:8443/idp', BINDING_HTTP_REDIRECT),
            ('https://idp.local:8443/idp', BINDING_HTTP_POST),
          ],
          'single_logout_service': [
            ('https://idp.local:8443/idp/logout', BINDING_HTTP_REDIRECT),
            ('https://idp.local:8443/idp/logout', BINDING_HTTP_POST),
          ],
        },
        'policy': {
          'default': {
            'lifetime': {'minutes': 15},
            'attribute_restrictions': None,  # No restrictions
            'nameid_format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
          }
        },
        'allow_unsolicited': True,
        'authn_requests_signed': True,
        'logout_requests_signed': True,
        'want_response_signed': True
      }
    },
    'metadata': {},
    'key_file': IDP_KEY,
    'cert_file': IDP_CERT,
    'ca_certs': IDP_CA_CERT,
    'debug': 1,
    'xmlsec_path': 'xmlsec1'
  }
  return IdPConfig().load(config)

idp_server = Server(config=get_idp_config())

# Generate IdP metadata and store in idp.xml in the same directory as idp.py
IDP_METADATA_PATH = os.path.join(os.path.dirname(__file__), 'idp.xml')
if not os.path.exists(IDP_METADATA_PATH):
  metadata_bytes = create_metadata_string(None, idp_server.config)
  with open(IDP_METADATA_PATH, 'wb') as f:
    f.write(metadata_bytes)

FRONTEND_STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'frontend'))
app = Flask(__name__, static_folder=FRONTEND_STATIC_DIR)
app.secret_key = os.environ.get('IDP_SECRET_KEY', 'change_this_secret')
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True)

SERVICES = [
  {
    'code': 'hr',
    'entityID': 'https://hr.mysrv.local:8444/saml',
    'metadataURL': 'https://hr.mysrv.local:8444/saml/metadata',
    'displayName': 'HR Application',
    'description': 'Human Resources Management System',
    'metadata': {},
    'error': None,
    'hasLogout': False
  },
  {
    'code': 'finance',
    'entityID': 'https://finance.mysrv.local:8445/saml',
    'metadataURL': 'https://finance.mysrv.local:8445/saml/metadata',
    'displayName': 'Finance Application',
    'description': 'Finance Management System',
    'metadata': {},
    'error': None,
    'hasLogout': False
  },
  {
    'code': 'idpportal',
    'entityID': 'https://idp.local:8443/saml',
    'metadataURL': 'https://idp.local:8443/saml/metadata',
    'displayName': 'Identity Provider Portal',
    'description': 'Identity Provider for SAML authentication',
    'metadata': {},
    'error': None,
    'hasLogout': False
  }
]

def entity_to_code(entity_id):
  """
  Given an entityID, return the corresponding service code from SERVICES.
  Returns None if not found.
  """
  for service in SERVICES:
    if service.get('entityID') == entity_id:
      return service.get('code')
  return None

def code_to_service(code):
  """
  Given a service code, return the corresponding service dict from SERVICES.
  Returns None if not found.
  """
  for service in SERVICES:
    if service.get('code') == code:
      return service
  return None

# In-memory users database
USERS_DB = {
  "alice": {
    "id": "alice",
    "name": {"givenName": "Alice", "familyName": "Smith"},
    "displayName": "Alice Smith",
    "emails": [{"value": "alice@example.com"}],
    "groups": ["users", "hradmin"],
    "password_hash": bcrypt.generate_password_hash("password").decode("utf-8")
  },
  "bob": {
    "id": "bob",
    "name": {"givenName": "Bob", "familyName": "Doe"},
    "displayName": "Bob Doe",
    "emails": [{"value": "bob@example.com"}],
    "groups": ["users", "financeadmin"],
    "password_hash": bcrypt.generate_password_hash("password").decode("utf-8")
  },
  "carol": {
    "id": "carol",
    "name": {"givenName": "Carol", "familyName": "Smith"},
    "displayName": "Carol Smith",
    "emails": [{"value": "carol@example.com"}],
    "groups": ["users", "itadmin"],
    "password_hash": bcrypt.generate_password_hash("password").decode("utf-8")
  },
  "don": {
    "id": "don",
    "name": {"givenName": "Don", "familyName": "Doe"},
    "displayName": "Don Doe",
    "emails": [{"value": "don@example.com"}],
    "groups": ["users"],
    "password_hash": bcrypt.generate_password_hash("password").decode("utf-8")
  }
}

def get_idpportal_sp_config():
  """
  Generates and returns the SAML metadata XML for the IDP portal's Service Provider.
  """
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
    'entityid': 'https://idp.local:8443/saml',
    'description': 'IDP Portal SAML Service Provider',
    'service': {
      'sp': {
        'endpoints': {
          'assertion_consumer_service': [
            ('https://idp.local:8443/saml/acs', BINDING_HTTP_POST),
          ],
          'single_logout_service': [
            ('https://idp.local:8443/saml/logout', BINDING_HTTP_REDIRECT),
            ('https://idp.local:8443/saml/logout', BINDING_HTTP_POST),
          ],
        },
        'allow_unsolicited': True,
        'authn_requests_signed': True,
        'logout_requests_signed': True,
        'want_response_signed': True
      }
    },
    'metadata': {
      'local': [ 
        IDP_METADATA_PATH
      ],
    },
    'allow_unknown_attributes': True,
    'key_file': IDP_KEY,
    'cert_file': IDP_CERT,
    'ca_certs': IDP_CA_CERT,
    'xmlsec_path': 'xmlsec1',
    'debug': 1,
  }
  return SPConfig().load(sp_config)

idpportal_sp = Saml2Client(config=get_idpportal_sp_config())
# Generate SP metadata XML for idpportal and store in idpportal.xml
IDPPORTAL_SP_METADATA_PATH = os.path.join(os.path.dirname(__file__), 'idpportal.xml')
if not os.path.exists(IDPPORTAL_SP_METADATA_PATH):
  sp_metadata_bytes = create_metadata_string(None, idpportal_sp.config)
  with open(IDPPORTAL_SP_METADATA_PATH, 'wb') as f:
    f.write(sp_metadata_bytes)

def get_active_sessions():
  # Return active sessions
  pass

def get_users():
  if 'user_profile' in session:
    ava = session['user_profile']
    user = ava.get('uid', [None])[0]
    if 'itadmin' in USERS_DB[user]['groups']:
      return USERS_DB
    return {user: USERS_DB[user]} if user in USERS_DB else None
  return None

def fetch_sp_metadata():
  # Fetch and parse SP metadata
  metadata_config = {'local': []}
  for service in SERVICES:
    try:
      # Fetch metadata from the service's metadataURL
      resp = requests.get(service['metadataURL'], timeout=5, verify=SSL_CA_CERT)
      resp.raise_for_status()
      metadata_xml = resp.text
      service['metadata'] = metadata_xml
      service['error'] = None
      metadata_path = f"{service['code']}.xml"
      with open(metadata_path, 'w') as f:
        f.write(metadata_xml)
      metadata_config['local'].append(metadata_path)
    except Exception as e:
      service['metadata'] = {}
      service['error'] = str(e)
  idp_server.reload_metadata(metadata_config)
  md = idp_server.metadata
  outservices = []
  for service in SERVICES:
    entity_id = service.get('entityID')
    try:
      slo_services = md.single_logout_service(entity_id, None, "spsso")
      service['hasLogout'] = bool(slo_services)
    except Exception as e:
      service['hasLogout'] = False
    service['loggedIn'] = service['hasLogout'] and service['code'] in session.get('logged_in_services', [])
    if service['error'] is None and service['metadata']:
      outservices.append(service) 
  return outservices

@app.route('/saml/metadata', methods=['GET'])
def saml_metadata():
  # Return SP metadata XML
  with open(IDPPORTAL_SP_METADATA_PATH, 'r') as f:
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
    authn_response = idpportal_sp.parse_authn_request_response(
      saml_response,
      BINDING_HTTP_POST
    )
    # Extract user info from the assertion
    if authn_response and authn_response.ava:
      session['user_profile'] = authn_response.ava
      return redirect('/')
    else:
      return jsonify({'error': 'Invalid SAML assertion'}), 401
  except Exception as e:
    return jsonify({'error': str(e)}), 400
  
@app.route('/saml/logout', methods=['GET'])
def saml_logout():
  # Handle SAML logout response/request from SP
  saml_request = request.args.get('SAMLRequest')
  relay_state = request.args.get('RelayState')
  saml_response = request.args.get('SAMLResponse')
  try:
    if saml_request:
      logout_req = idpportal_sp.parse_logout_request(saml_request, BINDING_HTTP_REDIRECT)
      # Remove user_profile from session
      session.pop('user_profile', None)
      logout_resp = idpportal_sp.create_logout_response(
        logout_req.message,
        status=success_status_factory(),
        bindings=[BINDING_HTTP_REDIRECT],
        sign=False
      )
      http_info = idpportal_sp.apply_binding(
        BINDING_HTTP_REDIRECT,
        str(logout_resp),
        logout_resp.destination,
        relay_state=relay_state,
        response=True,
        sign=True,
        signalg=idpportal_sp.config.signing_algorithm
      )
      return "Success", http_info.get('status', 200), http_info.get('headers', {})
    elif saml_response:
      return redirect('/')
    else:
      return jsonify({'error': 'Missing SAMLRequest or SAMLResponse'}), 400
  except Exception as e:
    return jsonify({'error': str(e)}), 400
  
@app.route('/auth/login', methods=['GET'])
def auth_login():
  # Initiate SAML login flow
  # Create SAML AuthnRequest using idpportal_sp
  reqid, info = idpportal_sp.prepare_for_authenticate(
    entityid=idp_server.config.entityid,
    relay_state=None,
    binding=BINDING_HTTP_REDIRECT,
    nameid_format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
  )
  return info.get('body', []), info.get('status', 200), info.get('headers', {})

@app.route('/auth/logout', methods=['GET'])
def auth_logout():
  session.pop('user_profile', None)
  if 'logged_in_services' in session and 'idpportal' in session['logged_in_services']:
    session['logged_in_services'].remove('idpportal')
  # Send SAML logout request to IdP
  service = code_to_service('idpportal')
  if service and service.get('metadata'):
    idp_entity_id = idp_server.config.entityid
    sp_entity_id = service['entityID']
    slo_services = idpportal_sp.metadata.single_logout_service(idp_entity_id, None, "idpsso")
    if slo_services:
      slo_service = slo_services.get(BINDING_HTTP_REDIRECT)[0]
      slo_url = slo_service['location']
      slo_binding = BINDING_HTTP_REDIRECT
      name_id = NameID(
        text=session.get('user', ''),
        format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        sp_name_qualifier=sp_entity_id,
        name_qualifier=idp_entity_id
      )
      rid, saml_request = idpportal_sp.create_logout_request(
        slo_url,
        idpportal_sp.config.entityid,
        name_id=name_id,
        reason="User logout"
      )
      http_info = idpportal_sp.apply_binding(
        slo_binding,
        str(saml_request),
        slo_url,
        rid,
        sign=True,
        sigalg=idpportal_sp.config.signing_algorithm
      )
      return http_info['data'], http_info['status'], http_info['headers']
      # Optionally, you could redirect to the SLO URL here
  return redirect('/')

@app.route('/auth/user', methods=['GET'])
def auth_user():
  # Return current user info
  if 'user_profile' in session:
    user = session['user_profile'].get('uid')
    return jsonify({'user': user if user else None})
  return jsonify({'error': 'Not authenticated'}), 401

@app.route('/admin/active-sessions', methods=['GET'])
def admin_active_sessions():
  # List active sessions
  return jsonify({'sessions': get_active_sessions()})

@app.route('/admin/users', methods=['GET'])
def admin_users():
  users = get_users()
  if users is None:
    return jsonify({'error': 'Not authorized'}), 403
  else:
    return jsonify(users)

@app.route('/admin/services', methods=['POST'])
def admin_services():
  # Fetch and parse metadata for all services
  return jsonify(fetch_sp_metadata())

@app.route('/admin/shortcuts/<code>', methods=['GET'])
def admin_shortcuts(code):
  # IdP-initiated SAML login for service code
  return redirect(f'/idp?service={code}')

def authenticate():
  """
  Authenticate user from session or via login form.
  If not authenticated, render login page and prompt for credentials.
  """
  if 'user' in session and session['user'] in USERS_DB:
    g.user = session['user']
    return True
  if request.method == 'POST':
    username = request.form.get('username')
    password = request.form.get('password')
    user = USERS_DB.get(username)
    if user and bcrypt.check_password_hash(user['password_hash'], password):
      g.user = session['user'] = username
      return True

  # Read login.html and parse the form
  login_html_path = os.path.join(app.static_folder, 'login.html')
  with open(login_html_path, 'r') as f:
    html = f.read()
  soup = BeautifulSoup(html, 'html.parser')
  form = soup.find('form')

  if not form:
    return "Invalid Form", 401

  # Add hidden fields for GET args
  if request.method == 'GET':
    items = request.args.items()
  elif request.method == 'POST':
    items = request.form.items()
  else:
    return "Invalid Method", 401

  for key, value in items:
    if not form.find('input', {'name': key}):
      hidden = soup.new_tag('input', type='hidden', value=value)
      hidden['name'] = key
      form.append(hidden)

  return str(soup), 401

def parse_saml_request(saml_request, binding, relay_state, sig_alg, signature):
  xml_str = decode_base64_and_inflate(saml_request)
  root = ET.fromstring(xml_str)
  req, is_logout = None, False
  if root.tag.endswith('LogoutRequest'):
    # It's a LogoutRequest
    req = idp_server.parse_logout_request(
      saml_request,
      binding,
      relay_state=relay_state,
      sigalg=sig_alg,
      signature=signature
    )
    is_logout = True
  elif root.tag.endswith('AuthnRequest'):
    # It's an AuthnRequest
    req = idp_server.parse_authn_request(
      saml_request,
      binding,
      relay_state=relay_state,
      sigalg=sig_alg,
      signature=signature
    )
  return req, is_logout

def validate_saml_request():
  # 1. Determine binding based on method and presence of SigAlg/Signature
  if request.method == 'GET':
    args = request.args
    binding = BINDING_HTTP_REDIRECT
  elif request.method == 'POST':
    args = request.form
    if args.get('SigAlg') or args.get('Signature'):
      binding = BINDING_HTTP_REDIRECT
    else:
      binding = BINDING_HTTP_POST
  else:
    return False
  g.binding = binding

  saml_request = args.get('SAMLRequest')
  relay_state = args.get('RelayState')
  sig_alg = args.get('SigAlg')
  signature = args.get('Signature')

  if not saml_request:
    return False

  try:
    if saml_request:
      req = idp_server.parse_authn_request(
        saml_request,
        binding,
        relay_state=relay_state,
        sigalg=sig_alg,
        signature=signature
      )
      g.destination = req.message.assertion_consumer_service_url
      g.name_id_policy=req.message.name_id_policy
      g.in_response_to=req.message.id
      g.sp_entity_id=req.message.issuer.text

    if not req:
      return False
    g.req = req
    g.relay_state = relay_state
    return True
  except Exception:
    return False
  
def clear_logged_in_services(exclude_code):
  if 'logged_in_services' in session:
    return [code for code in session['logged_in_services'] if code != exclude_code]
  return []

def append_logged_in_service(code):
  # Track logged-in services for the user in session
  if 'logged_in_services' not in session:
    session['logged_in_services'] = []
  service = code_to_service(code)
  if service and service.get('metadata'):
    try:
      md = idp_server.metadata
      slo_services = md.single_logout_service(service['entityID'], BINDING_HTTP_REDIRECT, "spsso")
    except Exception:
      slo_services = None
  svcs = session['logged_in_services']
  if slo_services and code not in svcs:
    svcs.append(code)
  return svcs

def handle_logout_response(saml_response):
  service_code = None
  try:
    # Parse the SAMLResponse to get the entityID (issuer)
    resp_obj = idp_server.parse_logout_request_response(saml_response, BINDING_HTTP_REDIRECT)
    if resp_obj and hasattr(resp_obj.response, 'issuer') and hasattr(resp_obj.response.issuer, 'text'):
      service_code = entity_to_code(resp_obj.response.issuer.text)
    # Confirm the in_response_to matches an earlier request sent
    in_response_to = getattr(resp_obj.response, 'in_response_to', None)
    last_logout_request_ids = session.get('last_logout_request_ids', [])
    if in_response_to and in_response_to not in last_logout_request_ids:
      logging.warning(f"in_response_to mismatch: expected one of {last_logout_request_ids}, got {in_response_to}")
      return "Invalid logout response: in_response_to mismatch", 400
    # Remove the matched request ID from the array
    if in_response_to in last_logout_request_ids:
      last_logout_request_ids.remove(in_response_to)
      session['last_logout_request_ids'] = last_logout_request_ids
  except Exception:
    service_code = None
  if service_code:
    session['logged_in_services'] = clear_logged_in_services(service_code)
  message = f'Logged out of {service_code} successfully'
  logging.info(message)
  if not session.get('slo_continue', False):
    return message, 200
  else:
    return redirect('/idp/logout')
  
@app.before_request
def before_idp():
  # Only protect /idp endpoint for authentication
  if request.path == '/idp':
    scode = request.args.get('service')
    if not scode:
      if not validate_saml_request():
        return "Invalid SAML request", 400
      auth_result = authenticate()
      if auth_result is not True:
        return auth_result
    else:
      user = session.get('user', None)
      if not user or user not in USERS_DB:
        return redirect('/auth/login')
      # IdP-initiated SAML login for the service
      svc = code_to_service(scode)
      if not svc or not svc.get('metadata'):
        return "Service not found or metadata missing", 400
      sp_entity_id = svc['entityID']
      # Find ACS URL from SP metadata
      try:
        md = idp_server.metadata
        acs_services = md.assertion_consumer_service(sp_entity_id, None, "spsso")
        g.destination = acs_services[0]['location']
      except Exception:
        return "ACS URL not found in metadata", 400
      g.sp_entity_id = sp_entity_id
      g.is_request = True
      g.user = user
  elif request.path == '/idp/logout' and request.method == 'GET':
    args = request.args
    if 'SAMLResponse' in args:
      saml_response = args['SAMLResponse']
      return handle_logout_response(saml_response)
      
@app.route('/idp', methods=['GET', 'POST'])
def idp():
  relay_state = g.pop('relay_state', None)
  is_logout = g.pop('is_logout', False)
  binding = g.pop('binding', BINDING_HTTP_POST)

  if is_logout:
    return "Logout not implemented in this example", 501

  # Get SP entityID and ACS URL
  sp_entity_id = g.pop('sp_entity_id', None)
  acs_url = g.pop('destination', None)

  # Get authenticated user info
  username = g.pop('user', None)
  user = USERS_DB.get(username)

  # Create SAML response
  saml_response = idp_server.create_authn_response(
    identity={
      'uid': user['id'],
      'displayName': user['displayName'],
      'givenName': user['name']['givenName'],
      'sn': user['name']['familyName'],
      'email': user['emails'][0]['value'],
      'groups': user['groups'],
    },
    userid=username,
    destination=acs_url,
    in_response_to=g.pop('in_response_to', None),
    sp_entity_id=sp_entity_id,
    name_id_policy=g.pop('name_id_policy', None),
    authn={
      'class_ref': PASSWORDPROTECTEDTRANSPORT,
      'authn_auth': 'https://idp.local:8443/idp'
    },
    sign_response=True
  )

  # Render auto-submitting HTML form to ACS
  saml_response_b64 = deflate_and_base64_encode(saml_response.encode()).decode()
  html = f"""
  <html>
    <body onload="document.forms[0].submit()">
    <form method="post" action="{acs_url}">
      <input type="hidden" name="SAMLResponse" value="{saml_response_b64}" />
      {'<input type="hidden" name="RelayState" value="{}" />'.format(relay_state) if relay_state else ''}
    </form>
    </body>
  </html>
  """

  sc = next((s['code'] for s in SERVICES if s['entityID'] == sp_entity_id), None)
  session['logged_in_services'] = append_logged_in_service(sc)

  return html

@app.route('/idp/metadata', methods=['GET'])
def idp_metadata():
  with open(IDP_METADATA_PATH, 'r') as f:
    metadata_str = f.read()
  return metadata_str, 200, {'Content-Type': 'application/xml'}

def send_service_logout_request(service_code):
  service = code_to_service(service_code)
  if not service or not service.get('metadata'):
    return "Service metadata not found", 400
  sp_entity_id = service['entityID']
  slo_services = idp_server.metadata.single_logout_service(sp_entity_id, None, "spsso")
  if slo_services:
    slo_service = slo_services.get(BINDING_HTTP_REDIRECT)[0]
    slo_url = slo_service['location']
    slo_binding = BINDING_HTTP_REDIRECT
    name_id = NameID(
      text=session['user'],
      format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      sp_name_qualifier=sp_entity_id,
      name_qualifier=idp_server.config.entityid
    )
    rid, saml_request = idp_server.create_logout_request(
      slo_url,
      idp_server.config.entityid,
      name_id=name_id,
      reason="User logout"
    )
    # Store the logout request ID in session for later comparison
    if 'last_logout_request_ids' not in session:
      session['last_logout_request_ids'] = []
    last_logout_request_ids = session['last_logout_request_ids']
    last_logout_request_ids.append(rid)
    session['last_logout_request_ids'] = last_logout_request_ids
    http_info = idp_server.apply_binding(
      slo_binding,
      str(saml_request),
      slo_url,
      rid,
      sign=True,
      sigalg=idp_server.config.signing_algorithm
    )
    return f"Redirecting to {sp_entity_id} for logout...", http_info['status'], http_info['headers']
  return f"No SLO found for {sp_entity_id}", 400

@app.route('/idp/logout', methods=['GET'])
def idp_logout():
  #IDP initiated logout for a specific service. 
  service_code = request.args.get('service')
  if service_code and 'logged_in_services' in session and service_code in session['logged_in_services']:
    return send_service_logout_request(service_code)
  binding = BINDING_HTTP_REDIRECT
  if not 'slo_continue' in session:
    saml_request = request.args.get('SAMLRequest')
    relay_state = request.args.get('RelayState')
    sig_alg = request.args.get('SigAlg')
    signature = request.args.get('Signature')

    if not saml_request:
      return "Missing SAMLRequest", 400
  
    req = idp_server.parse_logout_request(
      saml_request,
      binding,
      relay_state=relay_state,
      sigalg=sig_alg,
      signature=signature
    )
    
    if not req:
      return "Invalid Logout Request", 400
  
    session["slo_saml_request"] = saml_request
    session["slo_relay_state"] = relay_state
    session["slo_sig_alg"] = sig_alg
    session["slo_signature"] = signature

    logout_service_code = entity_to_code(req.message.issuer.text)
    session['logged_in_services'] = clear_logged_in_services(logout_service_code)

  if not session.get('logged_in_services') or len(session['logged_in_services']) == 0:
    session.pop('slo_continue', None)
    saml_request = session.pop("slo_saml_request", None)
    relay_state  = session.pop("slo_relay_state", None)
    sig_alg = session.pop("slo_sig_alg", None)
    signature = session.pop("slo_signature", None)

    req = idp_server.parse_logout_request(
      saml_request,
      binding,
      relay_state=relay_state,
      sigalg=sig_alg,
      signature=signature
    )

    # Find the SLO redirect binding URL for the issuer of req
    issuer_entity_id = req.message.issuer.text
    slo_services = idp_server.metadata.single_logout_service(issuer_entity_id, None, "spsso")
    if slo_services and BINDING_HTTP_REDIRECT in slo_services:
      destination = slo_services[BINDING_HTTP_REDIRECT][0]['location']

    logout_resp = idp_server.create_logout_response(
      req.message,
      status=success_status_factory(),
      bindings=[BINDING_HTTP_REDIRECT],
      sign=True
    )
    http_info = idp_server.apply_binding(
      BINDING_HTTP_REDIRECT,
      logout_resp,
      destination,
      relay_state=relay_state,
      response=True,
      sign=True,
      signalg=idp_server.config.signing_algorithm
    )
    session.clear()
    return http_info['data'], http_info['status'], http_info['headers']
  else:
    # Redirect to logout the next service in the list
    next_service_code = session['logged_in_services'][0]
    session['slo_continue'] = True
    return send_service_logout_request(next_service_code)

@app.route('/', methods=['GET'])
def serve_index():
  return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>', methods=['GET'])
def serve_frontend(path):
    # Serve static frontend assets
    return send_from_directory(app.static_folder, path)

# Combine server cert and intermediate CA into a chain file
CHAIN_CERT = os.path.join(SSL_CERTS_DIR, 'idp.local.chain.crt')
if not os.path.exists(CHAIN_CERT):
  with open(CHAIN_CERT, 'w') as chain:
    with open(SSL_CERT, 'r') as sc:
      chain.write(sc.read())
    with open(SSL_CA_CERT, 'r') as ca:
      chain.write('\n')
      chain.write(ca.read())
      
if __name__ == '__main__':
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain(CHAIN_CERT, SSL_KEY, password="password")
  app.run(host='0.0.0.0', port=8443, ssl_context=context)