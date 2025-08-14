import os
import ssl
from flask import Flask, request, jsonify, send_from_directory
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_decode
# from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor
from flask import Response
import json


app = Flask(__name__, static_folder='frontend')

# Relying Party info
rp = PublicKeyCredentialRpEntity(id="mysrv.local", name="Example RP")
server = Fido2Server(rp)

# In-memory user and session storage
USERS = {}
SESSIONS = {}

@app.route('/hello', methods=['GET'])
def hello():
  return "Hello, World!"

@app.route('/webauthn/register/begin', methods=['POST'])
def register_begin():
  username = request.args.get('username')
  state = request.args.get('state')
  if not username or not state:
    return jsonify({'error': 'Missing username or state'}), 400

  user_id = username.encode('utf-8')
  user = PublicKeyCredentialUserEntity(id=user_id, name=username, display_name=username)
  registration_data, state_obj = server.register_begin(
    user,
    credentials=USERS.get(username, []),
    user_verification="discouraged"
  )
  SESSIONS[state] = {'register': state_obj, 'username': username}
  public_key_options = registration_data['publicKey']
  return jsonify(public_key_options)

@app.route('/webauthn/register/finish', methods=['POST'])
def register_finish():
  username = request.args.get('username')
  state = request.args.get('state')
  if not username or not state or state not in SESSIONS:
    return jsonify({'error': 'Invalid username or state'}), 400

  data = request.get_json()
  state_obj = SESSIONS[state]['register']
  auth_data = server.register_complete(
    state_obj,
    data
  )

  USERS.setdefault(username, []).append(auth_data.credential_data)
  del SESSIONS[state]
  return jsonify({'success': 'Registered FIDO2 credential successfully'})

@app.route('/webauthn/login/begin', methods=['POST'])
def login_begin():
  username = request.args.get('username')
  state = request.args.get('state')
  if not username or not state or username not in USERS:
    return jsonify({'error': 'Invalid username or state'}), 400

  auth_data, state_obj = server.authenticate_begin(
    credentials=USERS[username],
    user_verification="discouraged"
  )
  SESSIONS[state] = {'login': state_obj, 'username': username}
  publicKey = auth_data['publicKey']
  return jsonify(publicKey)  # Uncomment if you want to use JSON response

@app.route('/webauthn/login/finish', methods=['POST'])
def login_finish():
  username = request.args.get('username')
  state = request.args.get('state')
  if not username or not state or state not in SESSIONS:
    return jsonify({'error': 'Invalid username or state'}), 400

  data = request.get_json()
  state_obj = SESSIONS[state]['login']
  try:
    server.authenticate_complete(
      state_obj,
      USERS[username],
      data
    )
    del SESSIONS[state]
    return jsonify({'success': 'Validated FIDO2 credential successfully'})
  except Exception as e:
    return jsonify({'error': str(e)}), 400

@app.route('/')
def serve_frontend():
  return send_from_directory(app.static_folder, 'index.html')

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
  app.run(host='mysrv.local', port=8443, ssl_context=context)