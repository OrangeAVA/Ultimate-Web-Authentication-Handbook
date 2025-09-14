# main.py
# 
# This Flask application demonstrates HTTPS server setup with optional client certificate authentication
# and HTTP Basic Authentication. It loads server and intermediate certificates, supports client cert
# verification if enabled via the CLIENT_AUTH environment variable, and exposes two endpoints:
#   - /hello: returns a simple greeting
#   - /basicauth: requires HTTP Basic Auth with hardcoded credentials
# 
# Certificate files are expected in the certs/server/ directory.
# 
# Usage:
#   CLIENT_AUTH=true python main.py   # to require client certificates
#   python main.py                    # to run without client certificate verification
import base64
from flask import Flask, request, Response
import ssl
import os

app = Flask(__name__)

# Configuration
SERVER_CERT = 'certs/server/mysrv.local.crt'
SERVER_KEY = 'certs/server/mysrv.local.key'
SERVER_INTERMEDIATE = 'certs/server/sint.crt'
CA_CERT = 'certs/server/croots.crt'  # For client cert verification
CLIENT_AUTH = os.environ.get('CLIENT_AUTH', 'false').lower() == 'true'
PORT = 8443

# Dummy credentials
VALID_USER = 'jdoe'
VALID_PASS = 'password'

@app.route('/hello', methods=['GET'])
def hello():
  return "Hello, World!"

@app.route('/basicauth', methods=['GET'])
def basicauth():
  auth = request.headers.get('Authorization')
  if not auth or not auth.startswith('Basic '):
    return Response(
      'Authentication required', 401,
      {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )
  try:
    encoded = auth.split(' ', 1)[1]
    decoded = base64.b64decode(encoded).decode('utf-8')
    username, password = decoded.split(':', 1)
  except Exception:
    return Response(
      'Invalid authentication header', 401,
      {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )
  if username == VALID_USER and password == VALID_PASS:
    return f"Authenticated as {username}"
  else:
    return Response(
      'Invalid credentials', 401,
      {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )


if __name__ == '__main__':
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  # Concatenate server cert and intermediate CA cert
  with open(SERVER_CERT, 'r') as sc, open(SERVER_INTERMEDIATE, 'r') as ca:
    cert_chain = sc.read() + ca.read()
  # Write the concatenated chain to a temp file
  chain_file = 'certs/server/mysrv.local.chain.crt'
  with open(chain_file, 'w') as f:
    f.write(cert_chain)
  context.load_cert_chain(certfile=chain_file, keyfile=SERVER_KEY, password="password")
  if CLIENT_AUTH:
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(CA_CERT)
  app.run(host='0.0.0.0', port=PORT, ssl_context=context)