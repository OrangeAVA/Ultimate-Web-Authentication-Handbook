
# resource.py: Flask app serving PKCE code via HTTPS with custom cert chain.
# This module implements a Flask web server that serves a simple HTML page
# displaying a PKCE code received via a query parameter. It sets up HTTPS
# using a custom certificate chain and a decrypted private key. The server
# combines the server certificate with intermediate and root CA certificates
# to form a chain file, and decrypts the private key if necessary. The main
# route ('/') expects a 'code' query parameter and renders it in the HTML
# response. SSL context is configured for secure communication.

from flask import Flask, request, abort, render_template_string
import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>PKCE Code</title>
</head>
<body>
  <h1>Received Code</h1>
  <p>{{ code }}</p>
</body>
</html>
"""

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Update SSL certificate and key paths
SSL_CERTS_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'certs'))
SSL_CERT = os.path.join(SSL_CERTS_DIR, 'mysrv.local.crt')
SSL_KEY = os.path.join(SSL_CERTS_DIR, 'mysrv.local.key')

# Decrypt the SSL_KEY if it is encrypted (example using cryptography library and a passphrase)
DECRYPTED_SSL_KEY = os.path.join(SSL_CERTS_DIR, 'mysrv.local.decrypted.key')
if not os.path.exists(DECRYPTED_SSL_KEY):
  try:
    with open(SSL_KEY, 'rb') as key_file:
      encrypted_key = key_file.read()
    private_key = serialization.load_pem_private_key(
      encrypted_key,
      password="password".encode(),
      backend=default_backend()
    )
    with open(DECRYPTED_SSL_KEY, 'wb') as out_key:
      out_key.write(
        private_key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=serialization.NoEncryption()
        )
      )
  except Exception as e:
    print(f"Failed to decrypt SSL key: {e}")
    sys.exit(1)

# Combine server cert and intermediate/root CAs into a chain file
CHAIN_CERT = os.path.join(SSL_CERTS_DIR, 'mysrv.local.chain.crt')
SSL_CA_CERTS = [
  os.path.join(SSL_CERTS_DIR, 'sint.crt'),
  os.path.join(SSL_CERTS_DIR, 'sroot.crt'),
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

@app.route('/', methods=['GET'])
def index():
  code = request.args.get('code')
  if code:
    return render_template_string(HTML_TEMPLATE, code=code)
  else:
    abort(400, description="Missing code parameter")

if __name__ == '__main__':
  context = (
    CHAIN_CERT,  # Path to server certificate
    DECRYPTED_SSL_KEY   # Path to server private key
  )
  app.run(host='0.0.0.0', port=8444, ssl_context=context)