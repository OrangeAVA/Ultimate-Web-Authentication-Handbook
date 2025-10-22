import io
import os
from flask import Flask, send_from_directory, jsonify
import pyotp
import qrcode
import base64
import ssl

app = Flask(__name__)

# In-memory user store: {username: {type, secret, counter}}
users = {}

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), 'frontend')
IMAGES_DIR = os.path.join(FRONTEND_DIR, 'images')
OTPLIB_BROWSER_DIR = os.path.join(os.path.dirname(__file__), '@otplib', 'preset-browser')

@app.route('/register/<user>/<otp_type>')
def register(user, otp_type):
  if otp_type not in ('totp', 'hotp'):
    return jsonify({'error': 'Invalid OTP type'}), 400

  secret = pyotp.random_base32()
  if otp_type == 'totp':
    otp = pyotp.TOTP(secret)
    uri = otp.provisioning_uri(name=user, issuer_name="UltimateWebAuth")
    counter = None
  else:
    otp = pyotp.HOTP(secret)
    uri = otp.provisioning_uri(name=user, initial_count=0, issuer_name="UltimateWebAuth")
    counter = 1

  # Generate QR code and save as PNG
  qr = qrcode.make(uri)
  qr = qr.resize((180, 180))
  buffered = io.BytesIO()
  qr.save(buffered, format="PNG")
  imgsrc = "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()

  users[user] = {
    'type': otp_type,
    'secret': secret,
    'counter': counter
  }

  return jsonify({
    'user': user,
    'type': otp_type,
    'secret': secret,
    'counter': counter,
    'qrfile': imgsrc
  })

@app.route('/validate/<user>/<otp_token>')
def validate(user, otp_token):
  user_data = users.get(user)
  if not user_data:
    return "User not registered", 404

  secret = user_data['secret']
  otp_type = user_data['type']

  if otp_type == 'totp':
    otp = pyotp.TOTP(secret)
    if otp.verify(otp_token):
      return "OTP is valid"
    else:
      return "Invalid OTP", 401
  else:
    counter = user_data['counter']
    otp = pyotp.HOTP(secret)
    if otp.verify(otp_token, counter):
      users[user]['counter'] = counter+1
      return "OTP is valid"
    else:
      return "Invalid OTP", 401

@app.route('/hello')
def hello():
  return "Hello, World!"

@app.route('/')
def serve_frontend():
  return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/images/<path:filename>')
def serve_images(filename):
  return send_from_directory(IMAGES_DIR, filename)

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