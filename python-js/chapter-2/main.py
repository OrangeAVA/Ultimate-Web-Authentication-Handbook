# This file implements a simple Flask web server with HTTP Basic Authentication
# using PBKDF2 password hashing.
#
# main.py
#
# A Flask application that demonstrates HTTP Basic Authentication.
# Passwords are stored as PBKDF2-HMAC-SHA1 hashes in a JSON file.
# The application provides a single endpoint (/basicauth) that requires valid
# credentials.
#
# Functions:
#   load_users(): Loads user credentials from a JSON file.
#   verify_password(stored_hash, password): Verifies a password against a stored
#     PBKDF2 hash.
#   authenticate(): Returns a 401 Unauthorized response with a Basic Auth
#     challenge.
#   basicauth(): Flask route handler for /basicauth, enforces Basic
#     Authentication.
#
# Constants:
#   PASSWORD_FILE: Path to the JSON file containing user credentials.
#   PBKDF2_ITERATIONS: Number of iterations for PBKDF2 hashing.
#   PBKDF2_SALT: Salt used for PBKDF2 hashing.
#   PBKDF2_HASH_NAME: Hash algorithm used for PBKDF2.
#
# Usage:
#   Run this file to start the Flask server on port 8080.
#   Access /basicauth with HTTP Basic Authentication headers.

import json
import base64
import hashlib
from flask import Flask, request, Response
import sys

PASSWORD_FILE = 'password.json'
PBKDF2_ITERATIONS = 4096
PBKDF2_SALT = b'12345678'
PBKDF2_HASH_NAME = 'sha1'
KEYLENGTH = 20  # Length of the key in bytes

def load_users():
  with open(PASSWORD_FILE, 'r') as f:
    return json.load(f)

def verify_password(stored_hash, password):
  dk = hashlib.pbkdf2_hmac(
    PBKDF2_HASH_NAME,
    password.encode('utf-8'),
    PBKDF2_SALT,
    PBKDF2_ITERATIONS,
    dklen=KEYLENGTH
  )
  dk_binhex = base64.b16encode(dk).decode('utf-8').lower()
  return dk_binhex == stored_hash

def authenticate():
  return Response(
    'Unauthorized', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'}
  )

app = Flask(__name__)
hashes = load_users()
if not hashes:
  print("No users found in password file.", file=sys.stderr)
  sys.exit(1)

@app.route('/basicauth', methods=['GET'])
def basicauth():
  auth = request.authorization
  if not auth or not auth.username or not auth.password:
    return authenticate()

  hash = hashes.get(auth.username)
  if not hash or not verify_password(hash, auth.password):
    return authenticate()

  return 'Authenticated successfully!'

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080)
