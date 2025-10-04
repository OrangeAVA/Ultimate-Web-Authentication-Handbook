#!/usr/bin/env python
import os
import sys
from django.core.management import execute_from_command_line
from sslserver.management.commands.runsslserver import Command as runsslserver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Update SSL certificate and key paths
SSL_CERTS_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', '..', 'certs'))
SSL_CERT = os.path.join(SSL_CERTS_DIR, 'idp.local.crt')
SSL_KEY = os.path.join(SSL_CERTS_DIR, 'idp.local.key')

# Decrypt the SSL_KEY if it is encrypted (example using cryptography library and a passphrase)
DECRYPTED_SSL_KEY = os.path.join(SSL_CERTS_DIR, 'idp.local.decrypted.key')
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
CHAIN_CERT = os.path.join(SSL_CERTS_DIR, 'idp.local.chain.crt')
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

def main():
  """Run administrative tasks."""
  os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'idp.settings')
  os.environ.setdefault('DJANGO_SUPERUSER_USERNAME', 'admin')
  os.environ.setdefault('DJANGO_SUPERUSER_PASSWORD', 'password')

  runsslserver.default_port = "8443"
  runsslserver.default_addr = "0.0.0.0"
  # Use SSL context with django-sslserver
  if len(sys.argv) == 1:
    sys.argv = [sys.argv[0], 'runsslserver', '0.0.0.0:8443', '--certificate', CHAIN_CERT, '--key', DECRYPTED_SSL_KEY]
  execute_from_command_line(sys.argv)

if __name__ == '__main__':
  main()