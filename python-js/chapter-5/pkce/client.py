# This file implements a PKCE OAuth2/OIDC client for authentication flows.

"""
client.py

A Python implementation of an OAuth2/OpenID Connect client using PKCE (Proof Key
for Code Exchange). This script demonstrates the authentication flow with an
OIDC provider, including discovery, authorization, token exchange, user info
retrieval, and periodic token refresh.

Functions:
----------
base64url_encode(data: bytes) -> str
  Encodes bytes to a base64url string without padding.

generate_pkce_pair() -> Tuple[str, str]
  Generates a PKCE code verifier and its corresponding code challenge.

discover_oidc_config() -> dict
  Fetches the OIDC provider's configuration from the discovery endpoint.

build_auth_url(config: dict, code_challenge: str) -> str
  Constructs the authorization URL with PKCE parameters.

exchange_code_for_tokens(config: dict, code: str, code_verifier: str) -> dict
  Exchanges the authorization code for access, ID, and refresh tokens.

decode_jwt(token: str) -> Optional[str]
  Decodes the payload of a JWT token and returns it as a string.

fetch_userinfo(config: dict, access_token: str) -> dict
  Retrieves user information from the OIDC userinfo endpoint.

refresh_access_token(config: dict, refresh_token: str) -> dict
  Uses the refresh token to obtain a new access token.

periodic_refresh(config: dict, refresh_token: str, interval: int, stop_event: threading.Event) -> dict
  Periodically refreshes the access token at the specified interval.

  Orchestrates the authentication flow: discovery, PKCE, browser login,
  token exchange, user info fetch, and periodic token refresh.
"""

import base64
import hashlib
import os
import sys
import time
import threading
import requests
import webbrowser
from urllib.parse import urlencode

import urllib.parse

OIDC_DISCOVERY_URL = "https://idp.local:8443/oidc/.well-known/openid-configuration"
REDIRECT_URI = "https://mysrv.local:8444/"
CLIENT_ID = "911337"  # Replace with your client ID
SCOPES = "openid profile email offline_access"

SERVER_ROOT = os.path.join(os.path.dirname(__file__), "..", "certs", "sroot.crt")

def base64url_encode(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def generate_pkce_pair():
  code_verifier = base64url_encode(os.urandom(32))
  code_challenge = base64url_encode(hashlib.sha256(code_verifier.encode()).digest())
  return code_verifier, code_challenge

def discover_oidc_config():
  resp = requests.get(OIDC_DISCOVERY_URL, verify=SERVER_ROOT)
  resp.raise_for_status()
  return resp.json()

def build_auth_url(config, code_challenge):
  params = {
    "client_id": CLIENT_ID,
    "response_type": "code",
    "scope": SCOPES,
    "redirect_uri": REDIRECT_URI,
    "code_challenge": code_challenge,
    "code_challenge_method": "S256"
  }
  return config["authorization_endpoint"] + "?" + urlencode(params)

def exchange_code_for_tokens(config, code, code_verifier):
  data = {
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": REDIRECT_URI,
    "client_id": CLIENT_ID,
    "code_verifier": code_verifier
  }
  resp = requests.post(config["token_endpoint"], data=data, verify=SERVER_ROOT)
  resp.raise_for_status()
  return resp.json()

def decode_jwt(token):
  parts = token.split('.')
  if len(parts) != 3:
    return None
  payload = parts[1] + '=' * (-len(parts[1]) % 4)
  return base64.urlsafe_b64decode(payload).decode('utf-8')

def fetch_userinfo(config, access_token):
  headers = {"Authorization": f"Bearer {access_token}"}
  resp = requests.get(config["userinfo_endpoint"], headers=headers, verify=SERVER_ROOT)
  resp.raise_for_status()
  return resp.json()

def refresh_access_token(config, refresh_token):
  data = {
    "grant_type": "refresh_token",
    "refresh_token": refresh_token,
    "client_id": CLIENT_ID
  }
  resp = requests.post(config["token_endpoint"], data=data, verify=SERVER_ROOT)
  resp.raise_for_status()
  return resp.json()

def periodic_refresh(config, refresh_token, interval, stop_event):
  tokens = None
  while not stop_event.is_set():
    time.sleep(interval)
    try:
      tokens = refresh_access_token(config, refresh_token)
      print("\n[+] Refreshed access token.")
    except Exception as e:
      print(f"[!] Failed to refresh token: {e}")
      break
  return tokens

def main():
  print("[*] Discovering OIDC configuration...")
  config = discover_oidc_config()
  code_verifier, code_challenge = generate_pkce_pair()
  auth_url = build_auth_url(config, code_challenge)
  print(f"[*] Opening browser for authentication: {auth_url}")
  webbrowser.open(auth_url)
  code = input("[?] Enter the authorization code from the redirect URL: ").strip()
  print("[*] Exchanging code for tokens...")
  tokens = exchange_code_for_tokens(config, code, code_verifier)
  print("[+] Access Token:", tokens.get("access_token"))
  print("[+] ID Token:", tokens.get("id_token"))
  print("[+] Refresh Token:", tokens.get("refresh_token"))
  print("[*] Decoding ID Token...")
  print(decode_jwt(tokens.get("id_token", "")))
  print("[*] Fetching user info...")
  userinfo = fetch_userinfo(config, tokens["access_token"])
  print("[+] User Info:", userinfo)
  if "refresh_token" in tokens:
    stop_event = threading.Event()
    print("[*] Starting periodic token refresh every 60 seconds. Press Ctrl+C to exit.")
    try:
      while True:
        time.sleep(60)
        tokens = refresh_access_token(config, tokens["refresh_token"])
        print("[+] Refreshed access token:", tokens.get("access_token"))
    except KeyboardInterrupt:
      print("\n[!] Exiting.")
  else:
    print("[!] No refresh token received.")

if __name__ == "__main__":
  main()