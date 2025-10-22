# github/device.py
#
# Implements the GitHub Device Authorization flow for authenticating users
# via the OAuth device code grant. Allows a user to authenticate with GitHub
# on a separate device and fetches the authenticated user's profile.
#
# Functions:
#   request_device_code():
#     Requests a device/user code pair from GitHub for user authorization.
#
#   poll_for_token(device_code, interval, expires_in):
#     Polls GitHub for an access token using the device code until the user
#     authorizes or the code expires.
#
#   fetch_user_profile(access_token):
#     Fetches the authenticated user's GitHub profile using the access token.
#
#   doDeviceWorkflow():
#     Orchestrates the device authorization flow, prints instructions for the
#     user, and displays the authenticated user's profile.
#
# This file implements GitHub's Device Authorization OAuth flow in Python.
import os
import time
import requests
import urllib.parse

GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

GH_CLIENT_ID = os.environ.get("GH_CLIENT_ID")
if not GH_CLIENT_ID:
  raise RuntimeError("GH_CLIENT_ID environment variable is required.")

def request_device_code():
  resp = requests.post(
    GITHUB_DEVICE_CODE_URL,
    data={"client_id": GH_CLIENT_ID, "scope": "read:user"}
  )
  resp.raise_for_status()
  # The response is URL-encoded, so convert it to JSON
  data = dict(item.split('=') for item in resp.text.split('&'))
  if "verification_uri" in data:
    data["verification_uri"] = urllib.parse.unquote(data["verification_uri"])
  # Convert numeric fields to int
  for key in ["expires_in", "interval"]:
    if key in data:
      data[key] = int(data[key])
  return data

def poll_for_token(device_code, interval, expires_in):
  start = time.time()
  while time.time() - start < expires_in:
    resp = requests.post(
      GITHUB_TOKEN_URL,
      data={
        "client_id": GH_CLIENT_ID,
        "device_code": device_code,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
      },
      headers={"Accept": "application/json"}
    )
    data = resp.json()
    if "access_token" in data:
      return data["access_token"]
    if data.get("error") == "authorization_pending":
      time.sleep(interval)
      continue
    if data.get("error") == "slow_down":
      interval += 5
      time.sleep(interval)
      continue
    raise RuntimeError(f"Error polling for token: {data.get('error_description', data.get('error'))}")
  raise TimeoutError("Device code expired before authorization.")

def fetch_user_profile(access_token):
  resp = requests.get(
    GITHUB_USER_URL,
    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
  )
  resp.raise_for_status()
  return resp.json()

def doDeviceWorkflow():
  device_data = request_device_code()
  print(f"Visit {device_data['verification_uri']} and enter code: {device_data['user_code']}")
  print(f"Expires in {device_data['expires_in']} seconds.")

  access_token = poll_for_token(
    device_data["device_code"],
    device_data["interval"],
    device_data["expires_in"]
  )
  print("Authentication successful. Fetching user profile...")
  user_profile = fetch_user_profile(access_token)
  print("Authenticated GitHub user:", user_profile["login"])
  print("Full user profile:", user_profile)

if __name__ == "__main__":
  doDeviceWorkflow()