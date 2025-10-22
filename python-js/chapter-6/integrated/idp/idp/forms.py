# This module defines Django form classes for user authentication and 
# registration workflows, supporting multiple authentication methods.
# Classes:
#   UsernameForm:
#     Form for capturing a username input. The username field is optional,
#     accepts between 1 and 150 characters, and is rendered as a text input
#     with a placeholder.
#   PasswordForm:
#     Form for capturing a password input. The password field is optional,
#     accepts up to 128 characters, and is rendered as a password input with
#     a placeholder.
#   OTPForm:
#     Form for capturing a one-time password (OTP). The OTP field is
#     optional, accepts up to 6 characters, and is rendered as a password
#     input with a placeholder.
#   WebAuthnForm:
#     Form for handling WebAuthn authentication responses. Contains a single
#     required hidden field for the signed response.
#   OTPRegistrationForm:
#     Form for registering OTP-based authentication. Contains a required
#     hidden field for the secret and an optional OTP field (up to 6
#     characters) rendered as a text input with a placeholder.
#   WebAuthnRegistrationForm:
#     Form for registering WebAuthn credentials. Contains a single required
#     hidden field for the attestation response.

from django import forms

class UsernameForm(forms.Form):
  username = forms.CharField(
    max_length=150,
    min_length=1,
    strip=True,
    required=False,
    widget=forms.TextInput(attrs={'placeholder': 'Username'})
  )

class PasswordForm(forms.Form):
  password = forms.CharField(
    max_length=128,
    strip=True,
    required=False,    
    widget=forms.PasswordInput(attrs={'placeholder': 'Password'})
  )

class OTPForm(forms.Form):
  otp = forms.CharField(
    max_length=6,
    strip=True,
    required=False,    
    widget=forms.PasswordInput(attrs={'placeholder': 'OTP'})
  )

class WebAuthnForm(forms.Form):
  signed_response = forms.CharField(
    widget=forms.HiddenInput(),
    required=True
  )

class OTPRegistrationForm(forms.Form):
  secret = forms.CharField(
    required=True, 
    widget=forms.HiddenInput()
  )
  otp = forms.CharField(
    max_length=6,
    strip=True,
    required=False,
    widget=forms.TextInput(attrs={'placeholder': 'OTP'})
  )

class WebAuthnRegistrationForm(forms.Form):
  attestation_response = forms.CharField(
    widget=forms.HiddenInput(),
    required=True
  )
  