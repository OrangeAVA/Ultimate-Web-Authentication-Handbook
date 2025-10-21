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
  