import json
from django.views.generic.base import TemplateView
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, get_user_model, login, get_user
from django.contrib import messages
from .forms import UsernameForm, PasswordForm, OTPForm, WebAuthnForm, OTPRegistrationForm, WebAuthnRegistrationForm
from .models import Device
import pyotp
import qrcode
import io
import base64
import pickle
from django.urls import reverse
from urllib.parse import quote
from urllib.parse import urlencode

from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
import enum

# Relying Party info
rp = PublicKeyCredentialRpEntity(id="idp.local", name="IDP")
server = Fido2Server(rp)

User = get_user_model()

class LoginView(TemplateView):
  template_name = 'login.html'
  state_form_map = {
    'username': UsernameForm,
    'password': PasswordForm,
    'otp': OTPForm,
    'webauthn': WebAuthnForm
  }

  def set_webauthn_options(self, context):
    username = self.request.session['login_username']
    user = User.objects.get(username=username)
    authentication_data, state_obj = server.authenticate_begin(
      credentials=[
        pickle.loads(dev.credential_data) for dev in user.devices.filter(device_type='webauthn')
      ],
      user_verification="discouraged"
    )
    self.request.session['webauthn_authentication_state'] = state_obj
    context['public_key_options'] = json.dumps(authentication_data['publicKey'], cls=EnumEncoder)

  def get_context_data(self, **kwargs):
    context = super().get_context_data(**kwargs)
    session_state = self.request.session.get('login_state', 'username')
    state = kwargs.get('login_state', session_state)
    context['state'] = state
    form_type = self.state_form_map.get(state)

    if self.request and self.request.method == 'POST' and state == session_state:
      context['form'] = form_type(self.request.POST)
      return context
    
    context['form'] = form_type()
    self.request.session['login_state'] = state
    if state == 'webauthn':
      self.set_webauthn_options(context)
    return context

  def get(self, request):
    if get_user(request).is_authenticated:
      return self.post_authentication_steps(request)
    context = self.get_context_data()
    return render(request, self.template_name, context)
  
  def cancel(self, request):
    context = self.get_context_data(login_state='username')
    return render(request, self.template_name, context)

  def username_step(self, request):
    context = self.get_context_data()
    form = context['form']
    if form.is_valid():
      username = form.cleaned_data['username']
      try:
        user = User.objects.get(username=username)
        request.session['login_username'] = username
        has_otp = user.devices.filter(device_type='otp').exists()
        has_webauthn = user.devices.filter(device_type='webauthn').exists()
        login_state = 'otp' if has_otp and has_webauthn else 'password'
        context = self.get_context_data(login_state=login_state)
        return render(self.request, self.template_name, context)
      except User.DoesNotExist:
        context['error'] = 'User not found.'
        return render(request, self.template_name, context)
    else:
      context['error'] = 'Invalid input.'
      return render(request, self.template_name, context)
    
  def password_step(self, request):
    context = self.get_context_data()
    form = context['form']
    if form.is_valid():
      username = request.session.get('login_username')
      password = form.cleaned_data['password']
      user = authenticate(request, username=username, password=password)
      if user is not None:
        login(request, user)
        return self.post_authentication_steps(request)
      else:
        context['error'] = 'Invalid password.'
        return render(request, self.template_name, context)
    else:
      context['error'] = 'Invalid input.'
      return render(request, self.template_name, context)
    
  def otp_step(self, request):
    context = self.get_context_data()
    form = context['form']
    if form.is_valid():
      username = request.session.get('login_username')
      otp_code = form.cleaned_data['otp']
      try:
        user = User.objects.get(username=username)
        otp_device = user.devices.filter(device_type='otp').first()
        if otp_device:
          otp_secret = otp_device.credential_data.decode()
          totp = pyotp.TOTP(otp_secret)
          if totp.verify(otp_code):
            context = self.get_context_data(login_state='webauthn')
            return render(request, self.template_name, context)
          else:
            context['error'] = 'Invalid OTP code.'
            return render(request, self.template_name, context)
        else:
          context['error'] = 'No OTP device registered.'
          return render(request, self.template_name, context)
      except User.DoesNotExist:
        context['error'] = 'User not found.'
        return render(request, self.template_name, context)
    else:
      context['error'] = 'Invalid input.'
      return render(request, self.template_name, context)
    
  def webauthn_step(self, request):
    context = self.get_context_data()
    form = context['form']
    if form.is_valid():
      username = request.session.get('login_username')
      signed_response = json.loads(form.cleaned_data['signed_response'])
      try:
        user = User.objects.get(username=username)
        webauthn_device = user.devices.filter(device_type='webauthn').first()
        if webauthn_device:
          state_obj = request.session.get('webauthn_authentication_state')
          credentials = [pickle.loads(webauthn_device.credential_data)]
          attested_credential_data = server.authenticate_complete(
            state_obj,
            credentials,
            signed_response
          )
          if attested_credential_data:
            login(request, user)
            return self.post_authentication_steps(request)
          else:
            context['error'] = 'WebAuthn authentication failed.'
            return render(request, self.template_name, context)
        else:
          context['error'] = 'No WebAuthn device registered.'
          return render(request, self.template_name, context)
      except User.DoesNotExist:
        context['error'] = 'User not found.'
        return render(request, self.template_name, context)
    else:
      context['error'] = 'Invalid input.'
      return render(request, self.template_name, context)

  def post_authentication_steps(self, request):
    next_url = request.GET.get('next', '/')
    user = get_user(request)
    orig_next = next_url

    has_otp = user.devices.filter(device_type='otp').exists()
    has_webauthn = user.devices.filter(device_type='webauthn').exists()

    # Resolve registration URLs (fall back to sensible paths if name not present)
    try:
      otp_url = reverse('register_otp')
    except Exception:
      otp_url = '/register/otp/'

    try:
      webauthn_url = reverse('register_webauthn')
    except Exception:
      webauthn_url = '/register/webauthn/'

    # Chain redirects: webauthn -> otp -> original (properly URL-encoded)
    if not has_webauthn:
      # If OTP also missing, make webauthn next point to otp which then points to original
      if not has_otp:
        otp_next = f"{otp_url}?{urlencode({'next': orig_next})}"
      else:
        otp_next = orig_next
      next_url = f"{webauthn_url}?{urlencode({'next': otp_next})}"
    elif not has_otp:
      next_url = f"{otp_url}?{urlencode({'next': orig_next})}"
    # otherwise next_url remains the original
    return redirect(next_url)

  def post(self, request):
    if get_user(request).is_authenticated:
      return self.post_authentication_steps(request)
    if request.POST.get('cancel'):
      return self.cancel(request)
    state = request.session.get('login_state', 'username')
    if state == 'username':
      return self.username_step(request)
    elif state == 'password':
      return self.password_step(request)
    elif state == 'otp':
      return self.otp_step(request)
    elif state == 'webauthn':
      return self.webauthn_step(request)
    else:
      return self.cancel(request)

class RegistrationView(TemplateView):
  template_name = 'notthere.html'

  def get(self, request):
    context = self.get_context_data()
    return render(request, self.template_name, context)

  def next(self, request):
    next_url = request.GET.get('next', '/')
    return redirect(next_url)
  
class OTPRegistrationView(RegistrationView):
  template_name = 'otpreg.html'

  def get_context_data(self, **kwargs):
    context = super().get_context_data(**kwargs)
    otp_secret = pyotp.random_base32()
    request = self.request
    user = get_user(request)
    username = user.username if user.is_authenticated else 'user'
    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="MyIDP")
    qr = qrcode.make(otp_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    imgsrc = "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()
    context['secret'] = otp_secret
    context['imgsrc'] = imgsrc
  
    if request and request.method == 'POST':
      context['form'] = OTPRegistrationForm(request.POST)
    else:
      context['form'] = OTPRegistrationForm({'secret': otp_secret})
    return context

  def post(self, request):
    if request.POST.get('cancel'):
      return self.next(request)
    context = self.get_context_data()
    form = context['form']
    if form.is_valid():
      otp_secret = form.cleaned_data['secret']
      otp_code = form.cleaned_data['otp']
      totp = pyotp.TOTP(otp_secret)
      user = get_user(request)
      if totp.verify(otp_code):
        Device.objects.create(
          user=user,
          name="OTP Device",
          credential_data=otp_secret.encode(),
          device_type='otp'
        )
        messages.success(request, "OTP device registered successfully.")
        return self.next(request)
      else:
        messages.error(request, "Invalid OTP code.")
        context['error'] = "Invalid OTP code."
        return render(request, self.template_name, context)
    else:
      messages.error(request, "Invalid input.")
      context['error'] = "Invalid input."
      return render(request, self.template_name, context)

class EnumEncoder(json.JSONEncoder):
  def default(self, obj):
    if isinstance(obj, enum.Enum):
      return obj.value
    return json.JSONEncoder.default(self, obj)

class WebAuthnRegistrationView(RegistrationView):
  template_name = 'webauthreg.html'

  def get_context_data(self, **kwargs):
    context = super().get_context_data(**kwargs)
    request = self.request
    if request and request.method == 'POST':
      context['form'] = WebAuthnRegistrationForm(request.POST)
    else:
      usr = get_user(request)
      username = usr.username
      user_id = username.encode('utf-8')
      user = PublicKeyCredentialUserEntity(id=user_id, name=username, display_name=username)
      registration_data, state_obj = server.register_begin(
        user,
        credentials=[],
        user_verification="discouraged"
      )
      request.session['webauthn_registration_state'] = state_obj
      context['form'] = WebAuthnRegistrationForm()

      # Convert any enum values inside the publicKey options to plain strings
      context['public_key_options'] = json.dumps(registration_data['publicKey'], cls=EnumEncoder)
    return context
  
  def post(self, request):
    if request.POST.get('cancel'):
      return self.next(request)
    context = self.get_context_data()
    form = context['form']
    user = get_user(request)
    if form.is_valid():
      attestation_response = json.loads(form.cleaned_data['attestation_response'])
      state_obj = request.session.get('webauthn_registration_state')
      auth_data = server.register_complete(
        state_obj,
        attestation_response
      )

      credential_data_bin = pickle.dumps(auth_data.credential_data)
      Device.objects.create(
        user=user,
        name="WebAuthn Device",
        credential_data=credential_data_bin,
        device_type='webauthn'
      )
      messages.success(request, "WebAuthn device registered successfully.")
      return self.next(request)
    else:
      messages.error(request, "Invalid input.")
      return self.next(request)