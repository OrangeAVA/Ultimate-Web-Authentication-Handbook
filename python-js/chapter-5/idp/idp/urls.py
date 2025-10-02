"""
This file configures URL routing for the Django OIDC Identity Provider (IDP).
It maps URL patterns to views for OIDC endpoints, user info, authentication,
and the admin interface.
"""
# from django.contrib import admin
from django.urls import path, include
from django.contrib import admin
from oidc_provider import urls as oidc_provider_urls
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from django.contrib.auth import logout as django_logout
from idp.helpers import userinfo

@login_required
def _userinfo(request):
  user = request.user
  info = userinfo(None, user)
  return JsonResponse(info)

def index(request):
  if request.user.is_authenticated:
    return HttpResponseRedirect('/userinfo/')
  return HttpResponse('Welcome to the Django OIDC IDP! <a href="/oidc/authorize/">Login</a>')

def logout(request):
  django_logout(request)
  return HttpResponseRedirect('/')

urlpatterns = [
  path('oidc/', include(oidc_provider_urls, namespace='oidc_provider')),
  path('userinfo/', _userinfo),
  path('accounts/', include('django.contrib.auth.urls')),
  path('admin/', admin.site.urls),
  path('', index),
]