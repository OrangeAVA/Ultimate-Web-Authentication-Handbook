"""
URL configuration for idp project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import path, include
from oidc_provider import urls as oidc_provider_urls
from django.contrib.auth import logout as django_logout
from django.contrib.auth.decorators import login_required
from idp.helpers import userinfo

@login_required
def _userinfo(request):
  user = request.user
  info = userinfo(None, user)
  return JsonResponse(info)

def index(request):
  return HttpResponseRedirect('/admin')

def logout(request):
  django_logout(request)
  return HttpResponseRedirect('/')

urlpatterns = [
  path('admin/', admin.site.urls),
  path('oidc/', include(oidc_provider_urls, namespace='oidc_provider')),
  path('accounts/', include('django.contrib.auth.urls')),
  path('userinfo/', _userinfo),
  path('', index)
]
