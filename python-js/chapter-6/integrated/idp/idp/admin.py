from django.contrib import admin

from .models import Device

class DeviceAdmin(admin.ModelAdmin):
  def has_add_permission(self, request):
      return False

  def has_change_permission(self, request):
     return False

admin.site.register(Device, DeviceAdmin)