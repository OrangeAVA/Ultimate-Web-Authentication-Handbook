"""
This module defines the Device model for associating authentication devices
with users in a Django application.

Classes:
  Device: Represents a device registered by a user for authentication
  purposes. Each device is linked to a user and stores credential data
  and device type information.

Device Model Fields:
  user (ForeignKey): References the user who owns the device. Deleting
    the user cascades and deletes associated devices.
  name (CharField): Optional human-readable name for the device.
  credential_data (BinaryField): Stores credential or secret data
    required for authentication (e.g., WebAuthn credential or OTP
    secret).
  device_type (CharField): Specifies the type of device, either 'otp'
    (One-Time Password) or 'webauthn' (Web Authentication).

Methods:
  __str__(): Returns a string representation of the device, including
    the username and device type.
"""
from django.db import models
from django.conf import settings

class Device(models.Model):
  user = models.ForeignKey(
    settings.AUTH_USER_MODEL,
    on_delete=models.CASCADE,
    related_name='devices'
  )
  name = models.CharField(max_length=255, blank=True)
  credential_data = models.BinaryField()
  device_type = models.CharField(
    max_length=10,
    choices=[
      ('otp', 'OTP'),
      ('webauthn', 'WebAuthn'),
    ]
  )

  def __str__(self):
    return f"{self.user.username} - {self.device_type} device"
