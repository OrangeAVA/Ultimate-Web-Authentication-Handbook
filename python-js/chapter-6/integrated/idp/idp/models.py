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
