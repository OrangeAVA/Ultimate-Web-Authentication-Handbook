In this demo, we achieve the following:

1. We set up an OIDC IDP using `django-oidc-provider`.
2. We create a service app, [mysrv.py](mysrv.py), that provides login and logout
  buttons to authenticate using the IDP.
3. In the IDP, we configure multifactor authentication with these rules:
     1. The user can log in using a username and password.
     2. Once logged in, the system prompts the user to register both an OTP
        device and a WebAuthn device.
     3. After successfully registering both OTP and WebAuthn devices, the user
        must log in using these devices. No password will be requested in this
        case.
4. The admin can delete devices from the admin portal.
5. When a device is deleted, the user is asked to authenticate using a password
  and re-register a new device.

## Configuring the Django IDP

Follow the steps in [Chapter 5/idp](../../chapter-5/idp) to initialize the IDP.
Create a superuser.

Log in to the admin console to register a regular user. Let's call her `alice`
and assign her a password.

`alice` cannot log in to the admin portal, but her credentials will be used to
log in to the `mysrv.local` portal.

## Starting the mysrv.local Portal

You can launch the portal using the `python mysrv.py` command.

Click the login button to begin the authentication workflow described above.

## What if You Do Not Have a FIDO2 Device?

You can open your browser's developer tools and use WebAuthn emulation mode to
register a device and use it for your experiments.
