1. Single Logout uses a browser session-based HTTP-Redirect binding architecture.
  If a logged-in service goes down, SAML Logout may fail when triggered from
  another service.

2. In production, track failures and restart logout via a background service
  that resumes failed requests. Only the `HTTP-Redirect` binding is implemented
  in the sample app. However, services can implement SPs using the HTTP-POST or
  SOAP binding which will help a service-based workflow. 

3. The [Finance](finance) app does not implement SAML Logout, showing that SPs
  may not support SLO.

4. While SAML only provides guidance for message passing in SLO, a good SLO
  implementation requires robust error handling for failures in distributed
  systems.

5. We have not implemented the listing of active sessions on the IDP UI. 
