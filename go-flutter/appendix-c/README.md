The following changes are introduced in the certificate creation process.
1. All certificates are generated using OpenSSL 3+.
2. The old `.p12` formats and legacy cryptographic methods are removed.
3. All the server certificates are generated from the `sroot` certificate authority.
4. There is an intermediate CA `sint` signed by `sroot`.
5. The end-entity or SSL certificate is signed by `sint`.
6. Just one SSL certificate has been generated and aliased using 
   `subjectAltName`, so that it can be used across all the domains used in the 
   examples, namely, `idp.local`, `mysrv.local`, `hr.mysrv.local`, 
   and `finance.mysrv.local`.
7. The server CA Root and Intermediate certificates are placed in `scas.crt` for
   easier portability for the clients.
8. The client certificates are generated with `croot.crt` --> `cint.crt` --> 
   `alice.crt` hierarchy. We store the `alice.p12` for easier movement of the 
   certificate and the private key.
9. All the private keys use `password` to encrypt their content in a PKCS-8
   envelope.
10. The certificates used to sign SAML requests and responses are self-signed
    certificates with no additional hierarchies.
11. All certificates are valid for 5 years and will expire in May 2030. 
12. The keys and certificates are stored in the [output](output) directory. 
    Softlinks in other folders directly or indirectly access the files in 
    this location.  
