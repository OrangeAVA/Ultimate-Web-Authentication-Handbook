/*

Chapter-3: Authentication with Network Security
Ultimate Web Authentication Handbook by Sambit Kumar Dash

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.5 mysrv.local

Start the server with the command: go run ./main.go

Import the certs/client/sroot.crt root certificate into your browser's trusted
roots before accessing the website. The chapter describes the steps.

Access the website by typing the URL https://mysrv.local:8443

The server exposes the following endpoints.
/hello - it responds with a "Hello, World" message to the screen.
/basicauth - implements the basic authentication scheme of HTTP. You can use
jdoe as the username and password as the password to authenticate.
/certauth - You should set the CLIENT_AUTH = true in the main method before
you activate this endpoint. You can authenticate using the client certificate
in the certs/client/alice.p12 file. Please follow the steps in the book to import
the certificate to your machine/browser.

*/

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"howa.in/common"
)

func addHelloHandler() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		log.Default().Print("Sending: Hello, World!\n")
		io.WriteString(w, "Hello, World!\n")
	})
}

func addBasicAuthHandler() {
	pmap := map[string]string{"jdoe": "password"}
	http.HandleFunc("/basicauth", func(w http.ResponseWriter, req *http.Request) {
		if u, p, ok := req.BasicAuth(); ok {
			if pmap[u] == p {
				str := fmt.Sprintf("User %s authenticated.", u)
				io.WriteString(w, str)
				log.Default().Print(str)
			} else {
				str := fmt.Sprintf("User %s failed to authenticate.", u)
				w.WriteHeader(http.StatusUnauthorized)
				log.Default().Print(str)
			}
		} else {
			w.Header().Add("WWW-Authenticate", "Basic Realm=\"Access Server\"")
			w.WriteHeader(http.StatusUnauthorized)
			log.Default().Print("Basic authentication needed.")
		}
	})
}

func configureClientAuth(tlsConfig *tls.Config) error {
	// Add certauth end point and handler
	http.HandleFunc("/certauth", func(w http.ResponseWriter, req *http.Request) {
		if req.TLS == nil || req.TLS.PeerCertificates == nil || len(req.TLS.PeerCertificates) <= 0 {
			str := "No client certificates. User failed to authenticate."
			w.WriteHeader(http.StatusUnauthorized)
			log.Default().Print(str)
		} else {
			str := fmt.Sprintf("User %s authenticated.\n", req.TLS.PeerCertificates[0].Subject.CommonName)
			io.WriteString(w, str)
			log.Default().Print(str)
		}
	})

	// Client CAs added to TLSConfig. Now, server can trust client certs.
	if data, err := os.ReadFile("certs/server/cint.crt"); err == nil {
		var block *pem.Block
		certpool := x509.NewCertPool()
		for block, data = pem.Decode(data); block != nil; block, data = pem.Decode(data) {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				certpool.AddCert(cert)
			}
		}
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.ClientCAs = certpool
	} else {
		return err
	}
	return nil
}

func main() {
	// Assign false to turnoff client auth
	const CLIENT_AUTH = false

	addHelloHandler()
	addBasicAuthHandler()

	cert, err := common.GetTLSCert(
		"certs/server/scas.crt",
		"certs/server/mysrv.local.crt",
		"certs/server/mysrv.local.key",
		[]byte("password"))
	if err != nil {
		log.Default().Fatal(err)
	}

	tlsConfig := &tls.Config{
		ServerName:   "mysrv.local",
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
	}

	if CLIENT_AUTH {
		if err := configureClientAuth(tlsConfig); err != nil {
			log.Default().Fatal(err)
		}
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
