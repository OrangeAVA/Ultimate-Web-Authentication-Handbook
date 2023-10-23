/*
Chapter-4: Federated Authentication-I
Hands-On Web Authentication by Sambit Kumar Dash

This code represents the Finance App in the demo discussed in the book. The
application implements a SAML SP and requires a SAML IDP to run.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.3 finance.mysrv.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Start the server with the command: go run ./finance.go

# Go to the folder frontend and build the flutter application using

flutter build web

The website runs at https://finance.mysrv.local:8445/

Make sure you have the IDP running before launching this service.
*/
package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml/samlsp"
	"golang.org/x/crypto/pkcs12"
)

func getProviderCertAndKey(certloc string) (key *rsa.PrivateKey, cert *x509.Certificate, err error) {
	var (
		fdata  []byte
		blocks []*pem.Block
	)
	if fdata, err = os.ReadFile(certloc); err == nil {
		if blocks, err = pkcs12.ToPEM(fdata, "password"); err == nil {
			for _, b := range blocks {
				if b.Type == "CERTIFICATE" {
					cert, err = x509.ParseCertificate(b.Bytes)
				} else if b.Type == "PRIVATE KEY" {
					key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
				}
			}
		}
	}
	return
}

func getTLSCert(certloc string) (cert tls.Certificate, err error) {
	var (
		fdata   []byte
		blocks  []*pem.Block
		pemData []byte
	)
	if fdata, err = os.ReadFile(certloc); err == nil {
		if blocks, err = pkcs12.ToPEM(fdata, "password"); err == nil {
			for _, b := range blocks {
				pemData = append(pemData, pem.EncodeToMemory(b)...)
			}
			cert, err = tls.X509KeyPair(pemData, pemData)
		}
	}
	return
}

func setupTLSServer(certloc string, srvName string) *http.Server {
	cert, err := getTLSCert(certloc)
	if err != nil {
		log.Default().Fatal(err)
	}

	tlsConfig := &tls.Config{
		ServerName:   srvName,
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}

	return &http.Server{
		Addr:      ":8445",
		TLSConfig: tlsConfig,
	}
}

func main() {
	rootURL, err := url.Parse("https://finance.mysrv.local:8445")
	if err != nil {
		log.Default().Fatal(err)
	}

	idpMetadataURL, err := url.Parse("https://idp.local:8443/idp/metadata")
	if err != nil {
		log.Default().Fatalf("IDP not running at: https://idp.local:8443 %v", err)
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	if err != nil {
		log.Default().Fatalf("Failed to download IDP metadata %v", err)
	}

	key, cert, err := getProviderCertAndKey("certs/finance.p12")
	if err != nil {
		panic(err)
	}

	database := map[string]int{
		"alice": 2000,
		"bob":   1000,
		"carol": 1500,
		"don":   1800,
	}

	samlSP, err := samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               key,
		Certificate:       cert,
		AllowIDPInitiated: true,
		SignRequest:       true,
		IDPMetadata:       idpMetadata,
	})
	if err != nil {
		log.Default().Fatalf("Unable to start HR SP %v", err)
	}

	http.Handle("/saml/", samlSP)
	http.Handle("/", samlSP.RequireAccount(http.FileServer(http.Dir("frontend/build/web"))))
	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		if session, err := samlSP.Session.GetSession(r); err == nil {
			attr := session.(samlsp.SessionWithAttributes).GetAttributes()
			for _, v := range attr["eduPersonAffiliation"] {
				switch v {
				case "financeadmin":
					jsValue, _ := json.Marshal(database)
					w.Write(jsValue)
					return
				case "users":
					uid := attr.Get("uid")
					js := fmt.Sprintf("{ \"%s\" : %d}", uid, database[uid])
					w.Write([]byte(js))
					return
				}
			}
		} else {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
		}
	})
	server := setupTLSServer("certs/ssl/finance.mysrv.local.p12", "finance.mysrv.local")
	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
