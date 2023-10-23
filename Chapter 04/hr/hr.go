/*
Chapter-4: Federated Authentication-I
Hands-On Web Authentication by Sambit Kumar Dash

This code represents the HR App in the demo discussed in the book. The
application implements a SAML SP and requires a SAML IDP to run.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.4 hr.mysrv.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Start the server with the command: go run ./hr.go

Go to the folder frontend and build the flutter application using

flutter build web

The website runs at https://hr.mysrv.local:8444/

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
	"time"

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
		Addr:      ":8444",
		TLSConfig: tlsConfig,
	}
}

func main() {
	rootURL, err := url.Parse("https://hr.mysrv.local:8444")
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

	key, cert, err := getProviderCertAndKey("certs/hr.p12")
	if err != nil {
		panic(err)
	}

	database := map[string]int{
		"alice": 30,
		"bob":   10,
		"carol": 15,
		"don":   7,
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
	http.Handle("/", http.FileServer(http.Dir("frontend/build/web")))

	http.Handle("/auth/",
		samlSP.RequireAccount(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sProvider := samlSP.Session
				switch r.URL.Path {
				case "/auth/logout":
					sProvider.DeleteSession(w, r)
					http.SetCookie(w, &http.Cookie{
						Name:     "uid",
						Value:    "deleted",
						HttpOnly: false,
						Secure:   true,
						Path:     "/",
						Expires:  time.Now().Add(-5 * time.Minute),
					})
				default:
					if session, err := sProvider.GetSession(r); err == nil {
						uid := session.(samlsp.SessionWithAttributes).GetAttributes().Get("uid")
						http.SetCookie(w, &http.Cookie{
							Name:     "uid",
							Value:    uid,
							HttpOnly: false,
							Secure:   true,
							Path:     "/",
						})
						log.Default().Println("The user ", uid, " logged in successfully.")
					}
				}
				http.Redirect(w, r, "/", http.StatusFound)
			}),
		),
	)

	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		if session, err := samlSP.Session.GetSession(r); err == nil {
			attr := session.(samlsp.SessionWithAttributes).GetAttributes()
			var jsValue []byte
			bFound := false
			for _, v := range attr["eduPersonAffiliation"] {
				switch v {
				case "hradmin":
					jsValue, _ = json.Marshal(database)
					bFound = true
				case "users":
					uid := attr.Get("uid")
					jsValue = []byte(fmt.Sprintf("{ \"%s\" : %d}", uid, database[uid]))
				}
				if bFound {
					break
				}
			}
			w.Write(jsValue)
		} else {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
		}
	})
	server := setupTLSServer("certs/ssl/hr.mysrv.local.p12", "hr.mysrv.local")
	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
