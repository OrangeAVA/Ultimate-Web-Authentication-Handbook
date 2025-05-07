/*
Chapter-4: Federated Authentication-I
Ultimate Web Authentication Handbook by Sambit Kumar Dash

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
	"github.com/youmark/pkcs8"
)

func getProviderCertAndKey(certpath, keypath string, keypass []byte) (key *rsa.PrivateKey, cert *x509.Certificate, err error) {
	var data []byte
	if data, err = os.ReadFile(keypath); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if key, err = pkcs8.ParsePKCS8PrivateKeyRSA(block.Bytes, keypass); err != nil {
				return
			}
		}
	}
	if data, err = os.ReadFile(certpath); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			cert, err = x509.ParseCertificate(block.Bytes)
		}
	}
	return
}

func addCertificates(certpath string, c *tls.Certificate) (err error) {
	var (
		data  []byte
		block *pem.Block
	)
	if data, err = os.ReadFile(certpath); err == nil {
		for block, data = pem.Decode(data); block != nil; block, data = pem.Decode(data) {
			if block.Type == "CERTIFICATE" {
				c.Certificate = append(c.Certificate, block.Bytes)
			}
		}
	}
	return
}

/*
Server certificate
*/
func getTLSCert(capath, certpath, keypath string, keypass []byte) (c *tls.Certificate, err error) {
	var (
		data  []byte
		block *pem.Block
		cert  tls.Certificate
	)

	if err = addCertificates(certpath, &cert); err == nil {
		if err = addCertificates(capath, &cert); err == nil {
			if data, err = os.ReadFile(keypath); err == nil {
				if block, _ = pem.Decode(data); block != nil {
					if cert.PrivateKey, _, err = pkcs8.ParsePrivateKey(block.Bytes, keypass); err == nil {
						if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err == nil {
							c = &cert
						}
					}
				} else {
					err = fmt.Errorf("no private key data found")
				}
			}
		}
	}
	return
}

func setupTLSServer(srvName string) *http.Server {
	cert, err := getTLSCert(
		"certs/server/scas.crt",
		fmt.Sprintf("certs/server/%s.crt", srvName),
		fmt.Sprintf("certs/server/%s.key", srvName),
		[]byte("password"))
	if err != nil {
		log.Default().Fatal(err)
	}

	tlsConfig := &tls.Config{
		ServerName:   srvName,
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
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

	key, cert, err := getProviderCertAndKey("certs/hr.crt", "certs/hr.key", []byte("password"))
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
	server := setupTLSServer("hr.mysrv.local")
	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
