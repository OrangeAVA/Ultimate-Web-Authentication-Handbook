/*
Chapter-4: Federated Authentication-I
Ultimate Web Authentication Handbook by Sambit Kumar Dash

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.2 idp.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Start the server with the command: go run ./idp.go

# Go to the folder frontend and build the flutter application using

flutter build web

The website runs at https://idp.local:8443/

The IDP provides a SAML IDP.

*/

package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/crewjam/saml/samlidp"
	"github.com/crewjam/saml/samlsp"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"

	"howa.in/common"
)

var sploaded bool = false

func setupTLSServer(srvName string) *http.Server {
	cert, err := common.GetTLSCert(
		"certs/ssl/scas.crt",
		fmt.Sprintf("certs/ssl/%s.crt", srvName),
		fmt.Sprintf("certs/ssl/%s.key", srvName),
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
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}
}

func addSP(httpsclient *http.Client, fn string, svcurl string, svcname string, mdurl string, scurl string) {
	if file, err := os.Open(fn); err == nil {
		defer file.Close()

		uri, _ := url.Parse(svcurl)
		req := http.Request{
			Method: http.MethodPut,
			URL:    uri,
			Body:   file,
		}

		if _, err := httpsclient.Do(&req); err != nil {
			log.Fatal(err)
		}

		shortcut := samlidp.Shortcut{
			Name:                  svcname,
			ServiceProviderID:     mdurl,
			URISuffixAsRelayState: true,
		}

		data, _ := json.Marshal(&shortcut)

		uri, _ = url.Parse(scurl)
		req = http.Request{
			Method: http.MethodPut,
			URL:    uri,
			Body:   io.NopCloser(bytes.NewReader(data)),
		}

		if _, err := httpsclient.Do(&req); err != nil {
			log.Fatal(err)
		}
	}
}

func addServiceProviders(w http.ResponseWriter, r *http.Request) {

	httpsclient, err := common.GetHTTPSClient("certs/ssl/scas.crt")
	if err != nil {
		log.Fatal(err)
	}
	addSP(httpsclient,
		"sp/idpportal.xml",
		"https://idp.local:8443/idp/services/idpportal",
		"IDPPortal",
		"https://idp.local:8443/saml/metadata",
		"https://idp.local:8443/idp/shortcuts/idpportal")
	addSP(httpsclient,
		"sp/hr.xml",
		"https://idp.local:8443/idp/services/hr",
		"HR",
		"https://hr.mysrv.local:8444/saml/metadata",
		"https://idp.local:8443/idp/shortcuts/hr")
	addSP(httpsclient,
		"sp/finance.xml",
		"https://idp.local:8443/idp/services/finance",
		"Finance",
		"https://hr.mysrv.local:8445/saml/metadata",
		"https://idp.local:8443/idp/shortcuts/finance")
	sploaded = true
	http.SetCookie(w, &http.Cookie{
		Name:     "sploaded",
		Value:    strconv.FormatBool(sploaded),
		HttpOnly: false,
		Path:     "/",
	})
}

func addUsers(idpServer *samlidp.Server) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

	idpServer.Store.Put("/users/alice", samlidp.User{
		Name:           "alice",
		HashedPassword: hashedPassword,
		Groups:         []string{"hradmin", "users"},
		Email:          "alice@example.com",
		CommonName:     "Alice Smith",
		Surname:        "Smith",
		GivenName:      "Alice",
	})

	idpServer.Store.Put("/users/bob", samlidp.User{
		Name:           "bob",
		HashedPassword: hashedPassword,
		Groups:         []string{"financeadmin", "users"},
		Email:          "bob@example.com",
		CommonName:     "Bob Smith",
		Surname:        "Smith",
		GivenName:      "Bob",
	})

	idpServer.Store.Put("/users/carol", samlidp.User{
		Name:           "carol",
		HashedPassword: hashedPassword,
		Groups:         []string{"itadmin", "users"},
		Email:          "carol@example.com",
		CommonName:     "Carol Smith",
		Surname:        "Smith",
		GivenName:      "Carol",
	})

	idpServer.Store.Put("/users/don", samlidp.User{
		Name:           "don",
		HashedPassword: hashedPassword,
		Groups:         []string{"users"},
		Email:          "don@example.com",
		CommonName:     "Don Lewis",
		Surname:        "Lewis",
		GivenName:      "Don",
	})
}

func addIDPAuth(idpServer *samlidp.Server, key *rsa.PrivateKey, cert *x509.Certificate) {
	rootURL, err := url.Parse("https://idp.local:8443/")
	if err != nil {
		log.Default().Fatalf("cannot parse base URL: %v", err)
	}

	if idpAuth, err := samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               key,
		Certificate:       cert,
		AllowIDPInitiated: true,
		SignRequest:       true,
		IDPMetadata:       idpServer.IDP.Metadata(),
	}); err != nil {
		log.Default().Fatalf("Unable to start HR SP %v", err)
	} else {
		http.Handle("/saml/", idpAuth)
		http.Handle("/auth/",
			idpAuth.RequireAccount(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					sProvider := idpAuth.Session
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
						if c, err := r.Cookie("session"); err == nil {
							idpServer.Store.Delete(fmt.Sprintf("/sessions/%s", c.Value))
							http.SetCookie(w, &http.Cookie{
								Name:     "session",
								Value:    "deleted",
								HttpOnly: false,
								Path:     "/",
								Expires:  time.Now().Add(-5 * time.Minute),
							})
						}
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
	}
}

func invalidateIDPSession(w http.ResponseWriter, r *http.Request, idpServer *samlidp.Server) {
	if ck, err := r.Cookie("session"); err == nil {
		sessions, _ := idpServer.Store.List("/sessions/")
		bFound := false
		for _, s := range sessions {
			if ck.Value == s {
				bFound = true
				break
			}
		}
		if !bFound {
			http.SetCookie(w, &http.Cookie{
				Name:     "uid",
				Value:    "deleted",
				HttpOnly: false,
				Secure:   true,
				Path:     "/",
				Expires:  time.Now().Add(-5 * time.Minute),
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    "deleted",
				HttpOnly: false,
				Path:     "/",
				Expires:  time.Now().Add(-5 * time.Minute),
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    "deleted",
				Domain:   ".idp.local",
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				Expires:  time.Now().Add(-5 * time.Minute),
			})
			log.Default().Print(err)
		}
	}
}

func main() {
	var baseURL *url.URL
	var err error
	var key crypto.PrivateKey
	var cert *x509.Certificate

	if baseURL, err = url.Parse("https://idp.local:8443/idp"); err != nil {
		log.Default().Fatalf("cannot parse base URL: %v", err)
	}

	if key, cert, err = common.GetProviderCertAndKey("certs/idp.crt", "certs/idp.key", []byte("password")); err != nil {
		log.Default().Fatalf("%v", err)
	}

	if idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         key,
		Certificate: cert,
		Store:       &samlidp.MemoryStore{},
	}); err != nil {
		log.Default().Fatalf("%s", err)
	} else {
		addUsers(idpServer)

		cors := cors.New(cors.Options{
			AllowedOrigins: []string{"https://hr.mysrv.local:8444", "https://finance.mysrv.local:8445"},
		})
		http.Handle("/idp/", cors.Handler(http.StripPrefix("/idp", idpServer)))
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:     "sploaded",
				Value:    strconv.FormatBool(sploaded),
				HttpOnly: false,
				Path:     "/",
			})
			invalidateIDPSession(w, r, idpServer)
			http.FileServer(http.Dir("frontend/build/web")).ServeHTTP(w, r)
		})
		http.HandleFunc("/addsps", addServiceProviders)
		addIDPAuth(idpServer, key.(*rsa.PrivateKey), cert)
	}
	server := setupTLSServer("idp.local")
	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
