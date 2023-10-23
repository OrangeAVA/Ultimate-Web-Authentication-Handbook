/*
Chapter-6: Multifactor Authentication
Hands-On Web Authentication by Sambit Kumar Dash

This demo shows how to run an OAuth 2 server with TOTP and WebAuthn as
authenticators. The user alice has a temporary password (password). She
authenticates into the system and then registers a TOTP and FIDO 2 credential.
When both are registered, she does not need the password.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.2 mysrv.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Go to the folder mysrvfront and build the flutter application using
flutter build web

Start the server with the command: go run ./mysrv.go

The website runs at https://idp.local:8444/

You will need to run the IDP and the SP simultaneously.

*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	session "github.com/go-session/session/v3"
	"github.com/google/uuid"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/oauth2"
)

func addOAuthHandlers() {
	conf := &oauth2.Config{
		ClientID:     "222222",
		ClientSecret: "22222222",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://idp.local:8443/oauth/authorize",
			TokenURL: "https://idp.local:8443/oauth/token",
		},
	}

	http.HandleFunc("/oauth/login", func(w http.ResponseWriter, req *http.Request) {
		store, _ := session.Start(req.Context(), w, req)
		guid := uuid.New().String()
		store.Set("state", guid)
		store.Save()

		url := conf.AuthCodeURL(guid,
			oauth2.SetAuthURLParam(
				"redirect_uri",
				"https://mysrv.local:8444/oauth/callback",
			),
		)
		log.Print(fmt.Sprintf("Redirecting to: %s", url))
		http.Redirect(w, req, url, http.StatusFound)
	})

	http.HandleFunc("/oauth/callback", func(w http.ResponseWriter, req *http.Request) {
		state := req.FormValue("state")

		store, _ := session.Start(req.Context(), w, req)
		tstate, ok := store.Get("state")
		if ok && state == tstate {
			log.Printf("State found: %s\n", state)
			store.Delete("state")
			store.Save()
		} else {
			log.Println("Invalid state parameter")
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		if err := req.FormValue("error"); err != "" {
			desc := req.FormValue("error_description")
			http.Error(w, desc, http.StatusUnauthorized)
		}
		if code := req.FormValue("code"); code != "" {
			token, _ := conf.Exchange(context.Background(), code, oauth2.SetAuthURLParam(
				"redirect_uri", "https://mysrv.local:8444/oauth/callback"))
			store.Set("token", token.AccessToken)
			store.Save()
			http.Redirect(w, req, "/", http.StatusFound)
		} else {
			http.Error(w, "Invalid code parameter", http.StatusUnauthorized)
		}
	})

	http.HandleFunc("/oauth/logout", func(w http.ResponseWriter, req *http.Request) {
		store, _ := session.Start(req.Context(), w, req)
		log.Println("Logging out the user")
		ti := store.Delete("token")
		if ti != nil {
			token := ti.(string)
			url := fmt.Sprintf("https://idp.local:8443/logout?access_token=%s", token)
			log.Print(fmt.Sprintf("Redirecting to: %s", url))
			http.Redirect(w, req, url, http.StatusFound)
		} else {
			http.Redirect(w, req, "/", http.StatusFound)
		}
	})

	http.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		store, _ := session.Start(r.Context(), w, r)
		token, ok := store.Get("token")
		if !ok {
			http.Error(w, "User not authorized.", http.StatusUnauthorized)
			return
		}
		client := conf.Client(context.Background(), &oauth2.Token{
			AccessToken: token.(string),
			TokenType:   "Bearer",
		})
		var (
			user_uri = "https://idp.local:8443/test"
			req      *http.Request
			res      *http.Response
			err      error
		)
		if req, err = http.NewRequest("GET", user_uri, nil); err == nil {
			req.Header.Add("Accept", "application/json")
			if res, err = client.Do(req); err == nil {
				if res.StatusCode == 200 {
					defer res.Body.Close()
					b, _ := io.ReadAll(res.Body)
					w.Header().Set("Content-Type", "application/json")
					w.Write(b)
				}
			} else {
				log.Printf(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	})
}

func main() {
	addOAuthHandlers()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("mysrvfront/build/web")).ServeHTTP(w, r)
	})
	StartTLSServer("../certs/mysrv.p12", "mysrv.local", "8444")
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

func StartTLSServer(certloc string, srvName string, port string) {
	cert, err := getTLSCert(certloc)
	if err != nil {
		log.Default().Fatal(err)
	}

	tlsConfig := &tls.Config{
		ServerName:   srvName,
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}

	server := http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
	}

	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
