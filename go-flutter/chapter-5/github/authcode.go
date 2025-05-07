/*
Chapter-5: Federated Authentication-II
Ultimate Web Authentication Handbook by Sambit Kumar Dash

This sample code shows the authorization code grant in OAuth 2.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.5 mysrv.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

# Go to the folder frontend and build the flutter application using

flutter build web

You will require a GitHub account with OAuth authentication enabled and set
up the environment variables:

GH_CLIENT_ID: <<GitHub OAuth Client ID>>
GH_CLIENT_SECRET: <<GitHub OAuth Client Secret>>

Start the server with the command: go run ./authcode.go

The website runs at https://mysrv.local:8443/
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
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

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
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}
}

func addOAuthHandlers() {
	client_id, ok := os.LookupEnv("GH_CLIENT_ID")
	if !ok {
		log.Panicf("Environment Variable GH_CLIENT_ID not found")
	}
	client_secret, ok := os.LookupEnv("GH_CLIENT_SECRET")
	if !ok {
		log.Panicf("Environment Variable GH_CLIENT_SECRET not found")
	}
	conf := &oauth2.Config{
		ClientID:     client_id,
		ClientSecret: client_secret,
		Scopes:       []string{"user"},
		Endpoint:     github.Endpoint,
	}

	states := make(map[string]struct{})
	muState := sync.RWMutex{}
	_setState := func(state string) {
		muState.Lock()
		defer muState.Unlock()
		states[state] = struct{}{}
	}

	_deleteState := func(state string) {
		muState.Lock()
		defer muState.Unlock()
		delete(states, state)
	}

	_existsState := func(state string) bool {
		muState.RLock()
		defer muState.RUnlock()
		_, ok := states[state]
		return ok
	}

	http.HandleFunc("/oauth/login", func(w http.ResponseWriter, req *http.Request) {
		state := uuid.New().String()
		_setState(state)
		conf.Scopes = []string{"user"}
		url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
		log.Print(fmt.Sprintf("Redirecting to: %s", url))
		http.Redirect(w, req, url, http.StatusFound)
	})

	http.HandleFunc("/oauth/logout", func(w http.ResponseWriter, req *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    "deleted",
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
			Expires:  time.Now().Add(-5 * time.Minute),
		})
		http.Redirect(w, req, "/", http.StatusFound)
	})

	http.HandleFunc("/oauth/callback", func(w http.ResponseWriter, req *http.Request) {
		state := req.FormValue("state")
		if _existsState(state) {
			log.Printf("State found: %s\n", state)
			_deleteState(state)
		} else {
			log.Println("Invalid state parameter")
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		}

		if err := req.FormValue("error"); err != "" {
			desc := req.FormValue("error_description")
			http.Error(w, desc, http.StatusUnauthorized)
		}
		if code := req.FormValue("code"); code != "" {
			conf.Scopes = []string{"read.user"}
			log.Printf("Reducing token scope to: %v\n", conf.Scopes)
			token, _ := conf.Exchange(context.Background(), code)
			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    token.AccessToken,
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
			})
			http.Redirect(w, req, "/", http.StatusFound)
		} else {
			http.Error(w, "Invalid code parameter", http.StatusUnauthorized)
		}
	})

	http.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if cookie == nil || err != nil {
			http.Error(w, "User not authorized.", http.StatusUnauthorized)
			return
		}
		client := conf.Client(context.Background(), &oauth2.Token{
			AccessToken: cookie.Value,
			TokenType:   "Bearer",
		})
		var (
			user_uri = "https://api.github.com/user"
			req      *http.Request
			res      *http.Response
		)
		if req, err = http.NewRequest("GET", user_uri, nil); err == nil {
			req.Header.Add("Accept", "application/vnd.github+json")
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
		http.FileServer(http.Dir("frontend/build/web")).ServeHTTP(w, r)
	})
	server := setupTLSServer("../certs/mysrv.p12", "mysrv.local")
	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
