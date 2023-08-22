/*
Chapter-5: Federated Authentication-II
Hands-On Web Authentication by Sambit Kumar Dash

This sample code shows the authorization code grant in OAuth 2.

# Go to the folder frontend and build the flutter application using

flutter build web

You will require a Google account with OAuth authentication enabled and set
up the environment variables:

GOOGLE_CLIENT_ID: <<Google OAuth Client ID>>
GOOGLE_CLIENT_SECRET: <<Google OAuth Client Secret>>

Start the server with the command: go run ./oidc.go

The website runs at http://localhost:8444/
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/oauth2"
)

func _setCookie(w http.ResponseWriter, name string, value string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: httpOnly,
		Secure:   true,
		Path:     "/",
	})
}

func _deleteCookie(w http.ResponseWriter, name string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "deleted",
		HttpOnly: httpOnly,
		Secure:   true,
		Path:     "/",
		Expires:  time.Now().Add(-5 * time.Minute),
	})
}

func addOIDCHandlers() {
	provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		log.Panicf("OIDC Provider for Google not found")
	}

	client_id, ok := os.LookupEnv("GOOGLE_CLIENT_ID")
	if !ok {
		log.Panicf("Environment Variable GOOGLE_CLIENT_ID not found")
	}
	client_secret, ok := os.LookupEnv("GOOGLE_CLIENT_SECRET")
	if !ok {
		log.Panicf("Environment Variable GOOGLE_CLIENT_SECRET not found")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: client_id})

	conf := &oauth2.Config{
		ClientID:     client_id,
		ClientSecret: client_secret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		RedirectURL:  "http://localhost:8444/oauth/callback",
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

	tokens := make(map[string]*oauth2.Token)
	muToken := sync.RWMutex{}
	_deleteToken := func(w http.ResponseWriter, req *http.Request) {
		if cookie, _ := req.Cookie("session"); cookie != nil {
			muToken.Lock()
			defer muToken.Unlock()
			delete(tokens, cookie.Value)
		}
		_deleteCookie(w, "session", true)
	}

	_saveToken := func(w http.ResponseWriter, token *oauth2.Token) (err error) {
		idTokenStr := token.Extra("id_token").(string)
		log.Printf("ID Token: %s", idTokenStr)
		var idToken *oidc.IDToken

		if idToken, err = verifier.Verify(context.Background(), idTokenStr); err == nil {
			if err = idToken.VerifyAccessToken(token.AccessToken); err == nil {
				uuidstr := uuid.NewString()
				muToken.Lock()
				defer muToken.Unlock()
				tokens[uuidstr] = token
				_setCookie(w, "session", uuidstr, true)
			}
		}
		return
	}

	http.HandleFunc("/oauth/login", func(w http.ResponseWriter, req *http.Request) {
		state := uuid.New().String()
		_setState(state)
		url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
		log.Printf("Redirecting to: %v", url)
		http.Redirect(w, req, url, http.StatusFound)
	})

	http.HandleFunc("/oauth/logout", func(w http.ResponseWriter, req *http.Request) {
		_deleteToken(w, req)
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
			return
		}

		if errs := req.FormValue("error"); errs != "" {
			desc := req.FormValue("error_description")
			log.Print(desc)
			http.Error(w, desc, http.StatusUnauthorized)
			return
		}
		var (
			token *oauth2.Token
			err   error
			code  string
		)
		if code = req.FormValue("code"); code != "" {
			if token, err = conf.Exchange(req.Context(), code); err == nil {
				log.Printf("The token is expiring at: %v", token.Expiry)
				if err = _saveToken(w, token); err == nil {
					http.Redirect(w, req, "/", http.StatusFound)
				}
			}
		} else {
			err = fmt.Errorf("invalid code parameter")
		}
		if err != nil {
			log.Print(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
	})

	_getToken := func(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error) {
		if cookie, err := r.Cookie("session"); err == nil {
			muToken.RLock()
			defer muToken.RUnlock()
			if token, ok := tokens[cookie.Value]; ok {
				return token, nil
			}
		}
		_deleteCookie(w, "session", false)
		return nil, fmt.Errorf("user not authorized")
	}

	_keyFunc := func(t *jwt.Token) (key interface{}, err error) {
		var (
			iss string
			res *http.Response
		)
		if iss, err = t.Claims.GetIssuer(); err != nil {
			return
		}

		wk := iss
		if !strings.HasSuffix(iss, "/") {
			wk += "/"
		}
		wk += ".well-known/openid-configuration"

		if res, err = http.Get(wk); err != nil {
			return
		}

		if res.StatusCode != 200 {
			err = fmt.Errorf("unable to access OIDC configuration")
			return
		}

		defer res.Body.Close()
		m := make(map[string]interface{})

		if err = json.NewDecoder(res.Body).Decode(&m); err != nil {
			return
		}

		if res, err = http.Get(m["jwks_uri"].(string)); err != nil {
			return
		}

		if res.StatusCode != 200 {
			err = fmt.Errorf("unable to access public key")
			return
		}

		defer res.Body.Close()
		if err = json.NewDecoder(res.Body).Decode(&m); err != nil {
			return
		}

		for _, k := range m["keys"].([]interface{}) {
			tk := k.(map[string]interface{})
			if tk["kid"].(string) == t.Header["kid"].(string) {
				log.Println("found signing key.")
				var b []byte
				if b, err = json.Marshal(tk); err != nil {
					return
				}
				var kk jwk.Key
				if kk, err = jwk.ParseKey(b); err != nil {
					return
				}
				err = kk.Raw(&key)
				return
			}
		}
		return
	}

	http.HandleFunc("/idtoken", func(w http.ResponseWriter, r *http.Request) {
		token, err := _getToken(w, r)
		if err != nil {
			log.Print(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ts := conf.TokenSource(r.Context(), token)
		ntoken, err := ts.Token()
		if err != nil {
			log.Print(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if ntoken != token {
			log.Println("Refreshed the token and saving...")
			err = _saveToken(w, ntoken)
			token = ntoken
		}
		if err != nil {
			log.Print(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims := jwt.MapClaims{}
		idTokenStr := token.Extra("id_token").(string)
		if idtoken, err := jwt.NewParser().ParseWithClaims(idTokenStr, &claims, _keyFunc); err == nil {
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			enc.Encode(idtoken)
		} else {
			log.Print(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
	})

	http.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		var (
			err           error
			ntoken, token *oauth2.Token
			ts            oauth2.TokenSource
			ui            *oidc.UserInfo
		)

		token, err = _getToken(w, r)
		if err != nil {
			log.Print(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ts = conf.TokenSource(r.Context(), token)
		if ntoken, err = ts.Token(); err == nil {
			if ntoken != token {
				log.Println("Refreshed the token and saving...")
				err = _saveToken(w, ntoken)
			}
		}
		if err == nil {
			if ui, err = provider.UserInfo(r.Context(), ts); err == nil {
				claims := make(map[string]interface{})
				if err = ui.Claims(&claims); err == nil {
					w.Header().Set("Content-Type", "application/json")
					enc := json.NewEncoder(w)
					enc.SetIndent("", "  ")
					enc.Encode(claims)
				}
			}
		}

		if err != nil {
			log.Print(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
	})
}

func main() {
	addOIDCHandlers()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("frontend/build/web")).ServeHTTP(w, r)
	})
	server := &http.Server{
		Addr: ":8444",
	}
	log.Default().Fatal(server.ListenAndServe())
}
