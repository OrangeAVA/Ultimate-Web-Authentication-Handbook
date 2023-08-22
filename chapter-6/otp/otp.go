/*
Chapter-6: Multifactor Authentication
Hands-On Web Authentication by Sambit Kumar Dash

This sample code shows the HOTP and TOTP registration and validation workflows.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.5 mysrv.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Go to the folder frontend and build the flutter application using

flutter build web

Start the server with the command: go run ./otp.go

The website runs at https://mysrv.local:8443/

The server exposes the following endpoints.
/register - The front end obtains the OTP registration parameters from this
    endpoint.
/validate - Given a username and the generated OTP value, it validates the
    parameters.

The UI shows three views for registration, validation, and an authenticator.

*/

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"os"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/pkcs12"
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

func addOtpHandlers() {
	type _userData struct {
		Type    string
		Secret  string
		Counter uint64
	}
	users := map[string]*_userData{
		"alice": {
			Type:    "totp",
			Secret:  "ABCDEFGHIJKLMNOP",
			Counter: 1,
		},
	}

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		if username == "" {
			http.Error(w, "invalid username", http.StatusBadRequest)
			log.Print("invalid username")
			return
		}
		otptype := r.FormValue("type")
		if otptype == "" {
			otptype = "totp"
		}
		secret_bytes := make([]byte, 20)
		rand.Read(secret_bytes)
		secret := base32.StdEncoding.EncodeToString(secret_bytes)
		url := fmt.Sprintf("otpauth://%s/mysrv:%s?issuer=mysrv&secret=%s", otptype, username, secret)
		key, err := otp.NewKeyFromURL(url)
		if err != nil {
			http.Error(w, "failed to create key", http.StatusBadRequest)
			log.Print("failed to create key")
			return
		}

		keyinfo := map[string]string{
			"secret":    key.Secret(),
			"type":      key.Type(),
			"algorithm": key.Algorithm().String(),
			"digits":    key.Digits().String(),
		}

		img, err := key.Image(200, 200)
		if err != nil {
			http.Error(w, "failed to create QR code", http.StatusInternalServerError)
			log.Print("failed to create QR code")
			return
		}
		var imgbuf bytes.Buffer
		err = png.Encode(&imgbuf, img)
		if err != nil {
			http.Error(w, "failed to create QR code", http.StatusInternalServerError)
			log.Print("failed to create QR code")
			return
		}

		keyinfo["image"] = base64.StdEncoding.EncodeToString(imgbuf.Bytes())

		if otptype == "totp" {
			keyinfo["period"] = fmt.Sprint(key.Period())
		}
		w.Header().Set("Content-Type", "application/json")
		jsonResp, err := json.Marshal(keyinfo)
		if err != nil {
			http.Error(w, "failed to generate JSON repsonse", http.StatusInternalServerError)
			log.Print("failed to generate JSON repsonse")
			return
		}
		log.Printf("new %s key provisioned for the user %s", key.Type(), username)
		w.Write(jsonResp)
		users[username] = &_userData{
			Type:    key.Type(),
			Secret:  key.Secret(),
			Counter: 1,
		}
	})

	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		otp := r.FormValue("otp")
		if username == "" || otp == "" {
			http.Error(w, "invalid username or otp", http.StatusUnauthorized)
			log.Print("invalid username or otp")
			return
		}
		authdata, ok := users[username]
		if !ok {
			http.Error(w, "invalid username or otp", http.StatusUnauthorized)
			log.Print("invalid username or otp")
			return
		}
		if authdata.Type == "hotp" {
			ok = hotp.Validate(otp, authdata.Counter, authdata.Secret)
			if ok {
				authdata.Counter++
			}
		} else {
			ok = totp.Validate(otp, authdata.Secret)
		}
		if ok {
			log.Printf("User %s authenticated successfully", username)
			return
		} else {
			http.Error(w, "invalid username or otp", http.StatusUnauthorized)
			log.Print("invalid username or otp")
		}
	})
}

func main() {
	addOtpHandlers()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("frontend/build/web")).ServeHTTP(w, r)
	})
	server := setupTLSServer("../certs/mysrv.p12", "mysrv.local")
	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
