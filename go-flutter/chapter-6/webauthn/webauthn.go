/*
Chapter-6: Multifactor Authentication
Ultimate Web Authentication Handbook by Sambit Kumar Dash

This sample code shows the WebAuthn registration and validation workflows.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.5 mysrv.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Go to the folder frontend and build the flutter application using

flutter build web

Start the server with the command: go run ./webauthn.go

The website runs at https://mysrv.local:8443/

The server exposes the following endpoints.

/register/begin
/register/finish

These end points used for registering a FIDO token over WebAuthn.

/login/begin
/login/finish

These end points used for authenticating with the WebAuthn token.

The UI shows two views for registration and authentication.

*/

package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"os"

	"github.com/go-openssl/pkcs12"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
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

type userImpl struct {
	_WebAuthnID          []byte
	_WebAuthnName        string
	_WebAuthnDisplayName string
	_WebAuthnCredentials []webauthn.Credential
}

func (u userImpl) WebAuthnID() []byte {
	return u._WebAuthnID
}

func (u userImpl) WebAuthnName() string {
	return u._WebAuthnName
}

func (u userImpl) WebAuthnDisplayName() string {
	return u._WebAuthnDisplayName
}

func (u userImpl) WebAuthnCredentials() []webauthn.Credential {
	return u._WebAuthnCredentials
}

func (u userImpl) WebAuthnIcon() string {
	return ""
}

func (u *userImpl) AddCredential(c *webauthn.Credential) {
	u._WebAuthnCredentials = append(u._WebAuthnCredentials, *c)
}

type DataStore map[string]interface{}

func (d DataStore) SaveUser(u webauthn.User) {
	d[u.WebAuthnName()] = u
}

func (d DataStore) GetUser(username string) webauthn.User {
	u, ok := d[username]
	if !ok {
		buf := make([]byte, 64)
		_, err := rand.Read(buf)
		if err != nil {
			return nil
		}
		usr := userImpl{
			_WebAuthnID:          buf,
			_WebAuthnName:        username,
			_WebAuthnDisplayName: username,
			_WebAuthnCredentials: make([]webauthn.Credential, 0),
		}
		d.SaveUser(usr)
		u = usr
	}
	return u.(webauthn.User)
}

func (d DataStore) SaveSession(state string, s *webauthn.SessionData) {
	d[state] = s
}

func (d DataStore) GetSession(state string) *webauthn.SessionData {
	return d[state].(*webauthn.SessionData)
}

func addWebAuthnHandlers() {
	datastore := DataStore{}

	wconfig := &webauthn.Config{
		RPDisplayName: "HOWA Webauthn",
		RPID:          "mysrv.local",
		RPOrigins:     []string{"https://mysrv.local:8443"},
	}

	wauthn, err := webauthn.New(wconfig)
	if err != nil {
		log.Fatal(err)
	}

	jsonResponse := func(w http.ResponseWriter, obj interface{}) {
		w.Header().Set("Content-Type", "application/json")
		jsonResp, _ := json.MarshalIndent(obj, "", "  ")
		w.Write(jsonResp)
	}

	http.HandleFunc("/webauthn/register/begin", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		if username == "" {
			http.Error(w, "invalid username", http.StatusBadRequest)
			log.Print("invalid username")
			return
		}

		state := r.FormValue("state")
		if state == "" {
			http.Error(w, "invalid state", http.StatusBadRequest)
			log.Print("invalid state")
			return
		}

		user := datastore.GetUser(username)
		options, session, err := wauthn.BeginRegistration(user, webauthn.WithCredentialParameters(
			[]protocol.CredentialParameter{
				{
					Type:      protocol.PublicKeyCredentialType,
					Algorithm: webauthncose.AlgES256,
				},
				{
					Type:      protocol.PublicKeyCredentialType,
					Algorithm: webauthncose.AlgRS256,
				},
			},
		))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			log.Print(err.Error())
			return
		}

		optionsJson, _ := json.MarshalIndent(options, "", "  ")
		optionsJson = append(optionsJson, byte('\n'))
		log.Writer().Write(optionsJson)

		datastore.SaveSession(state, session)
		jsonResponse(w, options)
		log.Printf("Sending registration information for user: %s state: %s", username, state)
	})

	http.HandleFunc("/webauthn/register/finish", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		if username == "" {
			http.Error(w, "invalid username", http.StatusBadRequest)
			log.Print("invalid username")
			return
		}

		state := r.FormValue("state")
		if state == "" {
			http.Error(w, "invalid state", http.StatusBadRequest)
			log.Print("invalid state")
			return
		}

		ccr, err := protocol.ParseCredentialCreationResponse(r)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			perr := err.(*protocol.Error)
			log.Print(perr.Error(), ' ', perr.DevInfo)
			return
		}

		session := datastore.GetSession(state)

		if ccr.Response.CollectedClientData.Challenge != session.Challenge {
			http.Error(w, "Internal Server Error", http.StatusBadRequest)
			log.Print("invalid session or client")
			return
		}

		ccrRespJson, _ := json.MarshalIndent(ccr.Response, "", "  ")
		ccrRespJson = append(ccrRespJson, byte('\n'))
		log.Writer().Write(ccrRespJson)

		user := datastore.GetUser(username).(userImpl) // Get the user

		// Get the session data stored from the function above

		credential, err := wauthn.CreateCredential(user, *session, ccr)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Print(err)
			return
		}

		jsonResponse(w, &struct {
			Message string `json:"message"`
		}{Message: "Registration Success"})
		user.AddCredential(credential)
		datastore.SaveUser(user)

		log.Printf("User: %s registered a WebAuthn credential.", username)
	})

	http.HandleFunc("/webauthn/login/begin", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		if username == "" {
			http.Error(w, "invalid username", http.StatusBadRequest)
			log.Print("invalid username")
			return
		}

		state := r.FormValue("state")
		if state == "" {
			http.Error(w, "invalid state", http.StatusBadRequest)
			log.Print("invalid state")
			return
		}

		user := datastore.GetUser(username)
		options, session, err := wauthn.BeginLogin(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			log.Printf("user: %s error: %s", username, err.Error())
			return
		}

		optionsJson, _ := json.MarshalIndent(options, "", "  ")
		optionsJson = append(optionsJson, byte('\n'))
		log.Writer().Write(optionsJson)

		datastore.SaveSession(state, session)
		jsonResponse(w, options)
		log.Printf("Sending login information for user: %s state: %s", username, state)
	})

	http.HandleFunc("/webauthn/login/finish", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		if username == "" {
			http.Error(w, "invalid username", http.StatusBadRequest)
			log.Print("invalid username")
			return
		}

		state := r.FormValue("state")
		if state == "" {
			http.Error(w, "invalid state", http.StatusBadRequest)
			log.Print("invalid state")
			return
		}

		cad, err := protocol.ParseCredentialRequestResponse(r)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			perr := err.(*protocol.Error)
			log.Print(perr.Error(), ' ', perr.DevInfo)
			return
		}

		session := datastore.GetSession(state)

		if cad.Response.CollectedClientData.Challenge != session.Challenge {
			http.Error(w, "Internal Server Error", http.StatusBadRequest)
			log.Print("invalid session or client")
			return
		}

		cadRespJson, _ := json.MarshalIndent(cad.Response, "", "  ")
		cadRespJson = append(cadRespJson, byte('\n'))
		log.Writer().Write(cadRespJson)

		user := datastore.GetUser(username).(userImpl) // Get the user

		// Get the session data stored from the function above

		_, err = wauthn.ValidateLogin(user, *session, cad)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			log.Print(err)
			return
		}

		jsonResponse(w, &struct {
			Message string `json:"message"`
		}{Message: "Authentication Successful."})
		log.Printf("User: %s authenticated successfully.", username)
	})
}

func main() {
	addWebAuthnHandlers()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("frontend/build/web")).ServeHTTP(w, r)
	})
	server := setupTLSServer("../certs/mysrv.p12", "mysrv.local")
	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
