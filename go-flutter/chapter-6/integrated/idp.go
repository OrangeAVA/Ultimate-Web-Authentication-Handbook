/*
Chapter-6: Multifactor Authentication
Ultimate Web Authentication Handbook by Sambit Kumar Dash

The server provides a OAuth authentication server for registration and
authentication with TOTP and WebAuthn.The frontend code is generated using
JavaScript templates embedded in the code.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.2 idp.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Start the server with the command: go run ./idp.go

The website runs at https://idp.local:8443/

*/

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"image"
	"image/png"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-openssl/pkcs12"
	sess "github.com/go-session/session/v3"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func jsonResponse(w http.ResponseWriter, obj interface{}) {
	w.Header().Set("Content-Type", "application/json")
	jsonResp, _ := json.MarshalIndent(obj, "", "  ")
	w.Write(jsonResp)
}

/*

  Users

*/

type userImpl struct {
	otpsecret            string
	password             string
	username             string
	_WebAuthnID          []byte
	_WebAuthnCredentials []webauthn.Credential
}

func NewUser(username string) *userImpl {
	buf := make([]byte, 64)
	_, err := rand.Read(buf)
	if err != nil {
		return nil
	}

	return &userImpl{
		username:             username,
		password:             "password",
		_WebAuthnID:          buf,
		_WebAuthnCredentials: make([]webauthn.Credential, 0),
	}
}

func (u userImpl) WebAuthnID() []byte {
	return u._WebAuthnID
}

func (u userImpl) WebAuthnName() string {
	return u.username
}

func (u userImpl) WebAuthnDisplayName() string {
	return u.username
}

func (u userImpl) WebAuthnCredentials() []webauthn.Credential {
	return u._WebAuthnCredentials
}

func (u userImpl) WebAuthnIcon() string {
	return ""
}

func (u userImpl) HasWebAuthnCredential() bool {
	return len(u._WebAuthnCredentials) != 0
}

func (u *userImpl) AddCredential(c *webauthn.Credential) {
	u._WebAuthnCredentials = append(u._WebAuthnCredentials, *c)
}

func (u userImpl) HasOTPCredential() bool {
	return u.otpsecret != ""
}

func (u userImpl) OTPSecret() string {
	return u.otpsecret
}

func (u *userImpl) AddOTPSecret(secret string) {
	u.otpsecret = secret
}

var users = map[string]*userImpl{
	"alice": NewUser("alice"),
}

func dump(r *http.Request, path string) {
	const dump_body = true
	dump, _ := httputil.DumpRequest(r, dump_body)
	log.Println("-------------------------------")
	log.Println("Dumping path: ", path)
	log.Println("-------------------------------")
	log.Writer().Write(dump)
}

func applyLoginPolicy(w http.ResponseWriter, r *http.Request) {
	store, err := sess.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, "invalid session", http.StatusInternalServerError)
		return
	}
	u, ok := store.Get("LoggedInUser")
	if !ok {
		http.Error(w, "invalid user", http.StatusBadRequest)
		return
	}
	user := u.(*userImpl)
	redir_url := ""

	if !user.HasOTPCredential() || !user.HasWebAuthnCredential() {
		if pw, ok := store.Get("PasswordPassed"); !ok {
			redir_url = "/password"
		} else {
			log.Println("Password authentication passed ", pw)
		}
	}

	if user.HasOTPCredential() {
		if otp, ok := store.Get("OTPPassed"); !ok {
			redir_url = "/otp/validate"
		} else {
			log.Println("OTP authentication passed ", otp)
		}
	}

	if user.HasWebAuthnCredential() {
		if wa, ok := store.Get("WebAuthnPassed"); !ok {
			redir_url = "/webauthn/login"
		} else {
			log.Println("WebAuthn authentication passed ", wa)
		}
	}

	if redir_url == "" && !user.HasOTPCredential() {
		redir_url = "/otp/register"
	}

	if redir_url == "" && !user.HasWebAuthnCredential() {
		redir_url = "/webauthn/register"
	}

	if redir_url != "" {
		http.Redirect(w, r, redir_url, http.StatusFound)
	} else {
		http.Redirect(w, r, "/auth", http.StatusFound)
	}
}

func addOAuthHandlers() {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    time.Second * 30,
		RefreshTokenExp:   time.Hour,
		IsGenerateRefresh: true,
	})

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	clientStore.Set("222222", &models.Client{
		ID:     "222222",
		Domain: "https://mysrv.local:8444",
		Secret: "22222222",
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(&server.Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.AuthorizationCode,
			oauth2.ClientCredentials,
			oauth2.Refreshing,
		},
		AllowedCodeChallengeMethods: []oauth2.CodeChallengeMethod{
			oauth2.CodeChallengePlain,
			oauth2.CodeChallengeS256,
		},
	}, manager)

	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID,
		username, password string,
	) (userID string, err error) {
		if username == "alice" && password == "password" {
			userID = "alice"
		}
		return
	})

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter,
		r *http.Request,
	) (userID string, err error) {
		store, err := sess.Start(r.Context(), w, r)
		if err != nil {
			log.Println("Failed to create session.")
			return
		}

		u, ok := store.Get("LoggedInUser")
		if !ok {
			if r.Form == nil {
				r.ParseForm()
			}

			store.Set("ReturnUri", r.Form)
			store.Save()

			log.Println("redirecting to login")

			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
			return
		}

		user := u.(*userImpl)

		userID = user.username
		store.Delete("LoggedInUser")
		store.Save()
		return
	})

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		dump(r, "/login")
		var (
			store sess.Store
			err   error
		)
		if store, err = sess.Start(r.Context(), w, r); err == nil {
			if r.Method == "POST" && r.Form == nil {
				if err = r.ParseForm(); err == nil {
					username := r.Form.Get("username")
					if user, ok := users[username]; ok {
						store.Set("LoggedInUser", user)
						store.Save()
						applyLoginPolicy(w, r)
						return
					}
				}
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`
    <html>
      <body>
        <h1>Login In</h1>
        <form method="POST">
          <label for="username">Username</label>
          <input type="text" name="username" required placeholder="alice">
          <button type="submit">Next</button>
        </form>
      </body>
    </html>
    `))
	})

	http.HandleFunc("/password", func(w http.ResponseWriter, r *http.Request) {
		dump(r, "/password")
		var (
			store sess.Store
			err   error
			pw    string
		)
		if store, err = sess.Start(r.Context(), w, r); err == nil {
			if r.Method == "POST" && r.Form == nil {
				defer applyLoginPolicy(w, r)
				u, _ := store.Get("LoggedInUser")
				if err = r.ParseForm(); err == nil {
					if pw = r.Form.Get("password"); pw == u.(*userImpl).password {
						store.Set("PasswordPassed", true)
						store.Save()
					}
					return
				}
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`
    <html>
      <body>
        <h1>Login In</h1>
        <form method="POST">
          <label for="password">Password</label>
          <input type="password" name="password" placeholder="password">
          <button type="submit">Next</button>
        </form>
      </body>
    </html>
    `))
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		dump(r, "/logout")
		_, err := srv.ValidationBearerToken(r)
		if err == nil {
			sess.Destroy(r.Context(), w, r)
		}
		http.Redirect(w, r, "https://mysrv.local:8444", http.StatusFound)
	})

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		dump(r, "/auth")
		store, err := sess.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, ok := store.Get("LoggedInUser"); !ok {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte(`
      <html><body>
        <form action="/oauth/authorize" method="POST">
          <h1>Authorize</h1>
          <p>The client would like to perform actions on your behalf.</p>
          <p>
            <button type="submit">Allow</button>
          </p>
        </form>
      </body></html>`))
	})

	http.HandleFunc("/oauth/authorize",
		func(w http.ResponseWriter, r *http.Request) {
			dump(r, "/oauth/authorize")
			store, err := sess.Start(r.Context(), w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			var form url.Values
			if v, ok := store.Get("ReturnUri"); ok {
				form = v.(url.Values)
			}
			r.Form = form
			store.Delete("ReturnUri")
			store.Save()
			err = srv.HandleAuthorizeRequest(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
		},
	)

	http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		dump(r, "/oauth/token")
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		dump(r, "/test")
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(time.
				Until(token.GetAccessCreateAt().
					Add(token.GetAccessExpiresIn())).
				Seconds()),
			"client_id": token.GetClientID(),
			"user_id":   token.GetUserID(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})
}

func addWebAuthnHandlers() {
	wauthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "HOWA Webauthn",
		RPID:          "idp.local",
		RPOrigins:     []string{"https://idp.local:8443"},
	})
	if err != nil {
		log.Fatal(err)
	}

	_renderPage := func(username string, options interface{}, isReg bool) string {
		jsonResp, _ := json.MarshalIndent(options, "        ", "  ")
		preprocfmt := `
        var opts = %s;
        const publicKey = opts["publicKey"];
        const challenge = publicKey["challenge"];
        opts["publicKey"]["challenge"] = str2buffer(challenge);
    `
		postproc := `
              var obj = {
                "id": cred.id,
                "rawId": buffer2str(cred.rawId),
                "type": 'public-key',
                "response": {
                  "clientDataJson":
                    buffer2str(cred.response.clientDataJSON),
                }
              };
    `
		if isReg {
			preprocfmt += `
        const uid = publicKey["user"]["id"];
        console.log(uid)
        opts["publicKey"]["user"]["id"] = str2buffer(uid);
      `

			postproc += `
              obj["response"]["attestationObject"] = 
                buffer2str(cred.response.attestationObject);
      `
		} else {
			preprocfmt += `
        const allowedcreds = publicKey["allowCredentials"];
        for (i = 0; i < allowedcreds.length; i++) {
          const cid = allowedcreds[i]["id"];
          opts["publicKey"]["allowCredentials"][i]["id"] =
              str2buffer(cid);
        }
      `
			postproc += `
              obj["response"]["authenticatorData"] = 
                buffer2str(cred.response.authenticatorData);
              obj["response"]["signature"] = 
                buffer2str(cred.response.signature);
      `
		}

		preproc := fmt.Sprintf(preprocfmt, jsonResp)

		var method, endpoint string

		if isReg {
			method = "create"
			endpoint = "register"
		} else {
			method = "get"
			endpoint = "login"
		}

		return fmt.Sprintf(`
    <html>
      <header><script>
        function str2buffer(s) {
          const l = Math.floor((s.length + 3) / 4) * 4;
          s = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(l, "=");
          return Uint8Array.from(window.atob(s), (c) => c.charCodeAt(0));
        }

        function buffer2str(buf) {
          const arr = new Uint8Array(buf);
          const binstr = String.fromCharCode.apply(null, arr);
          return window.btoa(binstr).replace(/\+/g, '-').replace(/\//g, '_');
        }

        %s

        function onload() {
          window.navigator.credentials.%s(opts)
          .then((cred)=>{
            if (cred == null) {
              throw Exception("Failed to acquire credentials.");
            } else {

              %s
              
              document.form.json.value = JSON.stringify(obj);
              console.log(document.form.json.value);
              document.form.submit();
            }
          });
        }
      </script></header>
      <body onload="onload()"><center>
        <h1>User: %s</h1>
        <form name="form" method="POST" action="/webauthn/%s" enctype="text/plain">
          <input type="hidden" id="json" name="json" value="">
        </form>
      </center></body>
    </html>
  `, preproc, method, postproc, username, endpoint)
	}

	_handler := func(w http.ResponseWriter, r *http.Request, isReg bool,
		begin func(*userImpl) (interface{}, *webauthn.SessionData, error),
		finish func(user *userImpl, session *webauthn.SessionData),
	) {
		store, err := sess.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, "invalid session", http.StatusInternalServerError)
			return
		}
		u, _ := store.Get("LoggedInUser")
		var user *userImpl
		if u != nil {
			user = u.(*userImpl)
		}
		if u == nil || user == nil {
			http.Error(w, "invalid username", http.StatusUnauthorized)
			log.Print("invalid username")
			return
		}

		s, _ := store.Get("WebAuthnSession")
		var session *webauthn.SessionData
		if s == nil {
			var options interface{}
			options, session, err = begin(user)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				log.Print(err.Error())
				return
			}
			store.Set("WebAuthnSession", session)
			store.Save()
			page := _renderPage(user.username, options, isReg)
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(page))
			log.Printf("Sending registration information for user: %s",
				user.username)
		} else {
			defer func() {
				r.Body.Close()
				store.Delete("WebAuthnSession")
				store.Save()
				applyLoginPolicy(w, r)
			}()
			session = s.(*webauthn.SessionData)
			b := make([]byte, 5)
			r.Body.Read(b)
			r.Header.Set("Content-Type", "application/json")
			finish(user, session)
		}
	}

	http.HandleFunc("/webauthn/register",
		func(w http.ResponseWriter, r *http.Request) {
			dump(r, "/webauthn/register")
			_handler(w, r, true,
				func(user *userImpl) (interface{}, *webauthn.SessionData, error) {
					return wauthn.BeginRegistration(user,
						webauthn.WithCredentialParameters(
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
				},
				func(user *userImpl, session *webauthn.SessionData) {
					var (
						err        error
						ccr        *protocol.ParsedCredentialCreationData
						credential *webauthn.Credential
					)
					if ccr, err = protocol.ParseCredentialCreationResponse(r); err == nil {
						if ccr.Response.CollectedClientData.Challenge != session.Challenge {
							log.Print("invalid session or client")
							return
						}
						if credential,
							err = wauthn.CreateCredential(user, *session, ccr); err == nil {
							user.AddCredential(credential)
							log.Printf("User: %s registered a WebAuthn credential.",
								user.username)
							if store, err := sess.Start(r.Context(), w, r); err == nil {
								store.Set("WebAuthnPassed", true)
								store.Save()
							}
							return
						}
					}
					if err != nil {
						log.Println(err.Error())
					}
				},
			)
		})

	http.HandleFunc("/webauthn/login",
		func(w http.ResponseWriter, r *http.Request) {
			dump(r, "/webauthn/login")
			_handler(w, r, false,
				func(ui *userImpl) (interface{}, *webauthn.SessionData, error) {
					return wauthn.BeginLogin(ui)
				},
				func(user *userImpl, session *webauthn.SessionData) {
					var (
						err error
						cad *protocol.ParsedCredentialAssertionData
					)

					if cad, err = protocol.ParseCredentialRequestResponse(r); err == nil {
						if cad.Response.CollectedClientData.Challenge != session.Challenge {
							log.Print("invalid session or client")
							return
						}

						if _, err = wauthn.ValidateLogin(user, *session, cad); err == nil {
							log.Printf("User: %s authenticated successfully.", user.username)
							if store, err := sess.Start(r.Context(), w, r); err == nil {
								store.Set("WebAuthnPassed", true)
								store.Save()
							}
							return
						}
					}
					if err != nil {
						log.Println(err.Error())
					}
				},
			)
		})
}

func addTOTPHandlers() {
	_generateSecret := func(username string) (secret string,
		imgpath string, err error,
	) {
		secret_bytes := make([]byte, 20)
		rand.Read(secret_bytes)
		secret = base32.StdEncoding.EncodeToString(secret_bytes)

		var key *otp.Key
		url := fmt.Sprintf("otpauth://totp/idp:%s?issuer=idp&secret=%s",
			username, secret)
		if key, err = otp.NewKeyFromURL(url); err == nil {
			var img image.Image
			if img, err = key.Image(200, 200); err == nil {
				var imgbuf bytes.Buffer
				if err = png.Encode(&imgbuf, img); err == nil {
					imgpath = "images/" + uuid.New().String() + ".png"
					var f *os.File
					if f, err = os.OpenFile(imgpath,
						os.O_WRONLY|os.O_CREATE, 0644); err == nil {
						defer f.Close()
						f.Write(imgbuf.Bytes())
					}
				}
			}
		}
		return
	}

	_renderRegistrationPage := func(username string, imgpath string,
		secret string,
	) string {
		return fmt.Sprintf(`
    <html><body><center>
      <h1>User: %s</h1>
      <p>
        <img src="/%s" /><br>
        Secret: %s
      </p>
      <form enctype="application/x-www-form-urlencoded">
        <label for="otp">OTP</label><br>
        <input type="text" id="otp" name="otp"><br>
        <input type="submit" value="Submit">
      </form>
    </center></body></html>
  `, username, imgpath, secret)
	}

	http.HandleFunc("/otp/register",
		func(w http.ResponseWriter, r *http.Request) {
			dump(r, "/otp/register")
			store, err := sess.Start(r.Context(), w, r)
			if err != nil {
				log.Println("invalid store")
				return
			}
			u, _ := store.Get("LoggedInUser")
			user := u.(*userImpl)
			s, _ := store.Get("Secret")
			secret := ""
			if s != nil {
				secret = s.(string)
			}

			if user == nil {
				log.Print("invalid username")
				return
			}

			if secret == "" {
				secret, imgpath, err := _generateSecret(user.username)
				if err != nil {
					log.Print(err)
					return
				}
				store.Set("Secret", secret)
				store.Save()

				log.Printf("OTP registration request for user: %s", user.username)
				page := _renderRegistrationPage(user.username, imgpath, secret)
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(page))
			} else {
				defer func() {
					store.Delete("Secret")
					store.Save()
					applyLoginPolicy(w, r)
				}()
				if otpval := r.FormValue("otp"); otpval != "" {
					if ok := totp.Validate(otpval, secret); ok {
						user.otpsecret = secret
						log.Printf("OTP registered for user: %s", user.username)
						store.Set("OTPPassed", true)
						store.Save()
						return
					}
				}
				log.Print("invalid otp")
			}
		})

	_renderValidationPage := func(username string) string {
		return fmt.Sprintf(`
    <html><body><center>
      <h1>User: %s</h1>
      <form enctype="application/x-www-form-urlencoded">
        <label for="otp">OTP</label><br>
        <input type="text" id="otp" name="otp"><br>
        <input type="submit" value="Submit">
      </form>
    </center></body></html>
  `, username)
	}

	http.HandleFunc("/otp/validate",
		func(w http.ResponseWriter, r *http.Request) {
			dump(r, "/otp/validate")
			defer applyLoginPolicy(w, r)

			store, err := sess.Start(r.Context(), w, r)
			if err != nil {
				log.Println("invalid session")
				return
			}
			u, _ := store.Get("LoggedInUser")
			var user *userImpl
			if u != nil {
				user = u.(*userImpl)
			}
			if u == nil || user == nil || !user.HasOTPCredential() {
				log.Print("invalid username or otp")
				return
			}
			otpval := r.FormValue("otp")
			if otpval == "" {
				page := _renderValidationPage(user.username)
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(page))
			} else {
				ok := totp.Validate(otpval, user.OTPSecret())
				if ok {
					log.Printf("User %s authenticated successfully", user.username)
					store.Set("OTPPassed", true)
					store.Save()
					return
				} else {
					log.Print("invalid username or otp")
				}
			}
		})
}

func addStaticRoutes() {
	http.HandleFunc("/images/", func(w http.ResponseWriter, r *http.Request) {
		http.StripPrefix("/images/",
			http.FileServer(http.Dir("images"))).ServeHTTP(w, r)
	})
}

func main() {
	addOAuthHandlers()
	addWebAuthnHandlers()
	addTOTPHandlers()
	addStaticRoutes()
	StartTLSServer("../certs/idp.local.p12", "idp.local", "8443")
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
