/*
Chapter-5: Federated Authentication-II
Hands-On Web Authentication by Sambit Kumar Dash

This sample code shows the PKCE code grant and token refresh using OAuth 2.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.5 mysrv.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Start the server with the command: go run ./server.go

The website runs at https://mysrv.local:8443/.

The PKCE client sends the token to this server the bearer token to access
resources. The IDP, the client, and this server should all be running for this
demo to function.

*/

package main

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

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
		Addr:      ":8444",
		TLSConfig: tlsConfig,
	}
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dumpRequest(os.Stdout, "/", r)
		if r.Form == nil {
			r.ParseForm()
		}
		if r.Form.Has("error") {
			http.Error(w, r.Form.Get("error_description"), http.StatusUnauthorized)
		} else {
			code := r.Form.Get("code")
			w.Write([]byte(fmt.Sprintf(`
        <html><body>
          <h1>Code</h1>
          <p>%s</p>
        </body></html>
      `, code)))
		}
	})

	http.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		dumpRequest(os.Stdout, "resource", r)
		var (
			err          error
			auth_headers []string
			ok           bool
			req          *http.Request
			res          *http.Response
			data         []byte
		)

		if auth_headers, ok = r.Header["Authorization"]; ok {
			if req, err = http.NewRequest("GET", "https://idp.local:8443/test", nil); err == nil {
				req.Header.Add("Authorization", auth_headers[0])
				if res, err = http.DefaultClient.Do(req); err == nil {
					defer res.Body.Close()
					if data, err = ioutil.ReadAll(res.Body); err == nil {
						log.Println(string(data))
						w.Write(data)
					}
				}
			}
		}

		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
	})

	server := setupTLSServer("../../certs/mysrv.p12", "mysrv.local")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func dumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}
