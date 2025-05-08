/*
Chapter-4: Federated Authentication-I
Ultimate Web Authentication Handbook by Sambit Kumar Dash

This code represents the Finance App in the demo discussed in the book. The
application implements a SAML SP and requires a SAML IDP to run.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.3 finance.mysrv.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Start the server with the command: go run ./finance.go

# Go to the folder frontend and build the flutter application using

flutter build web

The website runs at https://finance.mysrv.local:8445/

Make sure you have the IDP running before launching this service.
*/
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/samlsp"
	"howa.in/common"
)

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
		Addr:      ":8445",
		TLSConfig: tlsConfig,
	}
}

func main() {
	rootURL, err := url.Parse("https://finance.mysrv.local:8445")
	if err != nil {
		log.Default().Fatal(err)
	}

	idpMetadataURL, err := url.Parse("https://idp.local:8443/idp/metadata")
	if err != nil {
		log.Default().Fatalf("IDP not running at: https://idp.local:8443 %v", err)
	}

	httpclient, err := common.GetHTTPSClient("certs/ssl/scas.crt")
	if err != nil {
		log.Default().Fatalf("Unable to read RootCAs: %v", err)
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), httpclient, *idpMetadataURL)
	if err != nil {
		log.Default().Fatalf("Failed to download IDP metadata %v", err)
	}

	key, cert, err := common.GetProviderCertAndKey("certs/finance.crt", "certs/finance.key", []byte("password"))
	if err != nil {
		panic(err)
	}

	database := map[string]int{
		"alice": 2000,
		"bob":   1000,
		"carol": 1500,
		"don":   1800,
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
		log.Default().Fatalf("Unable to start Finance SP %v", err)
	}

	http.Handle("/saml/", samlSP)
	http.Handle("/", samlSP.RequireAccount(http.FileServer(http.Dir("frontend/build/web"))))
	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		if session, err := samlSP.Session.GetSession(r); err == nil {
			attr := session.(samlsp.SessionWithAttributes).GetAttributes()
			for _, v := range attr["eduPersonAffiliation"] {
				switch v {
				case "financeadmin":
					jsValue, _ := json.Marshal(database)
					w.Write(jsValue)
					return
				case "users":
					uid := attr.Get("uid")
					js := fmt.Sprintf("{ \"%s\" : %d}", uid, database[uid])
					w.Write([]byte(js))
					return
				}
			}
		} else {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
		}
	})
	server := setupTLSServer("finance.mysrv.local")
	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
