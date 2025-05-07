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

func getHTTPSClient(capath string) (client *http.Client, err error) {
	var (
		tlsConfig tls.Config
		data      []byte
	)
	if data, err = os.ReadFile(capath); err == nil {
		var block *pem.Block
		certpool := x509.NewCertPool()
		for block, data = pem.Decode(data); block != nil; block, data = pem.Decode(data) {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				certpool.AddCert(cert)
			}
		}
		tlsConfig.RootCAs = certpool
	} else {
		return
	}
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
		},
	}
	return
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

	httpclient, err := getHTTPSClient("certs/ssl/scas.crt")
	if err != nil {
		log.Default().Fatalf("Unable to read RootCAs: %v", err)
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), httpclient, *idpMetadataURL)
	if err != nil {
		log.Default().Fatalf("Failed to download IDP metadata %v", err)
	}

	key, cert, err := getProviderCertAndKey("certs/finance.crt", "certs/finance.key", []byte("password"))
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
