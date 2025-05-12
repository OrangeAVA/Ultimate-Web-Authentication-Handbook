package common

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"github.com/youmark/pkcs8"
)

func GetProviderCertAndKey(certpath, keypath string, keypass []byte) (key *rsa.PrivateKey, cert *x509.Certificate, err error) {
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
func GetTLSCert(capath, certpath, keypath string, keypass []byte) (c *tls.Certificate, err error) {
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

func GetHTTPSClient(capath string) (client *http.Client, err error) {
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
