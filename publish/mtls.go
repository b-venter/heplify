package publish

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/config"
)

/*
Certificate, key and chain can be embedded before building the binary by
appending values to this file. (echo "var agentKey string = \`$( cat ../../heplify1.key )\`" >> publish/mtls.go)
But if not, then pem files can be specified via the command line flags. The function below is used by publish/hep.go to load the files
*/

func loadFile(c string) (string, error) {
	f, err := os.ReadFile(c)
	if err != nil {
		return "", err
	}
	return string(f), nil
}

/*
Embed cert, key or chain by specifying base64 value below. Note use of back ticks!!
Example:

var agentCert string = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOoqfvFoQXUULe
...
xkKI+Y6MRPBb2qXcYfeS/0FI
-----END PRIVATE KEY-----`
*/

var agentCert string
var serverChain string
var agentKey string

// Read trusted RootCAs from operating system store
func renewRootCAs() *x509.CertPool {
	rootcas, err := x509.SystemCertPool()
	if err != nil || rootcas == nil {
		panic("Unable lto load/renew RootCAs from Operating System")
	}

	return rootcas
}

// Set node name as per CN value in certificate
func setHepNodeNameToCN(crt string) error {
	certBytes := []byte(crt)

	// Decode the PEM block
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v\n", err)
	}

	// Extract the Common Name
	commonName := cert.Subject.CommonName
	if commonName == "" {
		return fmt.Errorf("CN not set in certificate")
	} else {
		logp.Info("Node name from certificate Common Name (CN): %s\n", commonName)
		config.Cfg.HepNodeName = commonName
		return nil
	}
}
