package tlscert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Generates a self-signed TLS certificate and key.
// Overwrites any existing certificate and key at the given path.
func GenerateSelfSigned(certPath, keyPath string, template *x509.Certificate) error {
	// Generate a new RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Save the certificate to a file
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", certPath, err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return fmt.Errorf("failed to write certificate (%s): %v", certPath, err)
	}

	// Save the private key to a file
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", keyPath, err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}); err != nil {
		return fmt.Errorf("failed to write private key (%s): %v", keyPath, err)
	}

	return nil
}

// Load an existing TLS certificate and key
func Load(certPath, keyPath string) (*tls.Certificate, error) {

	if _, err := os.Stat(certPath); err != nil {
		if os.IsNotExist(err) {
			// No certificate file found at the given path
			return nil, nil
		} else {
			return nil, fmt.Errorf("os.Stat(%s) error: %v", certPath, err)
		}
	}
	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			// No key file found at the given path
			return nil, nil
		} else {
			return nil, fmt.Errorf("os.Stat(%s) error: %v", keyPath, err)
		}
	}

	// The files are confirmed to exist, now try to load them
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair (%s, %s): %v",
			certPath, keyPath, err)
	}

	if cert.Leaf == nil {
		return nil, fmt.Errorf("failed to extract certificate from key pair (%s, %s), invalid data",
			certPath, keyPath)
	}

	return &cert, nil
}
