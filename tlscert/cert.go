package tlscert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type File interface {
	io.Closer
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Writer
	io.WriterAt
}

type FileSystem interface {
	Stat(filePath string) (os.FileInfo, error)
	ReadFile(filePath string) ([]byte, error)
	Create(filePath string) (File, error)
}

// Generates a self-signed TLS certificate and key.
// Overwrites any existing certificate and key at the given path.
func GenerateSelfSigned(fs FileSystem, certPath, keyPath string, template *x509.Certificate) error {
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
	certFile, err := fs.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", certPath, err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return fmt.Errorf("failed to write certificate (%s): %v", certPath, err)
	}

	// Save the private key to a file
	keyFile, err := fs.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", keyPath, err)
	}
	defer keyFile.Close()
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("error during x509.MarshalPKCS8PrivateKey: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return fmt.Errorf("failed to write private key (%s): %v", keyPath, err)
	}

	return nil
}

// Load an existing TLS certificate and key
func Load(fs FileSystem, certPath, keyPath string) (*tls.Certificate, error) {

	if exists, err := fileExists(fs, certPath); !exists {
		return nil, err
	}
	if exists, err := fileExists(fs, keyPath); !exists {
		return nil, err
	}

	certBytes, err := fs.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file (%s): %v", certPath, err)
	}

	keyBytes, err := fs.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file (%s): %v", keyPath, err)
	}

	// The files are confirmed to exist, now try to load them
	cert, err := loadCertificateFromBytes(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate from bytes (%s, %s): %v",
			certPath, keyPath, err)
	}

	if cert.Leaf == nil {
		return nil, fmt.Errorf("failed to extract certificate from key pair (%s, %s), invalid data",
			certPath, keyPath)
	}

	return cert, nil
}

func loadCertificateFromBytes(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	// Decode the certificate PEM
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Decode the private key PEM
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	// Parse the private key
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Create the tls.Certificate
	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}

func fileExists(fs FileSystem, filePath string) (bool, error) {
	if _, err := fs.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			// No key file found at the given path
			return false, nil
		} else {
			return false, fmt.Errorf("os.Stat(%s) error: %v", filePath, err)
		}
	}
	return true, nil
}
