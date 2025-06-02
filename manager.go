package tlsmanager

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"

	"github.com/joaquindelcanto/go-tls/tlscert"
)

type Config struct {
	// Paths to the certificate and key files
	CertPath, KeyPath string

	// Distinguished name used when generating a certificate
	DistinguishedName pkix.Name

	// How long before a new certificate will expire
	CertExp time.Duration

	// Time to regenerate a certificate in advance of its expiration
	CertRegenBeforeExp time.Duration
}

// Run the manager, which is designed to run in its own Goroutine.
// Certificates will be served to the calling code via the given channel.
func Run(fileSystem tlscert.FileSystem, c Config, serveCertCh chan *tls.Certificate) {

	var genCert func() *tls.Certificate
	{
		// Create a certificate template
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               c.DistinguishedName,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		genCert = func() *tls.Certificate {
			template.NotBefore = time.Now()
			template.NotAfter = time.Now().Add(c.CertExp)

			err := tlscert.GenerateSelfSigned(fileSystem, c.CertPath, c.KeyPath, template)
			if err != nil {
				log.Printf("Error generating certificate (%s, %s): %v",
					c.CertPath, c.KeyPath, err)
				return nil
			}

			newCert, err := tlscert.Load(fileSystem, c.CertPath, c.KeyPath)
			if err != nil {
				log.Printf("Error loading certificate (%s, %s): %v",
					c.CertPath, c.KeyPath, err)
				return nil
			}

			return newCert
		}
	}

	// Load existing certificate, if it exists
	cert, err := tlscert.Load(fileSystem, c.CertPath, c.KeyPath)
	if err != nil {
		log.Printf("Error loading certificate (%s, %s): %v",
			c.CertPath, c.KeyPath, err)
	}

	// Generate a new certificate if none exists, or if it is time to regenerate it
	if cert == nil || time.Until(cert.Leaf.NotAfter) < c.CertRegenBeforeExp {
		cert = genCert()
	}

	for {
		if cert == nil {
			// something went wrong, try again in 5 seconds
			time.Sleep(time.Second * 5)

			// Regenerate the certificate
			cert = genCert()
		} else {

			// Serve the current certificate until it is time to regenerate it
			{
				regenerate := time.After(time.Until(cert.Leaf.NotAfter) - c.CertRegenBeforeExp)
				timeToRegenerate := false
				for !timeToRegenerate {
					select {
					case serveCertCh <- cert:
					case <-regenerate:
						// Time to regenerate the certificate
						timeToRegenerate = true
					}
				}
			}

			// Begin regenerate in background
			newCertCh := make(chan *tls.Certificate)
			go func() {
				for {
					newCert := genCert()
					if newCert != nil {
						newCertCh <- newCert
						return
					}

					// something went wrong, try again in 5 seconds
					time.Sleep(time.Second * 5)
				}
			}()

			// Continue to serve the current certificate until the new one
			// has been generated.
			genCertComplete := false
			for !genCertComplete {
				select {
				case serveCertCh <- cert:
				case cert = <-newCertCh:
					genCertComplete = true
				}
			}
		}
	}
}
