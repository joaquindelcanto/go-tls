package tlscert

import (
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	dir := path.Join(".", "testdata")
	certPath := path.Join(dir, "cert.pem")
	invalidCertPath := path.Join(dir, "invalid_cert.pem")
	missingCertPath := path.Join(dir, "missing_cert.pem")
	keyPath := path.Join(dir, "key.pem")
	invalidKeyPath := path.Join(dir, "invalid_key.pem")
	missingKeyPath := path.Join(dir, "missing_key.pem")

	// valid files
	cert, err := Load(certPath, keyPath)
	assert.NotNil(t, cert)
	assert.NotNil(t, cert.Leaf)
	assert.Equal(t, time.Hour*24, cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore))
	assert.Nil(t, err)

	// missing files
	cert, err = Load(missingCertPath, missingKeyPath)
	assert.Nil(t, cert)
	assert.Nil(t, err)

	// missing key file
	cert, err = Load(certPath, missingKeyPath)
	assert.Nil(t, cert)
	assert.Nil(t, err)

	// missing cert file
	cert, err = Load(missingCertPath, keyPath)
	assert.Nil(t, cert)
	assert.Nil(t, err)

	// invalid cert and key files
	cert, err = Load(invalidCertPath, invalidKeyPath)
	assert.Nil(t, cert)
	assert.NotNil(t, err)
}
