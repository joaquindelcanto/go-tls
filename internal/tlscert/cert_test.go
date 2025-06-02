package tlscert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

type aferoFileSystem struct {
	fs afero.Fs
}

func (a *aferoFileSystem) Stat(filePath string) (os.FileInfo, error) {
	return a.fs.Stat(filePath)
}

func (a *aferoFileSystem) ReadFile(filePath string) ([]byte, error) {
	return afero.ReadFile(a.fs, filePath)
}

func (a *aferoFileSystem) Create(filePath string) (File, error) {
	return a.fs.Create(filePath)
}

func TestGenerateSelfSigned(t *testing.T) {

	afs := &aferoFileSystem{fs: afero.NewMemMapFs()}

	certPath := "/cert.pem"
	keyPath := "/key.pem"

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"test org"},
			CommonName:   "test",
		},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(time.Second * 30),
	}

	err := GenerateSelfSigned(afs, certPath, keyPath, template)
	assert.Nil(t, err)

	cert, err := Load(afs, certPath, keyPath)
	assert.NotNil(t, cert)
	assert.Nil(t, err)
	assert.Equal(t, template.Subject.CommonName, cert.Leaf.Subject.CommonName)
	assert.Equal(t, template.NotBefore.Year(), cert.Leaf.NotBefore.Year())
	assert.Equal(t, template.NotBefore.Month(), cert.Leaf.NotBefore.Month())
	assert.Equal(t, template.NotBefore.Day(), cert.Leaf.NotBefore.Day())
	assert.Equal(t, template.NotBefore.Hour(), cert.Leaf.NotBefore.Hour())
	assert.Equal(t, template.NotBefore.Minute(), cert.Leaf.NotBefore.Minute())
	assert.Equal(t, template.NotBefore.Second(), cert.Leaf.NotBefore.Second())
	assert.Equal(t, template.NotAfter.Year(), cert.Leaf.NotAfter.Year())
	assert.Equal(t, template.NotAfter.Month(), cert.Leaf.NotAfter.Month())
	assert.Equal(t, template.NotAfter.Day(), cert.Leaf.NotAfter.Day())
	assert.Equal(t, template.NotAfter.Hour(), cert.Leaf.NotAfter.Hour())
	assert.Equal(t, template.NotAfter.Minute(), cert.Leaf.NotAfter.Minute())
	assert.Equal(t, template.NotAfter.Second(), cert.Leaf.NotAfter.Second())
}

func TestLoad(t *testing.T) {

	var validCertBytes []byte
	var invalidCertBytes []byte
	var validKeyBytes []byte
	var invalidKeyBytes []byte
	{
		osfs := OSFileSystem{}
		dir := path.Join(".", "testdata")
		validCertPath := path.Join(dir, "cert.pem")
		invalidCertPath := path.Join(dir, "invalid_cert.pem")
		missingCertPath := path.Join(dir, "missing_cert.pem")
		validKeyPath := path.Join(dir, "key.pem")
		invalidKeyPath := path.Join(dir, "invalid_key.pem")
		missingKeyPath := path.Join(dir, "missing_key.pem")

		// valid files
		cert, err := Load(osfs, validCertPath, validKeyPath)
		assert.NotNil(t, cert)
		assert.NotNil(t, cert.Leaf)
		assert.Equal(t, time.Hour*24, cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore))
		assert.Nil(t, err)

		// missing files
		cert, err = Load(osfs, missingCertPath, missingKeyPath)
		assert.Nil(t, cert)
		assert.Nil(t, err)

		// missing key file
		cert, err = Load(osfs, validCertPath, missingKeyPath)
		assert.Nil(t, cert)
		assert.Nil(t, err)

		// missing cert file
		cert, err = Load(osfs, missingCertPath, validKeyPath)
		assert.Nil(t, cert)
		assert.Nil(t, err)

		// invalid cert and key files
		cert, err = Load(osfs, invalidCertPath, invalidKeyPath)
		assert.Nil(t, cert)
		assert.NotNil(t, err)

		// get data for afero test
		validCertBytes, err = os.ReadFile(validCertPath)
		assert.NotNil(t, validCertBytes)
		assert.Nil(t, err)

		invalidCertBytes, err = os.ReadFile(invalidCertPath)
		assert.NotNil(t, invalidCertBytes)
		assert.Nil(t, err)

		validKeyBytes, err = os.ReadFile(validKeyPath)
		assert.NotNil(t, validKeyBytes)
		assert.Nil(t, err)

		invalidKeyBytes, err = os.ReadFile(invalidKeyPath)
		assert.NotNil(t, invalidKeyBytes)
		assert.Nil(t, err)
	}

	// Test with aferoFileSystem
	{
		afs := &aferoFileSystem{fs: afero.NewMemMapFs()}

		validCertPath := "/cert.pem"
		invalidCertPath := "/invalid_cert.pem"
		missingCertPath := "/missing_cert.pem"
		validKeyPath := "/key.pem"
		invalidKeyPath := "/invalid_key.pem"
		missingKeyPath := "/missing_key.pem"

		// Prepare data...
		{
			validCertFile, err := afs.Create(validCertPath)
			assert.NotNil(t, validCertFile)
			assert.Nil(t, err)
			_, err = validCertFile.Write(validCertBytes)
			assert.Nil(t, err)
			validCertFile.Close()
		}

		{
			invalidCertFile, err := afs.Create(invalidCertPath)
			assert.NotNil(t, invalidCertFile)
			assert.Nil(t, err)
			_, err = invalidCertFile.Write(invalidCertBytes)
			assert.Nil(t, err)
			invalidCertFile.Close()
		}

		{
			validKeyFile, err := afs.Create(validKeyPath)
			assert.NotNil(t, validKeyFile)
			assert.Nil(t, err)
			_, err = validKeyFile.Write(validKeyBytes)
			assert.Nil(t, err)
			validKeyFile.Close()
		}

		{
			invalidKeyFile, err := afs.Create(invalidKeyPath)
			assert.NotNil(t, invalidKeyFile)
			assert.Nil(t, err)
			_, err = invalidKeyFile.Write(invalidKeyBytes)
			assert.Nil(t, err)
			invalidKeyFile.Close()
		}

		// valid files
		cert, err := Load(afs, validCertPath, validKeyPath)
		assert.NotNil(t, cert)
		assert.NotNil(t, cert.Leaf)
		assert.Equal(t, time.Hour*24, cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore))
		assert.Nil(t, err)

		// missing files
		cert, err = Load(afs, missingCertPath, missingKeyPath)
		assert.Nil(t, cert)
		assert.Nil(t, err)

		// missing key file
		cert, err = Load(afs, validCertPath, missingKeyPath)
		assert.Nil(t, cert)
		assert.Nil(t, err)

		// missing cert file
		cert, err = Load(afs, missingCertPath, validKeyPath)
		assert.Nil(t, cert)
		assert.Nil(t, err)

		// invalid cert and key files
		cert, err = Load(afs, invalidCertPath, invalidKeyPath)
		assert.Nil(t, cert)
		assert.NotNil(t, err)
	}
}

func TestFileExists(t *testing.T) {

	// Test with OSFileSystem
	{
		osfs := OSFileSystem{}
		dir := path.Join(".", "testdata")
		validFilePath := path.Join(dir, "cert.pem")
		missingFilePath := path.Join(dir, "missing_cert.pem")

		exists, err := fileExists(osfs, validFilePath)
		assert.True(t, exists)
		assert.Nil(t, err)

		exists, err = fileExists(osfs, missingFilePath)
		assert.False(t, exists)
		assert.Nil(t, err)
	}

	// Test with aferoFileSystem
	{
		afs := &aferoFileSystem{fs: afero.NewMemMapFs()}

		validFilePath := "/test.txt"
		missingFilePath := "/missing.txt"
		file, err := afs.Create(validFilePath)
		assert.NotNil(t, file)
		assert.Nil(t, err)
		file.Close()

		exists, err := fileExists(afs, validFilePath)
		assert.True(t, exists)
		assert.Nil(t, err)

		exists, err = fileExists(afs, missingFilePath)
		assert.False(t, exists)
		assert.Nil(t, err)
	}
}
