package tlsmanager

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"os"
	"path"
	"testing"
	"time"

	"github.com/joaquindelcanto/go-tls/internal/tlscert"
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

func (a *aferoFileSystem) Create(filePath string) (tlscert.File, error) {
	return a.fs.Create(filePath)
}

func TestManager(t *testing.T) {

	afs := &aferoFileSystem{fs: afero.NewMemMapFs()}

	dir := "/manager_test"
	config := Config{
		CertPath: path.Join(dir, "cert.pem"),
		KeyPath:  path.Join(dir, "key.pem"),
		DistinguishedName: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.org",
		},
		CertExp:            time.Second,
		CertRegenBeforeExp: (time.Second) - (time.Millisecond * 100),
	}
	serveCertCh := make(chan *tls.Certificate)
	go Run(afs, config, serveCertCh)

	cert := <-serveCertCh
	assert.NotNil(t, cert)
	assert.NotNil(t, cert.Leaf)
	time.Sleep(time.Millisecond * 150)
	assert.NotNil(t, cert)
	assert.NotNil(t, cert.Leaf)
	time.Sleep(time.Second)
	assert.NotNil(t, cert)
	assert.NotNil(t, cert.Leaf)
}

func TestTimeAfter(t *testing.T) {
	// test positive duration
	afterCh := time.After(time.Millisecond * 100)
	<-afterCh

	// test zero duration
	afterCh = time.After(time.Second * 0)
	<-afterCh

	// test negative duration
	negDuration := time.Second * -2
	afterCh = time.After(negDuration)
	<-afterCh
}
