package tlscert

import "os"

type OSFileSystem struct {
}

func (OSFileSystem) Stat(filePath string) (os.FileInfo, error) {
	return os.Stat(filePath)
}

func (OSFileSystem) ReadFile(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}

func (OSFileSystem) Create(filePath string) (File, error) {
	return os.Create(filePath)
}
