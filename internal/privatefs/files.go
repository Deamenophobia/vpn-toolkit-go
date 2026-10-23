// Package privatefs writes credential-bearing files with restricted permissions.
package privatefs

import (
	"errors"
	"os"
	"path/filepath"
)

func Dir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private directory must be a real directory")
	}
	return protect(path, true)
}
func Read(path string) ([]byte, error) {
	i, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !i.Mode().IsRegular() {
		return nil, errors.New("secret file must be a regular file")
	}
	if err = protect(path, false); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// Write replaces a file in the same directory. Callers serialize state updates.
func Write(path string, data []byte) error {
	if i, err := os.Lstat(path); err == nil && !i.Mode().IsRegular() {
		return errors.New("output must be a regular file")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = protect(tmp, false); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return replace(tmp, path)
}
