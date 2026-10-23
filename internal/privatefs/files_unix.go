//go:build !windows

package privatefs

import (
	"os"
	"path/filepath"
)

func protect(path string, dir bool) error {
	if dir {
		return os.Chmod(path, 0700)
	}
	return os.Chmod(path, 0600)
}
func replace(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(to))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
