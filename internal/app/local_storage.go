package app

import (
	"fmt"
	"os"
	"path/filepath"
)

func prepareSQLiteFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		name := path + suffix
		info, err := os.Lstat(name)
		if err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("SQLite storage must be a regular file")
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if os.IsNotExist(err) && suffix != "" {
			continue
		}
		f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		err = f.Chmod(0o600)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
