package sshclient

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
)

func loadKey(path string, create bool) ([]byte, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("invalid SSH vault directory")
	}
	if err := securePath(dir, true); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && create {
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr == nil {
			_, err = file.Write(key)
			if err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil {
				err = securePath(path, false)
			}
			if err != nil {
				clear(key)
				return nil, err
			}
			return key, nil
		}
		clear(key)
		if !errors.Is(openErr, os.ErrExist) {
			return nil, openErr
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return nil, errors.New("SSH master key missing; restore original key to unlock stored connections")
	}
	if !info.Mode().IsRegular() || info.Size() != 32 {
		return nil, errors.New("invalid SSH master key file")
	}
	if err = securePath(path, false); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
