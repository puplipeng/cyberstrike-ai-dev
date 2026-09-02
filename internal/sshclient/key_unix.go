//go:build !windows

package sshclient

import "os"

func securePath(path string, directory bool) error {
	if directory {
		return os.Chmod(path, 0700)
	}
	return os.Chmod(path, 0600)
}
