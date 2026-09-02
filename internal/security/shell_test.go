package security

import (
	"os/exec"
	"runtime"
	"testing"
)

// These integrations exercise Unix job control, /dev/null and /bin/sh. Keep
// portable unit tests enabled on Windows; run the integrations in Linux CI.
func requirePOSIXShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX host; covered by the Linux integration job")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatal("POSIX integration requires sh in PATH")
	}
}
