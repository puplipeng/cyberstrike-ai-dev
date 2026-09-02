//go:build !windows

package codexbridge

import "os/exec"

func hideWindow(cmd *exec.Cmd) {}
