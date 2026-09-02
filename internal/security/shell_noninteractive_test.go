package security

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPrependNonInteractiveShellExports(t *testing.T) {
	out := PrependNonInteractiveShellExports("echo hi")
	if !strings.Contains(out, "GIT_PAGER=cat") || !strings.Contains(out, "PAGER=cat") {
		t.Fatalf("missing pager exports: %q", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "echo hi") {
		t.Fatalf("command suffix lost: %q", out)
	}
	skip := PrependNonInteractiveShellExports("GIT_PAGER=less echo hi")
	if strings.Contains(skip, "export GIT_PAGER=cat") {
		t.Fatalf("should not override existing GIT_PAGER: %q", skip)
	}
}

func TestPrependNonInteractiveStdinRedirect(t *testing.T) {
	out := PrependNonInteractiveStdinRedirect("echo hi")
	if !strings.HasPrefix(out, "exec </dev/null") {
		t.Fatalf("missing stdin redirect: %q", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "echo hi") {
		t.Fatalf("command suffix lost: %q", out)
	}
	skip := PrependNonInteractiveStdinRedirect("cmd </dev/null")
	if strings.HasPrefix(skip, "exec </dev/null") {
		t.Fatalf("should not double redirect: %q", skip)
	}
}

func TestPrepareNonInteractiveShellCommand(t *testing.T) {
	out := PrepareNonInteractiveShellCommand("echo hi")
	if !strings.Contains(out, "exec </dev/null") {
		t.Fatalf("missing stdin redirect: %q", out)
	}
	if !strings.Contains(out, "GIT_PAGER=cat") {
		t.Fatalf("missing pager export: %q", out)
	}
}

func TestPrepareShellInvocationPowerShellDoesNotInjectPOSIX(t *testing.T) {
	args, prepared, posix := prepareShellInvocation("powershell.exe", "Write-Output ok")
	if posix {
		t.Fatal("PowerShell must not be classified as POSIX")
	}
	if strings.Contains(prepared, "exec </dev/null") || strings.Contains(prepared, "export GIT_PAGER") {
		t.Fatalf("PowerShell received POSIX preamble: %q", prepared)
	}
	if !strings.Contains(prepared, "OutputEncoding") || !strings.Contains(prepared, "Write-Output ok") {
		t.Fatalf("PowerShell UTF-8 preamble or command missing: %q", prepared)
	}
	if len(args) < 2 || args[len(args)-2] != "-Command" || args[len(args)-1] != prepared {
		t.Fatalf("unexpected PowerShell args: %#v", args)
	}
}

func TestPrepareShellInvocationPOSIXKeepsNonInteractivePreamble(t *testing.T) {
	args, prepared, posix := prepareShellInvocation("bash", "echo ok")
	if !posix {
		t.Fatal("bash must be classified as POSIX")
	}
	if !strings.Contains(prepared, "exec </dev/null") || !strings.Contains(prepared, "export GIT_PAGER=cat") {
		t.Fatalf("missing POSIX preamble: %q", prepared)
	}
	if len(args) != 2 || args[0] != "-c" || args[1] != prepared {
		t.Fatalf("unexpected POSIX args: %#v", args)
	}
}

func TestNewShellInactivityWatch(t *testing.T) {
	w := NewShellInactivityWatch(1)
	if w == nil {
		t.Fatal("expected watch")
	}
	w.Bump()
	select {
	case <-w.Expired:
	case <-time.After(3 * time.Second):
		t.Fatal("expected inactivity fire within 3s")
	}
}

func TestResolveShellNoOutputTimeoutSeconds(t *testing.T) {
	if ResolveShellNoOutputTimeoutSeconds(0) != 300 {
		t.Fatal("zero should default to 300")
	}
	if ResolveShellNoOutputTimeoutSeconds(-1) != 0 {
		t.Fatal("-1 should disable")
	}
	if ResolveShellNoOutputTimeoutSeconds(30) != 30 {
		t.Fatal("explicit value")
	}
}

// TestNonInteractiveStdinReadExitsQuickly 验证 exec </dev/null + attachNonInteractiveStdin 时 read 立即 EOF，不挂起。
func TestNonInteractiveStdinReadExitsQuickly(t *testing.T) {
	requirePOSIXShell(t)
	if testing.Short() {
		t.Skip("skipping shell integration in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", PrepareNonInteractiveShellCommand(`read x; echo "x=<$x>"`))
	attachNonInteractiveStdin(cmd)

	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("read with closed stdin took %v, want <2s", elapsed)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v output=%q", err, out)
	}
	if !strings.Contains(string(out), "x=<>") {
		t.Fatalf("unexpected output: %q", out)
	}
}

// TestNonInteractiveStdinReadBlocksWithoutRedirect 对照：stdin 为永不写入的管道时 read 会挂起。
func TestNonInteractiveStdinReadBlocksWithoutRedirect(t *testing.T) {
	requirePOSIXShell(t)
	if testing.Short() {
		t.Skip("skipping shell integration in -short")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// 保持 w 打开且不写数据，模拟「等待用户输入」

	cmd := exec.Command("sh", "-c", `read x; echo done`)
	cmd.Stdin = r

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		t.Fatalf("expected hang, but command finished: %v", err)
	case <-time.After(500 * time.Millisecond):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = w.Close()
		<-done // 等待 goroutine 退出
	}
}
