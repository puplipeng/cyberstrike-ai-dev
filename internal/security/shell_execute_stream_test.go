package security

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk/filesystem"
)

func TestEinoStreamingShell_NativeExecution(t *testing.T) {
	for _, background := range []bool{false, true} {
		name := "foreground"
		if background {
			name = "background"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := "printf native-ok; printf native-err >&2"
			if runtime.GOOS == "windows" {
				command = "[Console]::Out.Write('native-ok'); [Console]::Error.Write('native-err')"
			}
			sr, err := NewEinoStreamingShell().ExecuteStreaming(ctx, &filesystem.ExecuteRequest{Command: command, RunInBackendGround: background})
			if err != nil {
				t.Fatal(err)
			}
			defer sr.Close()
			var output strings.Builder
			var exitCode *int
			for {
				response, err := sr.Recv()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if response != nil {
					output.WriteString(response.Output)
					if response.ExitCode != nil {
						exitCode = response.ExitCode
					}
				}
			}
			if exitCode == nil || *exitCode != 0 {
				t.Fatalf("missing successful exit: %v, output %q", exitCode, output.String())
			}
			if !background && (!strings.Contains(output.String(), "native-ok") || !strings.Contains(output.String(), "native-err")) {
				t.Fatalf("missing stdout/stderr: %q", output.String())
			}
		})
	}
}

func TestEinoStreamingShell_NativeExitCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sr, err := NewEinoStreamingShell().ExecuteStreaming(ctx, &filesystem.ExecuteRequest{Command: "exit 7"})
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Close()
	var exitCode *int
	for {
		response, err := sr.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if response != nil && response.ExitCode != nil {
			exitCode = response.ExitCode
		}
	}
	if exitCode == nil || *exitCode != 7 {
		t.Fatalf("expected exit 7, got %v", exitCode)
	}
}

func TestEinoStreamingShell_StreamsStderrBeforeStdoutEOF(t *testing.T) {
	requirePOSIXShell(t)
	shell := NewEinoStreamingShell()
	cmd := PrepareNonInteractiveShellCommand("echo err-only >&2; exit 1")
	sr, err := shell.ExecuteStreaming(context.Background(), &filesystem.ExecuteRequest{Command: cmd})
	if err != nil {
		t.Fatalf("ExecuteStreaming: %v", err)
	}
	defer sr.Close()

	start := time.Now()
	var got strings.Builder
	for {
		resp, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		if resp != nil && resp.Output != "" {
			got.WriteString(resp.Output)
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("expected fast completion, took %v", time.Since(start))
	}
	if !strings.Contains(got.String(), "err-only") {
		t.Fatalf("expected stderr in output, got: %q", got.String())
	}
}

func TestEinoStreamingShell_SudoFailsFast(t *testing.T) {
	requirePOSIXShell(t)
	binDir := t.TempDir()
	fakeSudo := filepath.Join(binDir, "sudo")
	if err := os.WriteFile(fakeSudo, []byte("#!/bin/sh\nprintf 'sudo: a password is required\\n' >&2\nIFS= read -r password\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	shell := NewEinoStreamingShell()
	cmd := PrepareNonInteractiveShellCommand("sudo whoami && sudo cat /etc/os-release")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sr, err := shell.ExecuteStreaming(ctx, &filesystem.ExecuteRequest{Command: cmd})
	if err != nil {
		t.Fatalf("ExecuteStreaming: %v", err)
	}
	defer sr.Close()

	start := time.Now()
	var got strings.Builder
	for {
		resp, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		if resp == nil {
			continue
		}
		got.WriteString(resp.Output)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("sudo command did not fail before the deadline; output=%q", got.String())
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("sudo should fail quickly, took %v output=%q", time.Since(start), got.String())
	}
	out := got.String()
	if strings.Contains(out, "command exited with non-zero code") {
		t.Fatalf("legacy exit line present: %q", out)
	}
	if !strings.Contains(out, "sudo") && !strings.Contains(out, "password") && !strings.Contains(out, "terminal") {
		t.Fatalf("expected sudo error text, got: %q", out)
	}
}

func TestEinoStreamingShell_StderrWhileStdoutBlocks(t *testing.T) {
	requirePOSIXShell(t)
	shell := NewEinoStreamingShell()
	// 模拟 sudo：stderr 先有输出，stdout 侧进程仍挂起；旧 eino local 在首包 stderr 前不会向流写任何内容。
	cmd := PrepareNonInteractiveShellCommand(`echo "password prompt" >&2; sleep 30`)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sr, err := shell.ExecuteStreaming(ctx, &filesystem.ExecuteRequest{Command: cmd})
	if err != nil {
		t.Fatalf("ExecuteStreaming: %v", err)
	}
	defer sr.Close()

	start := time.Now()
	var got strings.Builder
	for {
		resp, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			break
		}
		if resp != nil && resp.Output != "" {
			got.WriteString(resp.Output)
			if strings.Contains(got.String(), "password prompt") {
				break
			}
		}
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("expected stderr promptly, took %v output=%q", time.Since(start), got.String())
	}
	if !strings.Contains(got.String(), "password prompt") {
		t.Fatalf("expected early stderr, got: %q", got.String())
	}
}

// TestEinoStreamingShell_BackgroundJobDoesNotHoldPipe 模拟 cmd & 后继续前台逻辑：重定向后应快速结束。
func TestEinoStreamingShell_BackgroundJobDoesNotHoldPipe(t *testing.T) {
	requirePOSIXShell(t)
	if testing.Short() {
		t.Skip("skipping shell integration in -short")
	}
	shell := NewEinoStreamingShell()
	cmd := `(sh -c 'printf x; sleep 120') & echo started; sleep 0`
	sr, err := shell.ExecuteStreaming(context.Background(), &filesystem.ExecuteRequest{Command: cmd})
	if err != nil {
		t.Fatalf("ExecuteStreaming: %v", err)
	}
	defer sr.Close()

	start := time.Now()
	var got strings.Builder
	for {
		resp, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		if resp != nil && resp.Output != "" {
			got.WriteString(resp.Output)
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("expected fast completion, took %v output=%q", time.Since(start), got.String())
	}
	if !strings.Contains(got.String(), "started") {
		t.Fatalf("expected foreground echo, got: %q", got.String())
	}
}
