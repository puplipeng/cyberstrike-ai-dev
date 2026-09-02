package security

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveToolCommandUsesManagedToolPath(t *testing.T) {
	dir := t.TempDir()
	name := "cyberstrike-test-tool"
	fileName := name
	if runtime.GOOS == "windows" {
		fileName += ".exe"
	}
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, []byte("test"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cyberStrikeToolPathEnv, dir)
	got, ok := resolveToolCommand(name)
	if !ok || !filepath.IsAbs(got) || !sameFilePath(got, path) {
		t.Fatalf("resolveToolCommand(%q) = %q, %v; want %q", name, got, ok, path)
	}
}

func TestPythonModuleAvailable(t *testing.T) {
	python, ok := resolveToolCommand("python3")
	if !ok {
		t.Skip("python is not available in the test environment")
	}
	if !pythonModuleAvailable(python, "json") {
		t.Fatal("stdlib module json should be available")
	}
	if pythonModuleAvailable(python, "cyberstrike_module_that_does_not_exist") {
		t.Fatal("nonexistent module reported as available")
	}
}

func TestToolRuntimeSearchDirsIncludeManagedVenvsFromRuntimeRoot(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app", "service")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	venvScripts := filepath.Join(root, "runtime", "security-tools", "venvs", "pytools")
	pythonName := "python3"
	if runtime.GOOS == "windows" {
		venvScripts = filepath.Join(venvScripts, "Scripts")
		pythonName = "python.exe"
	} else {
		venvScripts = filepath.Join(venvScripts, "bin")
	}
	if err := os.MkdirAll(venvScripts, 0o755); err != nil {
		t.Fatal(err)
	}
	pythonPath := filepath.Join(venvScripts, pythonName)
	if err := os.WriteFile(pythonPath, []byte("test"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv(cyberStrikeToolPathEnv, "")
	t.Chdir(appDir)

	dirs := toolRuntimeSearchDirs()
	found := false
	for _, dir := range dirs {
		if sameFilePath(dir, venvScripts) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("toolRuntimeSearchDirs() did not include managed venv path %q; got %v", venvScripts, dirs)
	}
}

func TestResolveToolCommandPrefersManagedPytoolsPython(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime", "security-tools")
	pytoolsScripts := filepath.Join(root, "venvs", "pytools")
	otherScripts := filepath.Join(root, "venvs", "prowler")
	if runtime.GOOS == "windows" {
		pytoolsScripts = filepath.Join(pytoolsScripts, "Scripts")
		otherScripts = filepath.Join(otherScripts, "Scripts")
	} else {
		pytoolsScripts = filepath.Join(pytoolsScripts, "bin")
		otherScripts = filepath.Join(otherScripts, "bin")
	}
	if err := os.MkdirAll(pytoolsScripts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(otherScripts, 0o755); err != nil {
		t.Fatal(err)
	}
	pythonName := "python3"
	if runtime.GOOS == "windows" {
		pythonName = "python.exe"
	}
	pytoolsPython := filepath.Join(pytoolsScripts, pythonName)
	otherPython := filepath.Join(otherScripts, pythonName)
	if err := os.WriteFile(pytoolsPython, []byte("pytools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPython, []byte("other"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv(cyberStrikeToolPathEnv, root)

	got, ok := resolveToolCommand("python3")
	if !ok || !sameFilePath(got, pytoolsPython) {
		t.Fatalf("resolveToolCommand(%q) = %q, %v; want %q", "python3", got, ok, pytoolsPython)
	}
}

func sameFilePath(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
