package skillpackage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackageFilesStayInsideSkillRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "skills")
	dir := filepath.Join(root, "sample")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../outside", `..\outside`, "/absolute", `C:\outside`, ".", ""} {
		if _, err := ReadPackageFile(root, "sample", path, 0); err == nil {
			t.Errorf("read accepted %q", path)
		}
		if err := WritePackageFile(root, "sample", path, []byte("bad")); err == nil {
			t.Errorf("write accepted %q", path)
		}
	}
	if err := WritePackageFile(root, "sample", "references/note.md", []byte("safe")); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadPackageFile(root, "sample", "references/note.md", 2); err != nil || string(data) != "sa" {
		t.Fatalf("bounded read: %q %v", data, err)
	}
	if _, err := OpenSkillRoot(root, ".."); err == nil {
		t.Fatal("parent skill accepted")
	}
}

func TestPackageFilesRejectSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "skills")
	dir := filepath.Join(root, "sample")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "canary")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := ReadPackageFile(root, "sample", "link", 0); err == nil {
		t.Fatal("read followed outside symlink")
	}
	if err := WritePackageFile(root, "sample", "link", []byte("bad")); err == nil {
		t.Fatal("write followed outside symlink")
	}
	if err := os.Symlink(base, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSkillRoot(root, "linked"); err == nil {
		t.Fatal("symlink skill directory accepted")
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "keep" {
		t.Fatalf("canary changed: %v", err)
	}
}
