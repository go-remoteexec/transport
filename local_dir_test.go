package transport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalDirSetsTheWorkingDirectory pins what Dir is for: a command
// runs THERE, not in the process's own working directory.
func TestLocalDirSetsTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	l := NewLocal()
	l.Dir = dir

	res, err := l.Exec(context.Background(), "pwd", nil)
	if err != nil {
		t.Fatal(err)
	}
	// macOS hands out /var/folders/... paths that are a symlink to
	// /private/var/..., and the shell's pwd prints the LOGICAL path it
	// was given. Resolving BOTH sides is what makes this compare
	// directories rather than spellings.
	if got, want := realPath(t, strings.TrimSpace(res.Stdout)), realPath(t, dir); got != want {
		t.Errorf("pwd = %q, want %q", got, want)
	}

	// Unset Dir keeps the old behaviour: the process's own directory.
	plain := NewLocal()
	res, err = plain.Exec(context.Background(), "pwd", nil)
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := realPath(t, strings.TrimSpace(res.Stdout)), realPath(t, cwd); got != want {
		t.Errorf("with no Dir, pwd = %q, want the process cwd %q", got, want)
	}
}

// TestLocalDirResolvesRelativeRemotePaths pins the other half: every
// method taking a REMOTE path resolves a relative one against Dir, so a
// caller that sets Dir gets one consistent answer from all of them.
func TestLocalDirResolvesRelativeRemotePaths(t *testing.T) {
	dir := t.TempDir()
	l := NewLocal()
	l.Dir = dir

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Put: the remote path is relative, so it lands under Dir.
	if err := l.Put(context.Background(), src, "sub/dest.txt", PutOptions{MkdirParents: true}); err != nil {
		t.Fatal(err)
	}
	landed := filepath.Join(dir, "sub", "dest.txt")
	if _, err := os.Stat(landed); err != nil {
		t.Fatalf("Put with a relative remote path did not land under Dir: %v", err)
	}

	// Fetch reads it back from the same place.
	back := filepath.Join(t.TempDir(), "back.txt")
	if err := l.Fetch(context.Background(), "sub/dest.txt", back); err != nil {
		t.Fatalf("Fetch with a relative remote path: %v", err)
	}
	data, err := os.ReadFile(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "payload" {
		t.Errorf("fetched %q, want %q", data, "payload")
	}

	// Remove deletes it from the same place.
	if err := l.Remove(context.Background(), "sub/dest.txt"); err != nil {
		t.Fatalf("Remove with a relative remote path: %v", err)
	}
	if _, err := os.Stat(landed); !os.IsNotExist(err) {
		t.Errorf("Remove with a relative remote path did not remove it under Dir")
	}

	// An ABSOLUTE remote path is untouched by Dir.
	abs := filepath.Join(t.TempDir(), "abs.txt")
	if err := l.Put(context.Background(), src, abs, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Errorf("an absolute remote path must not be rewritten: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, abs)); err == nil {
		t.Error("an absolute remote path was joined onto Dir")
	}
}

func realPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolving %q: %v", path, err)
	}
	return resolved
}
