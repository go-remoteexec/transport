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
//
// It asserts the CONSEQUENCE -- a relative name in the command resolves
// under Dir -- rather than comparing `pwd` against a Go path. Those
// disagree by construction on Windows, where the shell is Git for
// Windows' sh and prints MSYS paths like /c/Users/... that Go's own
// path functions cannot resolve. The first version of this test did
// compare them, and failed on windows-latest for exactly that reason.
func TestLocalDirSetsTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker.txt"), []byte("here"), 0o644); err != nil {
		t.Fatal(err)
	}

	l := NewLocal()
	l.Dir = dir
	res, err := l.Exec(context.Background(), "cat marker.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.RC != 0 {
		t.Fatalf("rc = %d, want 0 -- the command did not run in Dir (stderr: %s)", res.RC, res.Stderr)
	}
	if got := strings.TrimSpace(res.Stdout); got != "here" {
		t.Errorf("stdout = %q, want %q -- a relative name must resolve under Dir", got, "here")
	}

	// With no Dir the same command runs in the process's own
	// directory, where that file does not exist.
	plain := NewLocal()
	res, err = plain.Exec(context.Background(), "cat marker.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.RC == 0 {
		t.Errorf("with no Dir the command succeeded; it must run in the process directory, where marker.txt is absent")
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
