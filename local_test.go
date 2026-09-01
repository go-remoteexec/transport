package transport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalExec(t *testing.T) {
	l := NewLocal()
	res, err := l.Exec(context.Background(), "echo hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(res.Stdout) != "hello" {
		t.Errorf("stdout = %q", res.Stdout)
	}
	if res.RC != 0 {
		t.Errorf("rc = %d", res.RC)
	}
}

func TestLocalExecNonZero(t *testing.T) {
	l := NewLocal()
	res, err := l.Exec(context.Background(), "exit 3", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.RC != 3 {
		t.Errorf("rc = %d, want 3", res.RC)
	}
}

func TestLocalExecStderr(t *testing.T) {
	l := NewLocal()
	res, err := l.Exec(context.Background(), "echo oops >&2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(res.Stderr) != "oops" {
		t.Errorf("stderr = %q", res.Stderr)
	}
}

func TestLocalExecStdin(t *testing.T) {
	l := NewLocal()
	res, err := l.Exec(context.Background(), "cat", strings.NewReader("piped in"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "piped in" {
		t.Errorf("stdout = %q", res.Stdout)
	}
}

func TestLocalPutFetch(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	l := NewLocal()
	if err := l.Put(context.Background(), src, dst, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "payload" {
		t.Errorf("dst content = %q", data)
	}

	fetched := filepath.Join(dir, "fetched.txt")
	if err := l.Fetch(context.Background(), dst, fetched); err != nil {
		t.Fatal(err)
	}
	data2, err := os.ReadFile(fetched)
	if err != nil {
		t.Fatal(err)
	}
	if string(data2) != "payload" {
		t.Errorf("fetched content = %q", data2)
	}
}

func TestLocalPutMkdirParentsAndExecutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.sh")
	if err := os.WriteFile(src, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "nested", "deeper", "dst.sh")

	l := NewLocal()
	if err := l.Put(context.Background(), src, dst, PutOptions{MkdirParents: true, Executable: true}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("mode = %v, want executable bit set", info.Mode())
	}
}

func TestLocalRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gone.txt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLocal()
	if err := l.Remove(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after Remove")
	}
	// Removing an already-absent path is not an error.
	if err := l.Remove(context.Background(), path); err != nil {
		t.Fatalf("Remove of missing path: %v", err)
	}
}

func TestLocalTempPath(t *testing.T) {
	l := NewLocal()
	a := l.TempPath("script.sh")
	b := l.TempPath("script.sh")
	if a == b {
		t.Fatal("TempPath should return distinct paths across calls")
	}
	if filepath.Base(a) == "script.sh" {
		t.Fatal("TempPath should namespace the base, not return it verbatim")
	}
}
