package transport

import (
	"bytes"
	"context"
	"io"
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

// TestLocalDirAppliesToASession pins Dir on the streaming path too. It
// is here because a neuter removing `cmd.Dir = l.Dir` from NewSession
// PASSED: Dir was set there and nothing looked.
func TestLocalDirAppliesToASession(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker.txt"), []byte("here"), 0o644); err != nil {
		t.Fatal(err)
	}

	l := NewLocal()
	l.Dir = dir
	sess, err := l.NewSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("cat marker.txt"); err != nil {
		t.Fatal(err)
	}

	// Drained before Wait: a session's output has to be read while the
	// command runs, not after it.
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, stdout)
		done <- buf.String()
	}()
	rc, err := sess.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if rc != 0 {
		t.Fatalf("rc = %d, want 0 -- the session did not run in Dir", rc)
	}
	if got := strings.TrimSpace(<-done); got != "here" {
		t.Errorf("stdout = %q, want %q -- a session must run in Dir too", got, "here")
	}
}

// ⛔⛔ THE BYTES SURVIVE THE REAP. os/exec's StdoutPipe is documented as "it is
// incorrect to call Wait before all reads from the pipe have completed" --
// Wait closes the pipe, and whatever the child wrote but the reader has not
// consumed is gone. That is not a contract a Session can offer: a caller reads
// on its own schedule, and a fast command that exits before the reader is
// scheduled loses everything.
//
// It is not theoretical. TestLocalDirAppliesToASession drains concurrently,
// exactly as the documentation asks, and still failed on the riscv64 lane on
// 2026-09-28 with stdout = "" and rc = 0: the command ran, wrote, exited, and
// the reader was never scheduled in time under qemu.
//
// So this reads AFTER Wait, which is the strongest form of the contract and
// the one a caller can actually rely on.
func TestASessionsOutputSurvivesTheReap(t *testing.T) {
	l := &Local{}
	sess, err := l.NewSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("echo surviving"); err != nil {
		t.Fatal(err)
	}
	rc, err := sess.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}

	// Nothing has read a byte yet, and the process is already reaped.
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, stdout); err != nil {
		t.Fatalf("reading after Wait: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "surviving" {
		t.Errorf("stdout after Wait = %q, want %q -- the reap ate the output", got, "surviving")
	}
}
