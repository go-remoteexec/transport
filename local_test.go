package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX executable bit; os.Chmod's mode argument is ignored beyond the read-only attribute")
	}
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

func TestLocalStreamerNewSession(t *testing.T) {
	l := NewLocal()
	var streamer Streamer = l
	sess, err := streamer.NewSession(context.Background())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}

	if err := sess.Start("cat"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// A paced write-then-read-back per line proves output arrives
	// progressively rather than only after the whole command finishes
	// (cat never finishes until stdin closes, so a buffered
	// implementation would simply hang here instead of echoing).
	lines := make(chan string)
	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(stdout)
		for {
			s, err := br.ReadString('\n')
			if s != "" {
				lines <- strings.TrimRight(s, "\n")
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	readLine := func() (string, error) {
		select {
		case s := <-lines:
			return s, nil
		case err := <-errc:
			return "", err
		case <-time.After(5 * time.Second):
			return "", fmt.Errorf("timed out waiting for a line")
		}
	}

	for i, line := range []string{"alpha", "beta", "gamma"} {
		if _, err := io.WriteString(stdin, line+"\n"); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got, err := readLine()
		if err != nil {
			t.Fatalf("readLine %d: %v", i, err)
		}
		if got != line {
			t.Errorf("line %d = %q, want %q", i, got, line)
		}
	}
	stdin.Close()

	rc, err := sess.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if rc != 0 {
		t.Errorf("rc = %d, want 0", rc)
	}
}

func TestLocalStreamerNonZeroExit(t *testing.T) {
	l := NewLocal()
	sess, err := l.NewSession(context.Background())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.Start("exit 5"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	rc, err := sess.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if rc != 5 {
		t.Errorf("rc = %d, want 5", rc)
	}
}

func TestLocalStreamerCloseMidRun(t *testing.T) {
	l := NewLocal()
	sess, err := l.NewSession(context.Background())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}

	if err := sess.Start("echo started; sleep 30"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	buf := make([]byte, 64)
	n, err := stdout.Read(buf)
	if err != nil {
		t.Fatalf("reading 'started': %v", err)
	}
	if strings.TrimSpace(string(buf[:n])) != "started" {
		t.Fatalf("stdout = %q", buf[:n])
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close must have killed and reaped the 30s sleep rather than leaving
	// it running: Wait should return promptly with whatever Close
	// already observed, not block for anywhere near 30s (and calling it
	// after Close must not panic or hang, since Close itself has to reap
	// the process too).
	done := make(chan struct{})
	go func() {
		sess.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after Close killed the process")
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
