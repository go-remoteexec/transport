package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Local is the "local" connection: the target IS the control node.
// Running the command through a real shell (rather than an argv
// exec.Command) is not a shortcut — it's what a local task/module runner
// needs, since a command's args are shell syntax (pipes, redirects,
// globs) that only a shell interprets.
type Local struct {
	// Shell is the interpreter commands are run through. Defaults to
	// "sh" resolved via PATH.
	Shell string
	// TempDir is where TempPath builds paths under. Defaults to
	// os.TempDir().
	TempDir string
}

// NewLocal returns a Local connection using "sh" resolved via PATH.
//
// This is deliberately the bare name "sh", not the absolute path
// "/bin/sh": os/exec's Windows LookPath only recognizes "\" and ":" as
// path separators, not "/", so an absolute-looking POSIX path like
// "/bin/sh" is instead treated as a literal bare command name and searched
// for on %PATH% — where it can never exist — failing every local exec on
// Windows with "executable file not found in %PATH%". A bare "sh" resolves
// correctly on both POSIX (finds /bin/sh or /usr/bin/sh via PATH) and
// Windows (finds Git for Windows' sh.exe, which GitHub's windows-latest
// runners — and most developer machines with Git installed — already have
// on PATH).
func NewLocal() *Local {
	return &Local{Shell: "sh"}
}

func (l *Local) shell() string {
	if l.Shell != "" {
		return l.Shell
	}
	return "sh"
}

func (l *Local) Exec(ctx context.Context, cmd string, stdin io.Reader) (Result, error) {
	c := exec.CommandContext(ctx, l.shell(), "-c", cmd)
	c.Stdin = stdin
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()

	rc := 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			rc = exitErr.ExitCode()
		} else {
			return Result{}, fmt.Errorf("transport: local exec: %w", err)
		}
	}
	return Result{Stdout: stdout.String(), Stderr: stderr.String(), RC: rc}, nil
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// NewSession opens a live streaming session for a local command,
// implementing Streamer. The command itself is not known until Start, so
// this builds the *exec.Cmd now with an empty placeholder "-c" argument,
// which Start fills in later — letting StdinPipe/StdoutPipe/StderrPipe
// use os/exec's own Cmd.StdinPipe/StdoutPipe/StderrPipe (real OS pipes)
// instead of a manually bridged io.Pipe.
//
// That distinction matters, and cost a real deadlock to learn: assigning
// an arbitrary io.Reader/io.Writer to Cmd.Stdin/Stdout/Stderr makes
// os/exec spawn its own internal copy goroutine, and Cmd.Wait blocks
// until every one of those finishes — including the stdin one, which
// only sees io.EOF once the write end is closed. A caller that requests
// StdinPipe (as any real interactive session does, to be able to forward
// keystrokes) but has no need to write anything — a command that doesn't
// read stdin, or a caller closing the session on an unrelated event
// before ever touching stdin — would then hang in Wait forever, since
// nothing else ever closes that write end. Cmd's own *Pipe methods don't
// have this problem: they hand back a real OS pipe end directly, with no
// bridging goroutine for Wait to wait on.
func (l *Local) NewSession(ctx context.Context) (Session, error) {
	cmd := exec.CommandContext(ctx, l.shell(), "-c", "")
	// A shell command like "sleep 30" runs as a grandchild that inherits
	// the shell's stdout/stderr fds; killing only the shell (Close does
	// exactly that, via Process.Kill) leaves the grandchild holding those
	// fds open, and without a bound Wait would then block draining them
	// until the grandchild exits on its own. WaitDelay bounds that: once
	// the process itself has been reaped, Wait force-closes any pipes
	// still open after this long instead of hanging.
	cmd.WaitDelay = 5 * time.Second
	return &localSession{cmd: cmd}, nil
}

type localSession struct {
	cmd *exec.Cmd

	stdin          io.WriteCloser
	stdout, stderr io.ReadCloser

	// waitOnce guards cmd.Wait(), which os/exec panics if called twice —
	// both Session.Wait and Session.Close (when it fires mid-run) need
	// to reap the process, so both funnel through doWait.
	waitOnce sync.Once
	waitRC   int
	waitErr  error
}

func (s *localSession) StdinPipe() (io.WriteCloser, error) {
	if s.stdin == nil {
		w, err := s.cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("transport: local session stdin pipe: %w", err)
		}
		s.stdin = w
	}
	return s.stdin, nil
}

func (s *localSession) StdoutPipe() (io.Reader, error) {
	if s.stdout == nil {
		r, err := s.cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("transport: local session stdout pipe: %w", err)
		}
		s.stdout = r
	}
	return s.stdout, nil
}

func (s *localSession) StderrPipe() (io.Reader, error) {
	if s.stderr == nil {
		r, err := s.cmd.StderrPipe()
		if err != nil {
			return nil, fmt.Errorf("transport: local session stderr pipe: %w", err)
		}
		s.stderr = r
	}
	return s.stderr, nil
}

func (s *localSession) Start(cmd string) error {
	// Fill in the placeholder "-c" argument NewSession left empty — the
	// command itself wasn't known until now, but StdinPipe/StdoutPipe/
	// StderrPipe had to be callable before Start, so the *exec.Cmd was
	// already built.
	s.cmd.Args[len(s.cmd.Args)-1] = cmd
	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("transport: local session start: %w", err)
	}
	return nil
}

func (s *localSession) Wait() (int, error) {
	if s.cmd.Process == nil {
		return 0, fmt.Errorf("transport: local session Wait called before Start")
	}
	return s.doWait()
}

// doWait calls cmd.Wait exactly once (os/exec panics on a second call)
// and caches the result, so both Wait and a mid-run Close — which also
// needs to reap the process — can call it safely regardless of which
// happens first or whether both happen.
func (s *localSession) doWait() (int, error) {
	s.waitOnce.Do(func() {
		err := s.cmd.Wait()
		if err == nil {
			return
		}
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			s.waitRC = exitErr.ExitCode()
			return
		}
		s.waitErr = fmt.Errorf("transport: local session wait: %w", err)
	})
	return s.waitRC, s.waitErr
}

// Close terminates the process (if still running) and reaps it. Safe to
// call after Wait, and safe to call more than once. It does not need to
// close the session's pipes itself: since StdinPipe/StdoutPipe/StderrPipe
// are real os/exec pipes rather than a manually bridged io.Pipe, Cmd.Wait
// (via doWait, above) already closes them on the way out — that is
// exactly the deadlock NewSession's doc comment describes avoiding.
func (s *localSession) Close() error {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	if s.cmd.Process != nil {
		_, _ = s.doWait()
	}
	return nil
}

func (l *Local) Put(ctx context.Context, localPath, remotePath string, opts PutOptions) error {
	if opts.MkdirParents {
		if err := os.MkdirAll(filepath.Dir(remotePath), 0o755); err != nil {
			return fmt.Errorf("transport: %w", err)
		}
	}
	if err := copyFile(localPath, remotePath); err != nil {
		return err
	}
	if opts.Executable {
		if err := os.Chmod(remotePath, 0o755); err != nil {
			return fmt.Errorf("transport: %w", err)
		}
	}
	return nil
}

func (l *Local) Fetch(ctx context.Context, remotePath, localPath string) error {
	return copyFile(remotePath, localPath)
}

func (l *Local) Remove(ctx context.Context, remotePath string) error {
	if err := os.Remove(remotePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("transport: %w", err)
	}
	return nil
}

// tempPathCounter guarantees TempPath returns distinct paths across calls
// even when the clock's resolution isn't fine enough to separate two calls
// made back-to-back (observed on Windows CI runners).
var tempPathCounter uint64

func (l *Local) TempPath(base string) string {
	dir := l.TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	n := atomic.AddUint64(&tempPathCounter, 1)
	return filepath.Join(dir, fmt.Sprintf("remoteexec_%d_%d_%s", time.Now().UnixNano(), n, base))
}

func (l *Local) Close() error { return nil }

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	return out.Close()
}
