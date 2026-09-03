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
// StdinPipe/StdoutPipe/StderrPipe (which must be usable before Start,
// matching os/exec's own Cmd.StdinPipe/StdoutPipe/StderrPipe convention)
// hand back io.Pipe ends now and Start wires the *exec.Cmd's Stdin/
// Stdout/Stderr to the other ends of those same pipes — the standard way
// to offer pre-Start pipes for a command whose argv isn't chosen yet.
func (l *Local) NewSession(ctx context.Context) (Session, error) {
	return &localSession{shell: l.shell(), ctx: ctx}, nil
}

type localSession struct {
	shell string
	ctx   context.Context
	cmd   *exec.Cmd

	stdinW  *io.PipeWriter // returned to the caller
	stdinR  *io.PipeReader // wired to cmd.Stdin
	stdoutR *io.PipeReader // returned to the caller
	stdoutW *io.PipeWriter // wired to cmd.Stdout
	stderrR *io.PipeReader // returned to the caller
	stderrW *io.PipeWriter // wired to cmd.Stderr

	// waitOnce guards cmd.Wait(), which os/exec panics if called twice —
	// both Session.Wait and Session.Close (when it fires mid-run) need
	// to reap the process, so both funnel through doWait.
	waitOnce sync.Once
	waitRC   int
	waitErr  error
}

func (s *localSession) StdinPipe() (io.WriteCloser, error) {
	if s.stdinW == nil {
		s.stdinR, s.stdinW = io.Pipe()
	}
	return s.stdinW, nil
}

func (s *localSession) StdoutPipe() (io.Reader, error) {
	if s.stdoutR == nil {
		s.stdoutR, s.stdoutW = io.Pipe()
	}
	return s.stdoutR, nil
}

func (s *localSession) StderrPipe() (io.Reader, error) {
	if s.stderrR == nil {
		s.stderrR, s.stderrW = io.Pipe()
	}
	return s.stderrR, nil
}

func (s *localSession) Start(cmd string) error {
	c := exec.CommandContext(s.ctx, s.shell, "-c", cmd)
	// A shell command like "sleep 30" runs as a grandchild that inherits
	// the shell's stdout/stderr fds; killing only the shell (Close does
	// exactly that, via Process.Kill) leaves the grandchild holding
	// those fds open, and without a bound Wait would then block on
	// draining them until the grandchild exits on its own. WaitDelay
	// bounds that: once the process itself has been reaped, Wait force-
	// closes any pipes still open after this long instead of hanging.
	c.WaitDelay = 5 * time.Second
	if s.stdinR != nil {
		c.Stdin = s.stdinR
	}
	if s.stdoutW != nil {
		c.Stdout = s.stdoutW
	}
	if s.stderrW != nil {
		c.Stderr = s.stderrW
	}
	s.cmd = c
	if err := c.Start(); err != nil {
		return fmt.Errorf("transport: local session start: %w", err)
	}
	return nil
}

func (s *localSession) Wait() (int, error) {
	if s.cmd == nil {
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
		// Cmd.Wait only returns once its internal copy-to-c.Stdout/
		// Stderr goroutines finish, which for an io.Pipe writer means a
		// reader has drained it — closing the writer ends here lets a
		// caller's final Read see io.EOF rather than hang.
		if s.stdoutW != nil {
			s.stdoutW.Close()
		}
		if s.stderrW != nil {
			s.stderrW.Close()
		}
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

// Close terminates the process (if still running) and releases the
// session's pipes. Safe to call after Wait, and safe to call more than
// once.
func (s *localSession) Close() error {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	// Close every pipe end before reaping, both directions: Cmd.Wait
	// blocks until ALL of Start's internal copy goroutines finish, not
	// just the output ones.
	//
	//   - stdout/stderr: that goroutine copies FROM the child INTO our
	//     io.Pipe: closing the reader end makes a pending write fail
	//     immediately instead of stalling forever with nothing left
	//     reading it.
	//   - stdin: that goroutine copies FROM our io.Pipe INTO the child —
	//     the opposite direction — so it's blocked on a *read* from
	//     stdinR, and killing the child does not unblock that (the
	//     goroutine is waiting on data from us, not from the child).
	//     Closing stdinW is what makes the pending read see io.EOF. This
	//     one has to close BEFORE doWait for the same reason the output
	//     pipes do: get here without it — e.g. a caller that dials,
	//     never touches stdin, and closes — and doWait hangs forever on
	//     a copy goroutine waiting for input that will never arrive.
	if s.stdinW != nil {
		_ = s.stdinW.Close()
	}
	if s.stdinR != nil {
		_ = s.stdinR.Close()
	}
	if s.stdoutR != nil {
		_ = s.stdoutR.Close()
	}
	if s.stderrR != nil {
		_ = s.stderrR.Close()
	}
	if s.cmd != nil {
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
