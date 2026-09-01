package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Local is the "local" connection: the target IS the control node.
// Running the command through a real shell (rather than an argv
// exec.Command) is not a shortcut — it's what a local task/module runner
// needs, since a command's args are shell syntax (pipes, redirects,
// globs) that only a shell interprets.
type Local struct {
	// Shell is the interpreter commands are run through. Defaults to
	// /bin/sh.
	Shell string
	// TempDir is where TempPath builds paths under. Defaults to
	// os.TempDir().
	TempDir string
}

// NewLocal returns a Local connection using /bin/sh.
func NewLocal() *Local {
	return &Local{Shell: "/bin/sh"}
}

func (l *Local) shell() string {
	if l.Shell != "" {
		return l.Shell
	}
	return "/bin/sh"
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

func (l *Local) TempPath(base string) string {
	dir := l.TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, fmt.Sprintf("remoteexec_%d_%s", time.Now().UnixNano(), base))
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
