// Package transport implements remote command execution — the low-level
// primitives an orchestration tool's task/module logic runs commands and
// moves files through, whether the target is the control node itself
// (Local), a Unix-like host over SSH (SSH), or a Windows host over
// WinRM (WinRM) — plus privilege escalation (Become: sudo/su/doas) as a
// decorator over any of them.
//
// It is deliberately scoped to these primitives and nothing
// tool-specific: no playbooks, no catalogs, no task manifests. Ansible's
// modules and Puppet Bolt's tasks both reduce, in the end, to "run this
// command" and "put this file there" — this package is that reduction,
// shared instead of reimplemented per tool.
package transport

import (
	"context"
	"io"
)

// Result is the outcome of running one command: its captured output and
// exit code.
type Result struct {
	Stdout string
	Stderr string
	RC     int
}

// PutOptions configures a file upload.
type PutOptions struct {
	// Executable chmods the remote file +x after writing (POSIX targets
	// only; WinRM implementations ignore it — Windows has no exec bit).
	Executable bool
	// MkdirParents creates the destination's parent directory first.
	MkdirParents bool
}

// Connection is how a caller reaches its target: run a shell command,
// move files in either direction, and clean up after itself. Every
// task/module operation is expressed in terms of these primitives so
// the same higher-level logic runs unchanged whether the connection is
// local, SSH, or WinRM.
type Connection interface {
	// Exec runs cmd through the target's shell (one command line, not an
	// argv — matching how both Ansible and Bolt build task invocations)
	// and returns its captured output and exit code. A non-zero exit is
	// not itself an error; err is only for a failure to run the command
	// at all. stdin, if non-nil, is streamed to the command's standard
	// input — how a become/run-as password reaches sudo/su without ever
	// appearing in argv or an environment variable.
	Exec(ctx context.Context, cmd string, stdin io.Reader) (Result, error)

	// Put copies the local file at localPath to remotePath on the
	// target.
	Put(ctx context.Context, localPath, remotePath string, opts PutOptions) error

	// Fetch copies the file at remotePath on the target to the local
	// file at localPath.
	Fetch(ctx context.Context, remotePath, localPath string) error

	// Remove deletes remotePath on the target. Removing a path that
	// does not exist is not an error.
	Remove(ctx context.Context, remotePath string) error

	// TempPath returns a fresh path under the target's temp directory
	// ending in base, using the target's own path syntax (forward
	// slashes for Local/SSH, backslashes under WinRM).
	TempPath(base string) string

	// Close releases any resources (an SSH/WinRM connection, an open
	// shell).
	Close() error
}
