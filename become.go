package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// BecomeMethod names a privilege-escalation program.
type BecomeMethod string

const (
	BecomeSudo BecomeMethod = "sudo"
	BecomeSu   BecomeMethod = "su"
	BecomeDoas BecomeMethod = "doas"
)

// BecomeConfig configures privilege escalation, Ansible's `become:`.
type BecomeConfig struct {
	Method   BecomeMethod // default BecomeSudo
	User     string       // default "root"
	Password string       // optional; empty assumes passwordless (NOPASSWD sudoers, or doas persist)
}

// Become wraps conn so every Exec runs as BecomeConfig.User via the
// configured escalation method. Put/Fetch/Close pass through unchanged
// (Ansible's own become plumbing only affects command execution, not
// file transfer, since the transferred file is written by the
// connection's own user and then chmod/chowned by an escalated task).
func Become(conn Connection, cfg BecomeConfig) Connection {
	if cfg.Method == "" {
		cfg.Method = BecomeSudo
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	return &becomeConnection{Connection: conn, cfg: cfg}
}

type becomeConnection struct {
	Connection
	cfg BecomeConfig
}

// successMarker is a fresh random token printed right before the real
// command runs, so become-wrapped output can be split into "escalation
// noise" (a password prompt, a MOTD) and the command's own stdout —
// exactly what Ansible's BECOME-SUCCESS-<uuid> marker is for.
func successMarker() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "BECOME-SUCCESS-" + hex.EncodeToString(buf), nil
}

func (b *becomeConnection) Exec(ctx context.Context, cmd string, stdin io.Reader) (Result, error) {
	marker, err := successMarker()
	if err != nil {
		return Result{}, fmt.Errorf("transport: generating become marker: %w", err)
	}

	inner := fmt.Sprintf("echo %s; %s", marker, cmd)
	wrapped, becomeStdin := b.cfg.wrapCommand(inner)

	// The become password (if any) must reach the escalation program's
	// own stdin before the wrapped command's stdin, if it has one — sudo
	// -S/su both read the password as their first line of input, then
	// hand the rest of stdin to the child process.
	var fullStdin io.Reader
	switch {
	case becomeStdin != "" && stdin != nil:
		fullStdin = io.MultiReader(strings.NewReader(becomeStdin), stdin)
	case becomeStdin != "":
		fullStdin = strings.NewReader(becomeStdin)
	default:
		fullStdin = stdin
	}

	res, err := b.Connection.Exec(ctx, wrapped, fullStdin)
	if err != nil {
		return res, err
	}

	// Strip everything up to and including the success marker line so
	// the caller sees exactly the wrapped command's own output, not the
	// escalation program's prompt/banner noise.
	if i := strings.Index(res.Stdout, marker+"\n"); i >= 0 {
		res.Stdout = res.Stdout[i+len(marker)+1:]
	} else if !strings.Contains(res.Stdout, marker) {
		// The marker never appeared at all: escalation itself failed
		// (wrong password, user not in sudoers, ...) before the command
		// ever ran. Surface that clearly instead of returning the
		// escalation program's raw exit code as if the command had run.
		return res, fmt.Errorf("transport: become (%s) failed: %s", b.cfg.Method, strings.TrimSpace(res.Stderr))
	}
	return res, nil
}

// wrapCommand returns the full command line to execute and, separately,
// the bytes (if any) that must be written to its stdin before anything
// else — the become password, newline-terminated.
func (c BecomeConfig) wrapCommand(inner string) (cmdLine string, stdin string) {
	sh := fmt.Sprintf("/bin/sh -c %s", shellQuote(inner))

	switch c.Method {
	case BecomeSu:
		// su reads the password from its controlling terminal or stdin
		// when not run interactively; -c hands the rest to the shell.
		cmd := fmt.Sprintf("su %s -c %s", shellQuote(c.User), shellQuote(sh))
		if c.Password != "" {
			return cmd, c.Password + "\n"
		}
		return cmd, ""

	case BecomeDoas:
		cmd := fmt.Sprintf("doas -u %s %s", shellQuote(c.User), sh)
		if c.Password != "" {
			return cmd, c.Password + "\n"
		}
		return cmd, ""

	default: // BecomeSudo
		if c.Password != "" {
			// -S: read the password from stdin instead of the tty.
			cmd := fmt.Sprintf("sudo -H -S -u %s %s", shellQuote(c.User), sh)
			return cmd, c.Password + "\n"
		}
		// -n: fail instead of prompting — the right default when no
		// password was configured, matching passwordless-sudo setups
		// used by most real automation.
		cmd := fmt.Sprintf("sudo -H -n -u %s %s", shellQuote(c.User), sh)
		return cmd, ""
	}
}
