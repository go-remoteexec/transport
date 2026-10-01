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

	// Exe overrides the program the method runs, Ansible's become_exe
	// (ansible_become_exe / ANSIBLE_BECOME_EXE). Empty means the
	// method's own name, which is what Ansible does: `become_exe` in
	// the real sudo plugin reads `self.get_option('become_exe') or
	// self.name`. A full path is the usual reason to set it.
	Exe string

	// Flags replaces the method's default flags, Ansible's become_flags
	// (ansible_become_flags / ANSIBLE_BECOME_FLAGS). Empty means the
	// method's own default -- "-H -S -n" for sudo, "" for su and doas,
	// read from each real become plugin's DOCUMENTATION. Set it and it
	// replaces that default outright rather than adding to it, which is
	// also what Ansible does.
	//
	// With a password set, sudo's own plugin strips -n/--non-interactive
	// out of the flags before use, since a non-interactive sudo can
	// never read the password it was just given. The same stripping
	// happens here, including the -n folded into a short cluster like
	// -Hn, so a caller that sets Flags and a Password does not have to
	// know to remove it.
	Flags string
}

// defaultBecomeFlags are each method's own default flag string, taken
// from the real become plugins' DOCUMENTATION blocks. A method absent
// from this map defaults to no flags.
var defaultBecomeFlags = map[BecomeMethod]string{
	BecomeSudo: "-H -S -n",
}

// flags returns the flag string to use: Flags when set, otherwise the
// method's default, with -n removed when a password has to be read.
func (c BecomeConfig) flags() string {
	f := c.Flags
	if f == "" {
		f = defaultBecomeFlags[c.Method]
	}
	if c.Password == "" || f == "" {
		return f
	}
	return stripNonInteractive(f)
}

// stripNonInteractive removes -n/--non-interactive from a flag string,
// including an n folded into a short cluster (-Hn -> -H), mirroring the
// regex real sudo.py applies for the same reason: the password has to
// be readable.
func stripNonInteractive(flags string) string {
	var out []string
	for _, f := range strings.Fields(flags) {
		switch {
		case f == "-n" || f == "--non-interactive":
			continue
		case strings.HasPrefix(f, "--"):
			out = append(out, f)
		case strings.HasPrefix(f, "-") && strings.Contains(f, "n"):
			if s := "-" + strings.Replace(f[1:], "n", "", 1); s != "-" {
				out = append(out, s)
			}
		default:
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

// exe returns the program to run: Exe when set, otherwise the method's
// own name.
func (c BecomeConfig) exe() string {
	if c.Exe != "" {
		return c.Exe
	}
	return string(c.Method)
}

// joinBecome assembles a become command line, dropping the empty parts
// so an unset flag string does not leave a double space.
func joinBecome(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

// Become wraps conn so every Exec runs as BecomeConfig.User via the
// configured escalation method. Put/Fetch/Close pass through unchanged
// (Ansible's own become plumbing only affects command execution, not
// file transfer, since the transferred file is written by the
// connection's own user and then chmod/chowned by an escalated task).
//
// Known gap: the wrapper returned here does not implement Streamer, even
// when conn does. Exec's become handling works by printing a random
// marker after escalation succeeds and slicing everything before it out
// of the buffered result (see successMarker below) — doing the
// equivalent safely on a live stream means scanning the stdout stream
// for that marker in real time and only starting to hand bytes to the
// caller once it has been seen, while still correctly forwarding a
// become password to the escalation program's stdin ahead of the
// wrapped command's own stdin. That is buildable, but not something to
// get subtly wrong under time pressure, so it is deliberately left
// undone rather than shipped half-right: conn.(transport.Streamer) on a
// Become-wrapped connection fails the type assertion, same as WinRM.
// Callers needing both become and a live interactive session need to
// wait for a follow-up that implements this deliberately, or run their
// interactive session unprivileged.
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
	sh := fmt.Sprintf("sh -c %s", shellQuote(inner))
	exe, flags := c.exe(), c.flags()

	switch c.Method {
	case BecomeSu:
		// su reads the password from its controlling terminal or stdin
		// when not run interactively; -c hands the rest to the shell.
		cmd := joinBecome(exe, flags, shellQuote(c.User), "-c", shellQuote(sh))
		if c.Password != "" {
			return cmd, c.Password + "\n"
		}
		return cmd, ""

	case BecomeDoas:
		cmd := joinBecome(exe, flags, "-u", shellQuote(c.User), sh)
		if c.Password != "" {
			return cmd, c.Password + "\n"
		}
		return cmd, ""

	default: // BecomeSudo
		// The default flags are sudo's own "-H -S -n". -S reads the
		// password from stdin rather than the tty, and -n fails instead
		// of prompting -- which is why flags() drops -n as soon as a
		// password is configured, exactly as the real plugin does.
		cmd := joinBecome(exe, flags, "-u", shellQuote(c.User), sh)
		if c.Password != "" {
			return cmd, c.Password + "\n"
		}
		return cmd, ""
	}
}
