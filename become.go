package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
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
// configured escalation method, and so do Put, Fetch and Remove: they
// are carried out through that same escalated Exec.
//
// They used to pass through unchanged, on the reasoning that Ansible's
// become only affects command execution: the controller writes the file
// into a temporary directory as the connection's own user, and an
// escalated module moves it into place. That reasoning holds for Ansible
// and not for the callers of this package. go-ansible's copy, template,
// lineinfile and blockinfile Put straight to the destination, so with
// `become: true` on a stock Ubuntu cloud image every one of them failed
// on a root-owned file:
//
//	writing /etc/hosts: transport: put /etc/hosts: exit 1:
//	bash: line 1: /etc/hosts: Permission denied
//
// -- the task asked for root and the write was made as `ubuntu`. Doing
// the transfer through the wrapper's own Exec makes the file land with
// the privileges the task asked for, whichever module wrote it. Close
// still passes through.
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

// Put writes localPath to remotePath as the become user, the same way
// SSH.Put does it as the login user: through `cat >` on the remote
// shell, with the file's bytes on stdin -- after the become password,
// when there is one, which Exec puts first.
func (b *becomeConnection) Put(ctx context.Context, localPath, remotePath string, opts PutOptions) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	if opts.MkdirParents {
		if dir := path.Dir(remotePath); dir != "." && dir != "/" {
			if err := b.run(ctx, "preparing "+dir, "mkdir -p "+shellQuote(dir), nil); err != nil {
				return err
			}
		}
	}
	if err := b.run(ctx, "put "+remotePath, "cat > "+shellQuote(remotePath), bytes.NewReader(data)); err != nil {
		return err
	}
	if opts.Executable {
		return b.run(ctx, "chmod +x "+remotePath, "chmod +x "+shellQuote(remotePath), nil)
	}
	return nil
}

// Fetch reads remotePath as the become user, so a root-only file
// (/etc/shadow, a munge key) can be fetched or slurped.
func (b *becomeConnection) Fetch(ctx context.Context, remotePath, localPath string) error {
	res, err := b.Exec(ctx, "cat "+shellQuote(remotePath), nil)
	if err != nil {
		return fmt.Errorf("transport: fetch %s: %w", remotePath, err)
	}
	if res.RC != 0 {
		return fmt.Errorf("transport: fetch %s: exit %d: %s", remotePath, res.RC, res.Stderr)
	}
	return os.WriteFile(localPath, []byte(res.Stdout), 0o644)
}

// Remove deletes remotePath as the become user.
func (b *becomeConnection) Remove(ctx context.Context, remotePath string) error {
	return b.run(ctx, "remove "+remotePath, "rm -f "+shellQuote(remotePath), nil)
}

// run is Exec for a command whose only useful outcome is success.
func (b *becomeConnection) run(ctx context.Context, what, cmd string, stdin io.Reader) error {
	res, err := b.Exec(ctx, cmd, stdin)
	if err != nil {
		return fmt.Errorf("transport: %s: %w", what, err)
	}
	if res.RC != 0 {
		return fmt.Errorf("transport: %s: exit %d: %s", what, res.RC, res.Stderr)
	}
	return nil
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
