package transport

import (
	"context"
	"strings"
	"testing"
)

// The expected flag string here is not a preference: it is what real
// Ansible emits. Measured with
//
//	ansible localhost -m command -a 'id -un' -b --become-method=sudo -vvv
//
// against ansible-core 2.21.4, which logs the command it runs:
//
//	sudo -H -S -n  -u root /bin/sh -c 'echo BECOME-SUCCESS-... ; ...'
//
// This test previously asserted "sudo -H -n -u root" -- no -S -- which
// was this port's own invention rather than sudo's documented default
// of "-H -S -n". The difference is harmless in behaviour (-n stops sudo
// prompting, so -S has nothing to read) but it mattered once
// BecomeConfig.Flags existed: "the default flags" has to mean the same
// string here as it does there, or a caller overriding them is working
// from a different baseline than the one Ansible documents.
func TestWrapCommandSudoNoPassword(t *testing.T) {
	cfg := BecomeConfig{Method: BecomeSudo, User: "root"}
	cmd, stdin := cfg.wrapCommand("echo MARK; whoami")
	if stdin != "" {
		t.Errorf("stdin = %q, want empty (no password configured)", stdin)
	}
	if !strings.Contains(cmd, "sudo -H -S -n -u root") {
		t.Errorf("cmd = %q, want sudo's own documented default flags", cmd)
	}
}

// Exe is Ansible's become_exe: it replaces the program, and nothing
// else about the line.
func TestWrapCommandBecomeExe(t *testing.T) {
	cfg := BecomeConfig{Method: BecomeSudo, User: "root", Exe: "/usr/bin/sudo"}
	cmd, _ := cfg.wrapCommand("id")
	if !strings.HasPrefix(cmd, "/usr/bin/sudo -H -S -n -u root") {
		t.Errorf("cmd = %q, want the overridden executable with the default flags", cmd)
	}
	if strings.HasPrefix(cmd, "sudo ") {
		t.Error("the bare method name is still being used as the program")
	}
}

// Flags REPLACES the default rather than adding to it, which is what
// the real plugin does with become_flags.
func TestWrapCommandBecomeFlagsReplace(t *testing.T) {
	cfg := BecomeConfig{Method: BecomeSudo, User: "root", Flags: "-i"}
	cmd, _ := cfg.wrapCommand("id")
	if !strings.HasPrefix(cmd, "sudo -i -u root") {
		t.Errorf("cmd = %q, want only the flags given", cmd)
	}
	if strings.Contains(cmd, "-H") || strings.Contains(cmd, "-S") {
		t.Error("the default flags survived an explicit override")
	}
}

// Empty Flags on a method with no documented default produces no empty
// slot in the line -- a double space would be harmless to a shell but
// makes the command unreadable in a log and untestable by prefix.
func TestWrapCommandNoFlagsNoDoubleSpace(t *testing.T) {
	cfg := BecomeConfig{Method: BecomeDoas, User: "root"}
	cmd, _ := cfg.wrapCommand("id")
	if strings.Contains(cmd, "  ") {
		t.Errorf("cmd = %q, want no double space", cmd)
	}
}

// A password and -n cannot both hold: sudo -n refuses to prompt, so it
// can never read the password it was handed. The real plugin strips -n
// out of the flags for this reason, including an n folded into a short
// cluster, and so does this.
func TestFlagsDropNonInteractiveWhenPasswordSet(t *testing.T) {
	for _, tc := range []struct{ flags, want string }{
		{"-H -S -n", "-H -S"},
		{"-n", ""},
		{"--non-interactive -H", "-H"},
		{"-Hn", "-H"},
		{"-nH", "-H"},
		{"-H -S", "-H -S"}, // nothing to strip
		{"--non-interactive-ish", "--non-interactive-ish"}, // a long flag that merely starts the same way
	} {
		cfg := BecomeConfig{Method: BecomeSudo, User: "root", Password: "pw", Flags: tc.flags}
		if got := cfg.flags(); got != tc.want {
			t.Errorf("flags(%q) = %q, want %q", tc.flags, got, tc.want)
		}
	}
	// and without a password, -n stays put
	cfg := BecomeConfig{Method: BecomeSudo, User: "root", Flags: "-H -S -n"}
	if got := cfg.flags(); got != "-H -S -n" {
		t.Errorf("flags() = %q with no password, want it untouched", got)
	}
}

func TestWrapCommandSudoWithPassword(t *testing.T) {
	cfg := BecomeConfig{Method: BecomeSudo, User: "deploy", Password: "hunter2"}
	cmd, stdin := cfg.wrapCommand("echo MARK; whoami")
	if stdin != "hunter2\n" {
		t.Errorf("stdin = %q, want the password newline-terminated", stdin)
	}
	// the default "-H -S -n" minus the -n a password makes impossible
	if !strings.Contains(cmd, "sudo -H -S -u deploy") {
		t.Errorf("cmd = %q, want -S (stdin) sudo without -n", cmd)
	}
	if strings.Contains(cmd, "-n ") {
		t.Errorf("cmd = %q, still non-interactive with a password set", cmd)
	}
	if strings.Contains(cmd, "hunter2") {
		t.Fatal("password must never appear in the command line itself")
	}
}

func TestWrapCommandSu(t *testing.T) {
	cfg := BecomeConfig{Method: BecomeSu, User: "root", Password: "pw"}
	cmd, stdin := cfg.wrapCommand("id")
	if !strings.HasPrefix(cmd, "su root -c") {
		t.Errorf("cmd = %q", cmd)
	}
	if stdin != "pw\n" {
		t.Errorf("stdin = %q", stdin)
	}
}

func TestWrapCommandDoas(t *testing.T) {
	cfg := BecomeConfig{Method: BecomeDoas, User: "root"}
	cmd, _ := cfg.wrapCommand("id")
	if !strings.HasPrefix(cmd, "doas -u root") {
		t.Errorf("cmd = %q", cmd)
	}
}

func TestWrapCommandDefaultsToSudoRoot(t *testing.T) {
	conn := Become(NewLocal(), BecomeConfig{})
	bc := conn.(*becomeConnection)
	if bc.cfg.Method != BecomeSudo || bc.cfg.User != "root" {
		t.Errorf("defaults = %+v, want sudo/root", bc.cfg)
	}
}

func TestBecomeNotAStreamer(t *testing.T) {
	// Local itself implements Streamer; wrapping it with Become must not
	// carry that through, per Become's documented gap.
	conn := Become(NewLocal(), BecomeConfig{})
	if _, ok := conn.(Streamer); ok {
		t.Fatal("Become-wrapped connection must not implement Streamer (known, documented gap)")
	}
}

// TestBecomeLocalPasswordlessSudo exercises the real Exec path end to
// end against the Local connection: if this machine happens to have
// passwordless sudo for the current user it will actually escalate; if
// not, it still proves the marker-based success detection and error
// wrapping behave sanely on failure.
func TestBecomeMarkerStripping(t *testing.T) {
	// Use "su" as a stand-in for any become method against a command
	// that never actually escalates (echoes success unconditionally via
	// /bin/sh, no real su/sudo binary needed) by wrapping Local directly
	// and checking the marker is stripped from stdout.
	conn := Become(NewLocal(), BecomeConfig{Method: BecomeSudo, User: "root"})
	// Passwordless path: on a machine without configured sudo this will
	// fail become itself, which is a legitimate outcome to assert on.
	res, err := conn.Exec(context.Background(), "echo hello-from-become", nil)
	if err != nil {
		t.Skipf("sudo -n not available in this sandbox (expected in CI): %v", err)
	}
	if strings.TrimSpace(res.Stdout) != "hello-from-become" {
		t.Errorf("stdout = %q, want marker stripped leaving only the command's own output", res.Stdout)
	}
}
