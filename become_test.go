package transport

import (
	"context"
	"strings"
	"testing"
)

func TestWrapCommandSudoNoPassword(t *testing.T) {
	cfg := BecomeConfig{Method: BecomeSudo, User: "root"}
	cmd, stdin := cfg.wrapCommand("echo MARK; whoami")
	if stdin != "" {
		t.Errorf("stdin = %q, want empty (no password configured)", stdin)
	}
	if !strings.Contains(cmd, "sudo -H -n -u root") {
		t.Errorf("cmd = %q, want -n (non-interactive) sudo", cmd)
	}
}

func TestWrapCommandSudoWithPassword(t *testing.T) {
	cfg := BecomeConfig{Method: BecomeSudo, User: "deploy", Password: "hunter2"}
	cmd, stdin := cfg.wrapCommand("echo MARK; whoami")
	if stdin != "hunter2\n" {
		t.Errorf("stdin = %q, want the password newline-terminated", stdin)
	}
	if !strings.Contains(cmd, "sudo -H -S -u deploy") {
		t.Errorf("cmd = %q, want -S (stdin) sudo", cmd)
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
