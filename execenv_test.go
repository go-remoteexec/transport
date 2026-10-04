package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ⛔ SECURITY. The two shapes a caller has for handing a credential to a
// command are NOT equivalent:
//
//	TOKEN=secret cmd       -> the secret is in the SHELL's argv
//	ExecEnv(cmd, {TOKEN:…}) -> the secret is in the child's environment
//
// Exec runs `sh -c "<cmd>"`, so the first form is visible to `ps` for
// every other user on the machine. This test demonstrates both halves:
// the prefix IS visible, and ExecEnv is not. It is written as one test
// so the comparison cannot drift apart.
func TestExecEnvKeepsACredentialOutOfPs(t *testing.T) {
	// This asserts a POSIX property: that `sh -c "VAR=x cmd; more"`
	// leaves the assignment in a live shell's argv. `VAR=x cmd` is not
	// a thing under cmd.exe, so there is nothing to assert on Windows --
	// the skip is about the PREMISE, not a missing tool.
	//
	// Gating on exec.LookPath("ps") was tried first and was wrong:
	// GitHub's windows-latest carries a Git-for-Windows `ps` that
	// resolves fine and lists nothing this test can read, so the
	// instrument check passed and the control then failed. A skip reads
	// as a pass, so the condition has to be the one that is actually
	// true rather than the one that makes CI green.
	if runtime.GOOS == "windows" {
		t.Skip("the premise is a POSIX shell's argv; VAR=x cmd has no meaning here")
	}

	// ⚠ The canary is GENERATED HERE, never written as a literal in any
	// shell command. A first version used a fixed string and `ps` found
	// it -- in the shell that had created the test file, whose own
	// command line contained the heredoc. The instrument was the leak.
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	canary := "canary-" + hex.EncodeToString(buf)
	l := NewLocal()

	visible := func(cmd string, env map[string]string) bool {
		done := make(chan struct{})
		go func() {
			if env != nil {
				_, _ = l.ExecEnv(context.Background(), cmd, env, nil)
			} else {
				_, _ = l.Exec(context.Background(), cmd, nil)
			}
			close(done)
		}()
		defer func() { <-done }()
		for i := 0; i < 25; i++ {
			out, err := exec.Command("ps", "-Ao", "args").Output()
			if err == nil && strings.Contains(string(out), canary) {
				return true
			}
			time.Sleep(80 * time.Millisecond)
		}
		return false
	}

	// POSITIVE CONTROL, and it had to be chosen carefully. A prefix on a
	// SINGLE command is not visible at all: `sh -c "VAR=x sleep 3"`
	// execs straight into sleep, so no process keeps that argv. Add a
	// second statement and the shell must stay, and then its argv -- the
	// credential with it -- is in `ps` for every local user:
	//
	//	/bin/sh -c MY_TOKEN=canary-… sleep 4; true
	//
	// Measured both ways. Without this control the negative result below
	// would prove nothing, because an instrument that sees nothing
	// passes it for free.
	if !visible("MY_TOKEN="+canary+"; sleep 3; true", nil) {
		t.Fatal("positive control failed: ps did not show a credential this test KNOWS is on a " +
			"live shell's command line -- fix the instrument before trusting the result below")
	}

	if visible("sleep 3; true", map[string]string{"MY_TOKEN": canary}) {
		t.Error("ExecEnv put the credential where ps can see it; that is the one thing it exists to avoid")
	}
}

// The environment actually reaches the command -- a fix that hid the
// value by not passing it at all would pass the test above.
func TestExecEnvActuallySetsTheVariable(t *testing.T) {
	res, err := NewLocal().ExecEnv(context.Background(), "printf %s \"$PROBE_VAR\"",
		map[string]string{"PROBE_VAR": "reached"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "reached" {
		t.Errorf("stdout = %q, want the variable's value", res.Stdout)
	}
}

// ExecWithEnv uses the safer path when the connection offers it, and
// says which path it took so a caller that must not leak can refuse.
func TestExecWithEnvReportsWhichPathItTook(t *testing.T) {
	_, onProcess, err := ExecWithEnv(context.Background(), NewLocal(), "true",
		map[string]string{"A": "1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !onProcess {
		t.Error("Local implements EnvExecer, so ExecWithEnv should have used it")
	}
}
