package transport

import (
	"context"
	"io"
)

// EnvExecer is implemented by a Connection that can put environment
// variables on the command's OWN PROCESS rather than on the command
// LINE.
//
// ⛔ SECURITY, and the reason this exists. A caller that needs to hand
// a credential to a third-party CLI has two shapes available:
//
//	TOKEN=secret some-cli ...        // a shell prefix
//	ExecEnv(ctx, "some-cli ...", map[string]string{"TOKEN": "secret"}, nil)
//
// They are not equivalent, but the difference is NARROWER than it first
// looks and the measurement is worth recording precisely.
//
// Exec runs its command as `sh -c "<cmd>"`. For a SINGLE command the
// shell execs straight into it, so nothing keeps that argv and the
// prefix is not visible anywhere -- measured: `sh -c "VAR=x sleep 4"`
// leaves only `sleep 4` in the process table. Add a second statement
// and the shell must stay, and then its argv carries the credential for
// the command's whole lifetime, for every local user to read:
//
//	/bin/sh -c MY_TOKEN=canary-fc8d34e8eadc sleep 4; true
//
// So the exposure is real and demonstrated, and it applies to commands
// that are not a lone exec -- a pipeline, an `&&`, or an assignment
// followed by `;`, which is the shape that actually bit in
// go-ansible/modules' keyring.go (two passwords, one live shell).
//
// A first version of this comment claimed the single-command form was
// exposed too. It is not; that reading came from a contaminated probe
// whose own heredoc contained the canary.
//
// Connection.Exec's own doc already states this principle for the
// become password, which goes through stdin "without ever appearing in
// argv or an environment variable". ExecEnv is the same principle for
// everything else.
//
// WHAT IT CANNOT FIX, stated because the limit is real: over SSH the
// environment is set with the protocol's own env request, which sshd
// refuses by default for anything outside its AcceptEnv list (usually
// just LANG and LC_*). A caller that must work against an unmodified
// sshd still needs the prefix, or stdin, or a mode-0600 file. Real
// Ansible has the same constraint and resolves it the same way for its
// own `environment:` keyword. This is therefore a fix for LOCAL
// connections and for SSH servers configured to accept it, not a
// universal one -- which is why it is an OPTIONAL interface a caller
// type-asserts for rather than a method on Connection.
type EnvExecer interface {
	ExecEnv(ctx context.Context, cmd string, env map[string]string, stdin io.Reader) (Result, error)
}

// ExecWithEnv runs cmd with env set on the process when conn can do
// that, and otherwise falls back to a shell prefix -- so a caller gets
// the safer behaviour wherever it is available without having to
// branch.
//
// The fallback is NOT silent in the sense that matters: it is the same
// exposure the caller would have had anyway, never a weaker one, and
// the ok return says which happened so a caller that must not leak can
// refuse instead.
func ExecWithEnv(ctx context.Context, conn Connection, cmd string, env map[string]string, stdin io.Reader) (res Result, onProcess bool, err error) {
	if ee, able := conn.(EnvExecer); able {
		r, e := ee.ExecEnv(ctx, cmd, env, stdin)
		return r, true, e
	}
	prefixed := cmd
	for _, k := range sortedKeys(env) {
		prefixed = k + "=" + shellQuote(env[k]) + " " + prefixed
	}
	r, e := conn.Exec(ctx, prefixed, stdin)
	return r, false, e
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// insertion sort: these maps hold a handful of entries and this
	// avoids pulling sort into a file that otherwise needs nothing.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
