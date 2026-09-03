package transport

import (
	"context"
	"io"
)

// Session is a live, streaming command execution — the interactive
// counterpart to Connection.Exec's single buffered call. Where Exec hands
// back one Result after the command has already finished, a Session lets
// the caller drive its stdin/stdout/stderr directly as plain pipes while
// the command runs: an interactive multi-host shell needs to forward
// keystrokes to a remote process and show its output as it is produced,
// not after the fact. Nothing is buffered by the library — the caller
// owns pacing and framing.
//
// The usual sequence is: request the pipes you need, Start the command,
// pump stdin/stdout/stderr concurrently, then Wait for the exit code.
// Close releases the session's resources at any point, terminating the
// remote process if Wait has not yet returned.
type Session interface {
	// StdinPipe returns a writer for the session's standard input. Call
	// before Start.
	StdinPipe() (io.WriteCloser, error)
	// StdoutPipe returns a reader streaming standard output as it is
	// produced. Call before Start.
	StdoutPipe() (io.Reader, error)
	// StderrPipe returns a reader streaming standard error as it is
	// produced. Call before Start.
	StderrPipe() (io.Reader, error)
	// Start begins running cmd. Non-blocking.
	Start(cmd string) error
	// Wait blocks until the command exits and returns its exit code. A
	// non-zero exit is not itself an error; err is only for a failure to
	// wait on the command at all.
	Wait() (int, error)
	// Close releases the session's resources, terminating the remote
	// process if Wait has not yet returned. Safe to call after Wait, and
	// safe to call more than once.
	Close() error
}

// Streamer is implemented by a Connection that can also open a live
// Session for callers needing real-time interactivity instead of Exec's
// buffered result. Local and SSH implement it.
//
// WinRM does not: WS-Management's Command/Send/Receive shell protocol is
// poll-based (Receive returns whatever output has accumulated since the
// last poll, not a continuous stream), so it does not map onto the
// continuous-pipe shape Session assumes without either fabricating fake
// liveness or accepting periodic stalls that would silently degrade what
// "streaming" promises. Left unimplemented rather than shipped half-true.
//
// Become-wrapped connections also do not implement Streamer, for a
// narrower reason: see Become's doc comment.
//
// Callers should type-assert (conn.(transport.Streamer)) and handle
// absence explicitly, not assume every Connection supports it.
type Streamer interface {
	NewSession(ctx context.Context) (Session, error)
}
