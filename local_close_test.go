package transport

import (
	"context"
	"io"
	"testing"
	"time"
)

// Close must unblock a reader that is parked on StdoutPipe, including
// when the write end is held by something killing the command does not
// reach. `sleep 30 & wait` forks, so the grandchild survives the kill
// and keeps the pipe open; a reader waiting for EOF waits forever.
//
// This is the contract Session.Close documents, and it is here because
// a consumer got it wrong from a doc comment that said the opposite:
// configuration-management-tool joined its drainer goroutines before
// calling Close and deadlocked on four of five CI platforms.
func TestSessionCloseUnblocksAReaderAGrandchildIsHolding(t *testing.T) {
	l := NewLocal()
	sess, err := l.NewSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("sleep 30 & wait"); err != nil {
		t.Fatal(err)
	}

	read := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, stdout) // parks until EOF
		close(read)
	}()

	// Nothing should have ended it yet.
	select {
	case <-read:
		t.Fatal("the reader returned before anything closed the session")
	case <-time.After(150 * time.Millisecond):
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-read:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock the reader: the grandchild still holds the write end")
	}
}

// And the other half of the contract: a command that exits on its own
// leaves its output readable, so draining before Close loses nothing.
func TestSessionOutputReadableAfterWait(t *testing.T) {
	l := NewLocal()
	sess, err := l.NewSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("echo marker"); err != nil {
		t.Fatal(err)
	}
	if rc, err := sess.Wait(); err != nil || rc != 0 {
		t.Fatalf("Wait = %d, %v", rc, err)
	}
	// read AFTER the reap, deliberately
	b, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatalf("ReadAll after Wait: %v", err)
	}
	if string(b) != "marker\n" {
		t.Errorf("stdout = %q, want %q", b, "marker\n")
	}
	_ = sess.Close()
}
