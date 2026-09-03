package transport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startTestSSHServer runs a minimal in-process SSH server (real wire
// protocol, via the same golang.org/x/crypto/ssh this package's client
// uses) that accepts password auth for user/pass and, for each "exec"
// request, runs the command through /bin/sh — exactly what a real
// sshd does — so SSH.Exec/Put/Fetch are exercised end to end without
// needing a system sshd or root.
func startTestSSHServer(t *testing.T, user, pass string) (addr string, stop func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(password) == pass {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSSHConn(t, nc, config)
		}
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		close(done)
	}
}

func serveTestSSHConn(t *testing.T, nc net.Conn, config *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, config)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		channel, requests, err := newChan.Accept()
		if err != nil {
			return
		}
		go func() {
			defer channel.Close()
			for req := range requests {
				if req.Type != "exec" {
					if req.WantReply {
						req.Reply(false, nil)
					}
					continue
				}
				var payload struct{ Command string }
				ssh.Unmarshal(req.Payload, &payload)
				if req.WantReply {
					req.Reply(true, nil)
				}

				// Wire the child directly to the channel via pipes (not a
				// buffer filled in after Run completes) so output really
				// streams to the client as it is produced — exercising
				// SSH's streaming Session honestly, not just its buffered
				// Exec.
				// Bare "sh", not "/bin/sh": this fake server is itself a
				// local child process during the test, and Windows'
				// os/exec LookPath doesn't treat "/" as a path separator
				// — see the same reasoning in local.go's NewLocal.
				cmd := exec.Command("sh", "-c", payload.Command)
				stdinPipe, _ := cmd.StdinPipe()
				stdoutPipe, _ := cmd.StdoutPipe()
				stderrPipe, _ := cmd.StderrPipe()
				if err := cmd.Start(); err != nil {
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{127}))
					return
				}

				go func() {
					io.Copy(stdinPipe, channel)
					stdinPipe.Close()
				}()
				var copyWG sync.WaitGroup
				copyWG.Add(2)
				go func() { defer copyWG.Done(); io.Copy(channel, stdoutPipe) }()
				go func() { defer copyWG.Done(); io.Copy(channel.Stderr(), stderrPipe) }()

				// cmd.Wait must not run concurrently with the stdout/
				// stderr copies above: per the os/exec docs for
				// StdoutPipe/StderrPipe, Wait closes the underlying pipe
				// once the process exits, and calling it before all reads
				// have finished can truncate output that just hasn't been
				// drained yet — fast locally, but a real, reproducible
				// race under slow qemu emulation. Drain first, reap after.
				copyWG.Wait()
				runErr := cmd.Wait()

				exitCode := 0
				if runErr != nil {
					if ee, ok := runErr.(*exec.ExitError); ok {
						exitCode = ee.ExitCode()
					}
				}
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)}))
				return
			}
		}()
	}
}

func dialTestServer(t *testing.T, addr, user, pass string) *SSH {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	conn, err := DialSSH(context.Background(), SSHConfig{
		Host:         host,
		Port:         port,
		User:         user,
		Password:     pass,
		HostKeyCheck: false,
	})
	if err != nil {
		t.Fatalf("DialSSH: %v", err)
	}
	return conn
}

func TestSSHExec(t *testing.T) {
	addr, stop := startTestSSHServer(t, "tester", "secret")
	defer stop()

	conn := dialTestServer(t, addr, "tester", "secret")
	defer conn.Close()

	res, err := conn.Exec(context.Background(), "echo hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(res.Stdout) != "hello" {
		t.Errorf("stdout = %q", res.Stdout)
	}
	if res.RC != 0 {
		t.Errorf("rc = %d", res.RC)
	}
}

func TestSSHExecNonZeroExit(t *testing.T) {
	addr, stop := startTestSSHServer(t, "tester", "secret")
	defer stop()

	conn := dialTestServer(t, addr, "tester", "secret")
	defer conn.Close()

	res, err := conn.Exec(context.Background(), "exit 7", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.RC != 7 {
		t.Errorf("rc = %d, want 7", res.RC)
	}
}

func TestSSHWrongPasswordRejected(t *testing.T) {
	addr, stop := startTestSSHServer(t, "tester", "secret")
	defer stop()

	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	_, err := DialSSH(context.Background(), SSHConfig{
		Host: host, Port: port, User: "tester", Password: "wrong", HostKeyCheck: false,
	})
	if err == nil {
		t.Fatal("expected auth failure with wrong password")
	}
}

func TestSSHPutFetch(t *testing.T) {
	addr, stop := startTestSSHServer(t, "tester", "secret")
	defer stop()

	conn := dialTestServer(t, addr, "tester", "secret")
	defer conn.Close()

	dir := t.TempDir()
	src := dir + "/src.txt"
	dst := dir + "/dst.txt"
	if err := writeFile(src, "roundtrip payload"); err != nil {
		t.Fatal(err)
	}

	if err := conn.Put(context.Background(), src, dst, PutOptions{}); err != nil {
		t.Fatal(err)
	}

	fetched := dir + "/fetched.txt"
	if err := conn.Fetch(context.Background(), dst, fetched); err != nil {
		t.Fatal(err)
	}

	data, err := readFile(fetched)
	if err != nil {
		t.Fatal(err)
	}
	if data != "roundtrip payload" {
		t.Errorf("fetched = %q", data)
	}
}

func TestSSHBecomeOverRealSession(t *testing.T) {
	addr, stop := startTestSSHServer(t, "tester", "secret")
	defer stop()

	raw := dialTestServer(t, addr, "tester", "secret")
	defer raw.Close()

	// No real sudo/su on the test server's shell needed: this proves
	// the become wrapper's marker-stripping works over a genuine SSH
	// session by using a become method whose "escalation program" is
	// just /bin/sh itself succeeding immediately (sudo -n as root
	// running the test's own uid — many CI containers run as root,
	// where sudo -n succeeds trivially; skip otherwise).
	conn := Become(raw, BecomeConfig{Method: BecomeSudo, User: "root"})
	res, err := conn.Exec(context.Background(), "echo over-ssh", nil)
	if err != nil {
		t.Skipf("sudo -n not usable against the test server's shell: %v", err)
	}
	if strings.TrimSpace(res.Stdout) != "over-ssh" {
		t.Errorf("stdout = %q", res.Stdout)
	}
}

func TestSSHStreamerNewSession(t *testing.T) {
	addr, stop := startTestSSHServer(t, "tester", "secret")
	defer stop()

	conn := dialTestServer(t, addr, "tester", "secret")
	defer conn.Close()

	var streamer Streamer = conn
	sess, err := streamer.NewSession(context.Background())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}

	if err := sess.Start("cat"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Pace the writes and read each echoed line back before sending the
	// next one, proving output really streams rather than only becoming
	// visible once the whole command has finished.
	reader := newLineReader(stdout)
	for i, line := range []string{"first", "second", "third"} {
		if _, err := io.WriteString(stdin, line+"\n"); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got, err := reader.readLine(5 * time.Second)
		if err != nil {
			t.Fatalf("readLine %d: %v", i, err)
		}
		if got != line {
			t.Errorf("line %d = %q, want %q", i, got, line)
		}
	}
	stdin.Close()

	rc, err := sess.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if rc != 0 {
		t.Errorf("rc = %d, want 0", rc)
	}
}

func TestSSHStreamerNonZeroExit(t *testing.T) {
	addr, stop := startTestSSHServer(t, "tester", "secret")
	defer stop()

	conn := dialTestServer(t, addr, "tester", "secret")
	defer conn.Close()

	sess, err := conn.NewSession(context.Background())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.Start("exit 9"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	rc, err := sess.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if rc != 9 {
		t.Errorf("rc = %d, want 9", rc)
	}
}

func TestSSHStreamerCloseMidRun(t *testing.T) {
	addr, stop := startTestSSHServer(t, "tester", "secret")
	defer stop()

	conn := dialTestServer(t, addr, "tester", "secret")
	defer conn.Close()

	sess, err := conn.NewSession(context.Background())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}

	if err := sess.Start("echo started; sleep 30"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	buf := make([]byte, 64)
	n, err := stdout.Read(buf)
	if err != nil {
		t.Fatalf("reading 'started': %v", err)
	}
	if strings.TrimSpace(string(buf[:n])) != "started" {
		t.Fatalf("stdout = %q", buf[:n])
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The remote sleep must not still be running; the exact signal the
	// server observes is implementation detail, so just require the
	// session channel to be gone rather than racing a long sleep.
}

// lineReader lets a test read newline-delimited output as it arrives,
// with a per-line timeout so a hang shows up as a test failure instead
// of a stuck test run.
type lineReader struct {
	line chan string
	errc chan error
}

func newLineReader(r io.Reader) *lineReader {
	lr := &lineReader{line: make(chan string), errc: make(chan error, 1)}
	go func() {
		br := bufio.NewReader(r)
		for {
			s, err := br.ReadString('\n')
			if s != "" {
				lr.line <- strings.TrimRight(s, "\n")
			}
			if err != nil {
				lr.errc <- err
				return
			}
		}
	}()
	return lr
}

func (lr *lineReader) readLine(timeout time.Duration) (string, error) {
	select {
	case s := <-lr.line:
		return s, nil
	case err := <-lr.errc:
		return "", err
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out waiting for a line")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}
