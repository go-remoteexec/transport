package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// startTestBastion runs an in-process SSH server that forwards
// direct-tcpip channels -- what a jump host does, and what
// ssh.Client.DialContext asks for. It counts the forwards so a test can
// prove the traffic really went THROUGH it.
func startTestBastion(t *testing.T, user, pass string) (addr string, forwards *atomic.Int64, stop func()) {
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
	counted := &atomic.Int64{}

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveBastionConn(nc, config, counted)
		}
	}()
	return ln.Addr().String(), counted, func() { ln.Close() }
}

func serveBastionConn(nc net.Conn, config *ssh.ServerConfig, forwards *atomic.Int64) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, config)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			newChan.Reject(ssh.UnknownChannelType, "this bastion only forwards")
			continue
		}
		var payload struct {
			DestAddr string
			DestPort uint32
			OrigAddr string
			OrigPort uint32
		}
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
			newChan.Reject(ssh.ConnectionFailed, "bad payload")
			continue
		}
		target, err := net.Dial("tcp", net.JoinHostPort(payload.DestAddr, strconv.Itoa(int(payload.DestPort))))
		if err != nil {
			newChan.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			target.Close()
			continue
		}
		forwards.Add(1)
		go ssh.DiscardRequests(chReqs)
		go func() {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(ch, target) }()
			go func() { defer wg.Done(); io.Copy(target, ch) }()
			wg.Wait()
			ch.Close()
			target.Close()
		}()
	}
}

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

// A command really runs on the target, reached through the bastion, and
// the bastion really carried it. Without the forward count this test
// would pass just as well if ProxyJump were ignored and the target
// dialled directly -- which is exactly the bug worth catching.
func TestProxyJumpReachesTheTargetThroughTheBastion(t *testing.T) {
	targetAddr, stopTarget := startTestSSHServer(t, "tuser", "tpass")
	defer stopTarget()
	bastionAddr, forwards, stopBastion := startTestBastion(t, "tuser", "tpass")
	defer stopBastion()

	host, port := hostPort(t, targetAddr)
	conn, err := DialSSH(context.Background(), SSHConfig{
		Host:         host,
		Port:         port,
		User:         "tuser",
		Password:     "tpass",
		HostKeyCheck: false,
		ProxyJump:    []SSHConfig{jumpTo(t, bastionAddr)},
	})
	if err != nil {
		t.Fatalf("DialSSH through %s: %v", bastionAddr, err)
	}
	defer conn.Close()

	res, err := conn.Exec(context.Background(), "echo through-the-bastion", nil)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if got := string(res.Stdout); got != "through-the-bastion\n" {
		t.Errorf("stdout = %q, want %q", got, "through-the-bastion\n")
	}
	if n := forwards.Load(); n != 1 {
		t.Errorf("the bastion forwarded %d connection(s), want exactly 1 — "+
			"the target may have been dialled directly", n)
	}
}

// CONTROL: the same target, dialled with no ProxyJump, must NOT touch
// the bastion. If this counted a forward, the assertion above would be
// measuring something else.
func TestWithoutProxyJumpTheBastionIsUnused(t *testing.T) {
	targetAddr, stopTarget := startTestSSHServer(t, "tuser", "tpass")
	defer stopTarget()
	_, forwards, stopBastion := startTestBastion(t, "tuser", "tpass")
	defer stopBastion()

	conn := dialTestServer(t, targetAddr, "tuser", "tpass")
	defer conn.Close()
	if _, err := conn.Exec(context.Background(), "echo direct", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if n := forwards.Load(); n != 0 {
		t.Errorf("the bastion forwarded %d connection(s) for a direct dial, want 0", n)
	}
}

// Two hops, so "the chain is walked" is asserted rather than assumed: a
// one-hop implementation that ignored the rest would pass the test
// above.
func TestProxyJumpWalksAChainOfTwo(t *testing.T) {
	targetAddr, stopTarget := startTestSSHServer(t, "tuser", "tpass")
	defer stopTarget()
	firstAddr, firstFwd, stopFirst := startTestBastion(t, "tuser", "tpass")
	defer stopFirst()
	secondAddr, secondFwd, stopSecond := startTestBastion(t, "tuser", "tpass")
	defer stopSecond()

	host, port := hostPort(t, targetAddr)
	conn, err := DialSSH(context.Background(), SSHConfig{
		Host:         host,
		Port:         port,
		User:         "tuser",
		Password:     "tpass",
		HostKeyCheck: false,
		ProxyJump:    []SSHConfig{jumpTo(t, firstAddr), jumpTo(t, secondAddr)},
	})
	if err != nil {
		t.Fatalf("DialSSH through %s,%s: %v", firstAddr, secondAddr, err)
	}
	defer conn.Close()

	if _, err := conn.Exec(context.Background(), "echo hi", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	// The first carries the second's SSH connection; the second carries
	// the target's. One forward each, and the order is what proves the
	// chain was walked left to right.
	if n := firstFwd.Load(); n != 1 {
		t.Errorf("first hop forwarded %d, want 1", n)
	}
	if n := secondFwd.Load(); n != 1 {
		t.Errorf("second hop forwarded %d, want 1", n)
	}
}

// An unreachable bastion must fail as a ProxyJump failure, naming the
// hop, rather than as a plain dial error against the target.
func TestProxyJumpReportsAnUnreachableBastion(t *testing.T) {
	targetAddr, stopTarget := startTestSSHServer(t, "tuser", "tpass")
	defer stopTarget()
	host, port := hostPort(t, targetAddr)

	_, err := DialSSH(context.Background(), SSHConfig{
		Host:         host,
		Port:         port,
		User:         "tuser",
		Password:     "tpass",
		HostKeyCheck: false,
		ProxyJump:    []SSHConfig{{Host: "127.0.0.1", Port: 1}}, // nothing listens on port 1
	})
	if err == nil {
		t.Fatal("dialling through an unreachable bastion succeeded")
	}
	if !strings.Contains(err.Error(), "ProxyJump") || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error %q names neither ProxyJump nor the hop", err)
	}
}

// jumpTo is a hop naming nothing but where it is: everything else --
// user, credentials, host-key policy -- is inherited from the target,
// which is the contract go-ansible/playbook relies on when it parses a
// bare `-o ProxyJump=bastion`.
func jumpTo(t *testing.T, addr string) SSHConfig {
	t.Helper()
	host, port := hostPort(t, addr)
	return SSHConfig{Host: host, Port: port}
}

// The inheritance itself, asserted rather than only exercised: a hop
// that names no credential must end up with the target's, and one that
// names its own must keep it.
func TestAHopInheritsWhatItDoesNotName(t *testing.T) {
	target := SSHConfig{
		User: "tuser", Password: "tpass",
		PrivateKeyFile: "/key", PrivateKeyPassphrase: "phrase",
		UseAgent: true, HostKeyCheck: true, KnownHostsFile: "/kh",
		Timeout: 7, TempDir: "/target-tmp", TTY: true,
		ProxyJump: []SSHConfig{{Host: "somewhere"}},
	}

	t.Run("a bare hop takes the target's credentials", func(t *testing.T) {
		got := inheritJumpCredentials(SSHConfig{Host: "bastion"}, target)
		for _, c := range []struct{ name, got, want string }{
			{"User", got.User, "tuser"},
			{"Password", got.Password, "tpass"},
			{"PrivateKeyFile", got.PrivateKeyFile, "/key"},
			{"KnownHostsFile", got.KnownHostsFile, "/kh"},
		} {
			if c.got != c.want {
				t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
			}
		}
		if got.Port != 22 {
			t.Errorf("Port = %d, want 22", got.Port)
		}
		if !got.HostKeyCheck {
			t.Error("HostKeyCheck was downgraded for the hop")
		}
		if got.Timeout != 7 {
			t.Errorf("Timeout = %v, want the target's 7", got.Timeout)
		}
	})

	t.Run("a hop's own key is kept, and the target's is not added", func(t *testing.T) {
		got := inheritJumpCredentials(SSHConfig{Host: "b", User: "jump", PrivateKeyFile: "/own"}, target)
		if got.User != "jump" {
			t.Errorf("User = %q, want the hop's own", got.User)
		}
		if got.PrivateKeyFile != "/own" {
			t.Errorf("PrivateKeyFile = %q, want /own", got.PrivateKeyFile)
		}
		if got.Password != "" || got.UseAgent {
			t.Errorf("the target's credentials leaked onto a hop that named its own: password=%q useAgent=%v",
				got.Password, got.UseAgent)
		}
	})

	t.Run("a hop is a tunnel, not a place commands run", func(t *testing.T) {
		got := inheritJumpCredentials(SSHConfig{Host: "b"}, target)
		if got.ProxyJump != nil {
			t.Error("a hop inherited the target's ProxyJump, which would recurse")
		}
		if got.TempDir != "" || got.TTY {
			t.Errorf("a hop inherited TempDir=%q TTY=%v", got.TempDir, got.TTY)
		}
	})
}
