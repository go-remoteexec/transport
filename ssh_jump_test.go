package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// jumpTestServer is an in-process sshd that can be a jump host as well
// as a target: besides "session" channels (served exactly like
// startTestSSHServer's) it accepts "direct-tcpip" -- the channel type
// `ssh -J` and ssh.Client.Dial open -- and forwards it to the requested
// host:port with a real TCP connection.
//
// It counts what is open RIGHT NOW, not what was ever opened, because
// the property under test is that nothing is left open: live is the
// number of authenticated SSH connections not yet torn down, and
// forwards the number of tunnels still carrying traffic.
type jumpTestServer struct {
	addr    string
	host    string
	port    int
	hostKey ssh.PublicKey

	live     atomic.Int32
	accepted atomic.Int32
	forwards atomic.Int32

	mu        sync.Mutex
	forwarded []string // every direct-tcpip destination, in order
}

type jumpTestServerOpts struct {
	refuseForward bool // reject every direct-tcpip channel
}

func startJumpTestServer(t *testing.T, user, pass string, opts jumpTestServerOpts) *jumpTestServer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
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
	s := &jumpTestServer{addr: ln.Addr().String(), hostKey: signer.PublicKey()}
	host, portStr, _ := net.SplitHostPort(s.addr)
	s.host = host
	s.port, _ = strconv.Atoi(portStr)

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, config, opts)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *jumpTestServer) serve(nc net.Conn, config *ssh.ServerConfig, opts jumpTestServerOpts) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, config)
	if err != nil {
		nc.Close()
		return
	}
	s.accepted.Add(1)
	s.live.Add(1)
	defer s.live.Add(-1)
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			channel, requests, err := newChan.Accept()
			if err != nil {
				return
			}
			go serveTestSession(channel, requests)
		case "direct-tcpip":
			if opts.refuseForward {
				newChan.Reject(ssh.Prohibited, "forwarding disabled")
				continue
			}
			var p struct {
				DestAddr   string
				DestPort   uint32
				OriginAddr string
				OriginPort uint32
			}
			if err := ssh.Unmarshal(newChan.ExtraData(), &p); err != nil {
				newChan.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			dest := net.JoinHostPort(p.DestAddr, strconv.Itoa(int(p.DestPort)))
			s.mu.Lock()
			s.forwarded = append(s.forwarded, dest)
			s.mu.Unlock()
			out, err := net.Dial("tcp", dest)
			if err != nil {
				newChan.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			channel, requests, err := newChan.Accept()
			if err != nil {
				out.Close()
				continue
			}
			go ssh.DiscardRequests(requests)
			s.forwards.Add(1)
			go func() {
				defer s.forwards.Add(-1)
				done := make(chan struct{}, 2)
				go func() { io.Copy(out, channel); done <- struct{}{} }()
				go func() { io.Copy(channel, out); done <- struct{}{} }()
				<-done
				// Either side ending ends the tunnel, both ways --
				// what sshd does, and what lets a closed client be
				// seen as closed by the server behind the tunnel.
				out.Close()
				channel.Close()
				<-done
			}()
		default:
			newChan.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func (s *jumpTestServer) forwardedTo() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.forwarded...)
}

// hop returns the SSHConfig naming s as a jump host, with its own
// credentials.
func (s *jumpTestServer) hop(user, pass string) SSHConfig {
	return SSHConfig{Host: s.host, Port: s.port, User: user, Password: pass}
}

// waitIdle fails the test unless every SSH connection and every tunnel
// on each server is gone within a few seconds. Teardown is asynchronous
// on the server side -- the client's Close returns before the server's
// read loop notices the EOF -- so this polls rather than asserting once.
func waitIdle(t *testing.T, servers map[string]*jumpTestServer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var busy []string
		for name, s := range servers {
			if l, f := s.live.Load(), s.forwards.Load(); l != 0 || f != 0 {
				busy = append(busy, fmt.Sprintf("%s: %d live connection(s), %d open tunnel(s)", name, l, f))
			}
		}
		if len(busy) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still open after 5s -- leaked:\n  %s", strings.Join(busy, "\n  "))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writeKnownHosts(t *testing.T, entries map[string]ssh.PublicKey) string {
	t.Helper()
	var b strings.Builder
	for addr, key := range entries {
		b.WriteString(knownhosts.Line([]string{addr}, key) + "\n")
	}
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func execEcho(t *testing.T, conn *SSH, word string) {
	t.Helper()
	res, err := conn.Exec(context.Background(), "echo "+word, nil)
	if err != nil {
		t.Fatalf("Exec through the chain: %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != word || res.RC != 0 {
		t.Fatalf("Exec through the chain = %q rc=%d, want %q rc=0", got, res.RC, word)
	}
}

func TestSSHProxyJumpOneHop(t *testing.T) {
	bastion := startJumpTestServer(t, "jumper", "jump-pass", jumpTestServerOpts{})
	target := startJumpTestServer(t, "tester", "secret", jumpTestServerOpts{})

	conn, err := DialSSH(context.Background(), SSHConfig{
		Host: target.host, Port: target.port, User: "tester", Password: "secret",
		ProxyJump: []SSHConfig{bastion.hop("jumper", "jump-pass")},
	})
	if err != nil {
		t.Fatalf("DialSSH via one jump host: %v", err)
	}
	defer conn.Close()
	execEcho(t, conn, "through-one")

	// The target was reached FROM the bastion, not dialled from here:
	// the bastion forwarded exactly one tunnel, and it went to the target.
	if got := bastion.forwardedTo(); len(got) != 1 || got[0] != target.addr {
		t.Errorf("bastion forwarded to %v, want exactly [%s]", got, target.addr)
	}
}

// Two hops, the second one inheriting the target's credentials: it sets
// a User and no authentication at all, so it must authenticate with the
// target's password rather than with nothing.
func TestSSHProxyJumpTwoHops(t *testing.T) {
	outer := startJumpTestServer(t, "outer", "outer-pass", jumpTestServerOpts{})
	inner := startJumpTestServer(t, "tester", "secret", jumpTestServerOpts{})
	target := startJumpTestServer(t, "tester", "secret", jumpTestServerOpts{})

	conn, err := DialSSH(context.Background(), SSHConfig{
		Host: target.host, Port: target.port, User: "tester", Password: "secret",
		ProxyJump: []SSHConfig{
			outer.hop("outer", "outer-pass"),
			{Host: inner.host, Port: inner.port, User: "tester"},
		},
	})
	if err != nil {
		t.Fatalf("DialSSH via two jump hosts: %v", err)
	}
	defer conn.Close()
	execEcho(t, conn, "through-two")

	// Each hop carried the next one, in the order given: outer -> inner
	// -> target, never outer -> target.
	if got := outer.forwardedTo(); len(got) != 1 || got[0] != inner.addr {
		t.Errorf("outer forwarded to %v, want exactly [%s]", got, inner.addr)
	}
	if got := inner.forwardedTo(); len(got) != 1 || got[0] != target.addr {
		t.Errorf("inner forwarded to %v, want exactly [%s]", got, target.addr)
	}
}

// ⭐ THE TARGET IS CHECKED AGAINST THE TARGET'S NAME. Through a tunnel
// the TCP peer is the bastion, and the connection's RemoteAddr is a
// zero address -- so the only thing that can identify the target is the
// Host:Port it was asked for. Each half of this test fails if the
// lookup is done against anything else: the first because the right
// keys would not be found, the second because a wrong key would be.
func TestSSHProxyJumpChecksTheTargetKeyAgainstTheTargetAddress(t *testing.T) {
	bastion := startJumpTestServer(t, "jumper", "jump-pass", jumpTestServerOpts{})
	target := startJumpTestServer(t, "tester", "secret", jumpTestServerOpts{})

	dial := func(knownHosts string) (*SSH, error) {
		return DialSSH(context.Background(), SSHConfig{
			Host: target.host, Port: target.port, User: "tester", Password: "secret",
			HostKeyCheck: true, KnownHostsFile: knownHosts,
			ProxyJump: []SSHConfig{bastion.hop("jumper", "jump-pass")},
		})
	}

	good := writeKnownHosts(t, map[string]ssh.PublicKey{
		bastion.addr: bastion.hostKey,
		target.addr:  target.hostKey,
	})
	conn, err := dial(good)
	if err != nil {
		t.Fatalf("both keys known, each under its own address, yet: %v", err)
	}
	execEcho(t, conn, "verified")
	conn.Close()

	// The target's entry now holds the BASTION's key -- what a client
	// that verified the target against the carrying hop would accept.
	swapped := writeKnownHosts(t, map[string]ssh.PublicKey{
		bastion.addr: bastion.hostKey,
		target.addr:  bastion.hostKey,
	})
	if conn, err := dial(swapped); err == nil {
		conn.Close()
		t.Fatal("target presented a key that is not the one known for its address, and was accepted")
	} else if !strings.Contains(err.Error(), target.addr) || !strings.Contains(err.Error(), "key mismatch") {
		t.Errorf("error should be a key mismatch naming the target %s; got: %v", target.addr, err)
	}
	waitIdle(t, map[string]*jumpTestServer{"bastion": bastion, "target": target})
}

// A hop whose key does not match is refused before anything is sent
// through it. The hop's config does not mention HostKeyCheck at all:
// it is verified because the target's config asked for verification,
// and a hop can only be stricter than the target, never laxer.
func TestSSHProxyJumpRefusesABadJumpHostKey(t *testing.T) {
	bastion := startJumpTestServer(t, "jumper", "jump-pass", jumpTestServerOpts{})
	target := startJumpTestServer(t, "tester", "secret", jumpTestServerOpts{})

	knownHosts := writeKnownHosts(t, map[string]ssh.PublicKey{
		bastion.addr: target.hostKey, // wrong key for the bastion
		target.addr:  target.hostKey,
	})
	conn, err := DialSSH(context.Background(), SSHConfig{
		Host: target.host, Port: target.port, User: "tester", Password: "secret",
		HostKeyCheck: true, KnownHostsFile: knownHosts,
		ProxyJump: []SSHConfig{bastion.hop("jumper", "jump-pass")},
	})
	if err == nil {
		conn.Close()
		t.Fatal("a jump host with the wrong key was accepted")
	}
	if !strings.Contains(err.Error(), "jump host 1 ("+bastion.addr+")") || !strings.Contains(err.Error(), "key mismatch") {
		t.Errorf("error should be a key mismatch naming jump host 1 (%s); got: %v", bastion.addr, err)
	}
	if n := bastion.accepted.Load(); n != 0 {
		t.Errorf("bastion authenticated %d connection(s); the password must not be sent to an unverified host", n)
	}
	if n := target.accepted.Load(); n != 0 {
		t.Errorf("target saw %d connection(s) through an unverified jump host", n)
	}
}

// ⭐ NO HOP OUTLIVES A FAILED DIAL. The chain is built one hop at a time,
// so a failure at the target finds every hop already connected and
// authenticated. Each one must be closed, or every failed connection
// attempt leaves a session open on each bastion until the process
// exits.
func TestSSHProxyJumpClosesTheHopsWhenTheTargetFails(t *testing.T) {
	outer := startJumpTestServer(t, "outer", "outer-pass", jumpTestServerOpts{})
	inner := startJumpTestServer(t, "inner", "inner-pass", jumpTestServerOpts{})
	target := startJumpTestServer(t, "tester", "secret", jumpTestServerOpts{})

	conn, err := DialSSH(context.Background(), SSHConfig{
		Host: target.host, Port: target.port, User: "tester", Password: "wrong",
		ProxyJump: []SSHConfig{outer.hop("outer", "outer-pass"), inner.hop("inner", "inner-pass")},
	})
	if err == nil {
		conn.Close()
		t.Fatal("wrong target password was accepted")
	}
	if !strings.Contains(err.Error(), "ssh handshake with "+target.addr+" via jump host 2") {
		t.Errorf("error should name the target and the hop it was reached through; got: %v", err)
	}
	// Both hops really were up -- otherwise "nothing is open" below
	// would prove nothing.
	if outer.accepted.Load() != 1 || inner.accepted.Load() != 1 {
		t.Fatalf("hops accepted outer=%d inner=%d, want 1 each", outer.accepted.Load(), inner.accepted.Load())
	}
	waitIdle(t, map[string]*jumpTestServer{"outer": outer, "inner": inner, "target": target})
}

// The same, for a failure that is not a handshake: the hop refuses to
// open the tunnel at all.
func TestSSHProxyJumpClosesTheHopWhenItRefusesToForward(t *testing.T) {
	bastion := startJumpTestServer(t, "jumper", "jump-pass", jumpTestServerOpts{refuseForward: true})
	target := startJumpTestServer(t, "tester", "secret", jumpTestServerOpts{})

	conn, err := DialSSH(context.Background(), SSHConfig{
		Host: target.host, Port: target.port, User: "tester", Password: "secret",
		ProxyJump: []SSHConfig{bastion.hop("jumper", "jump-pass")},
	})
	if err == nil {
		conn.Close()
		t.Fatal("dial succeeded through a hop that refuses forwarding")
	}
	if !strings.Contains(err.Error(), "dialing "+target.addr+" via jump host 1") {
		t.Errorf("error should say the target could not be reached via jump host 1; got: %v", err)
	}
	waitIdle(t, map[string]*jumpTestServer{"bastion": bastion, "target": target})
}

func TestSSHProxyJumpCloseClosesEveryHop(t *testing.T) {
	outer := startJumpTestServer(t, "outer", "outer-pass", jumpTestServerOpts{})
	inner := startJumpTestServer(t, "inner", "inner-pass", jumpTestServerOpts{})
	target := startJumpTestServer(t, "tester", "secret", jumpTestServerOpts{})

	conn, err := DialSSH(context.Background(), SSHConfig{
		Host: target.host, Port: target.port, User: "tester", Password: "secret",
		ProxyJump: []SSHConfig{outer.hop("outer", "outer-pass"), inner.hop("inner", "inner-pass")},
	})
	if err != nil {
		t.Fatalf("DialSSH: %v", err)
	}
	execEcho(t, conn, "before-close")
	for name, s := range map[string]*jumpTestServer{"outer": outer, "inner": inner, "target": target} {
		if s.live.Load() != 1 {
			t.Fatalf("%s has %d live connection(s) before Close, want 1", name, s.live.Load())
		}
	}

	if err := conn.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	waitIdle(t, map[string]*jumpTestServer{"outer": outer, "inner": inner, "target": target})
}

// Dialer is the way out of this machine, so with ProxyJump it makes
// exactly one connection: to the first hop.
func TestSSHProxyJumpDialerReachesOnlyTheFirstHop(t *testing.T) {
	bastion := startJumpTestServer(t, "jumper", "jump-pass", jumpTestServerOpts{})
	target := startJumpTestServer(t, "tester", "secret", jumpTestServerOpts{})

	var mu sync.Mutex
	var dialled []string
	conn, err := DialSSH(context.Background(), SSHConfig{
		Host: target.host, Port: target.port, User: "tester", Password: "secret",
		ProxyJump: []SSHConfig{bastion.hop("jumper", "jump-pass")},
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialled = append(dialled, addr)
			mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatalf("DialSSH: %v", err)
	}
	defer conn.Close()
	execEcho(t, conn, "dialer")
	if len(dialled) != 1 || dialled[0] != bastion.addr {
		t.Errorf("Dialer was asked for %v, want exactly [%s]", dialled, bastion.addr)
	}
}

// Every misconfiguration is reported before the first packet: the
// Dialer here fails the test if it is ever called.
func TestSSHProxyJumpConfigErrorsNeverTouchTheNetwork(t *testing.T) {
	cases := []struct {
		name string
		hop  SSHConfig
		want string
	}{
		{"no host", SSHConfig{User: "u"}, "jump host 1 has no Host"},
		{"no user", SSHConfig{Host: "bastion"}, "jump host 1 (bastion:22) has no User"},
		{"own dialer", SSHConfig{Host: "bastion", User: "u", Dialer: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}, "sets Dialer"},
		{"nested", SSHConfig{Host: "bastion", Port: 2222, User: "u", ProxyJump: []SSHConfig{{Host: "x", User: "u"}}}, "jump host 1 (bastion:2222) sets its own ProxyJump"},
		{"unreadable key", SSHConfig{Host: "bastion", User: "u", PrivateKeyFile: filepath.Join(t.TempDir(), "absent")}, "reading private key"},
		{"unreadable known_hosts", SSHConfig{Host: "bastion", User: "u", HostKeyCheck: true, KnownHostsFile: filepath.Join(t.TempDir(), "absent")}, "jump host 1 (bastion:22): reading known_hosts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DialSSH(context.Background(), SSHConfig{
				Host: "target", User: "tester", Password: "secret",
				ProxyJump: []SSHConfig{tc.hop},
				Dialer: func(context.Context, string, string) (net.Conn, error) {
					t.Error("Dialer called for a config that should have been refused up front")
					return nil, fmt.Errorf("unreachable")
				},
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
