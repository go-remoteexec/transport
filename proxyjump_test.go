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

func TestParseProxyJump(t *testing.T) {
	for _, c := range []struct {
		spec string
		want []jumpHop
		bad  bool
	}{
		{spec: "", want: nil},
		// OpenSSH's own way of cancelling a ProxyJump set earlier in a
		// config file. It is not a host called "none".
		{spec: "none", want: nil},
		{spec: "bastion", want: []jumpHop{{host: "bastion"}}},
		{spec: "bastion:2222", want: []jumpHop{{host: "bastion", port: 2222}}},
		{spec: "jump@bastion", want: []jumpHop{{user: "jump", host: "bastion"}}},
		{spec: "jump@bastion:2222", want: []jumpHop{{user: "jump", host: "bastion", port: 2222}}},
		{spec: "a,b:2,c@d", want: []jumpHop{{host: "a"}, {host: "b", port: 2}, {user: "c", host: "d"}}},
		{spec: " a , b ", want: []jumpHop{{host: "a"}, {host: "b"}}},
		// A colon inside a host can only be an IPv6 literal, and only
		// brackets can say so -- as OpenSSH also requires.
		{spec: "[::1]", want: []jumpHop{{host: "::1"}}},
		{spec: "[::1]:2222", want: []jumpHop{{host: "::1", port: 2222}}},
		{spec: "u@[fe80::1]:22", want: []jumpHop{{user: "u", host: "fe80::1", port: 22}}},
		{spec: "::1", bad: true},
		{spec: "a,,b", bad: true},
		{spec: "@host", bad: true},
		{spec: "host:notaport", bad: true},
		{spec: "[::1", bad: true},
	} {
		t.Run(c.spec, func(t *testing.T) {
			got, err := parseProxyJump(c.spec)
			if c.bad {
				if err == nil {
					t.Fatalf("parsed %q as %+v, want an error", c.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProxyJump(%q): %v", c.spec, err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("hop %d = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

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
		ProxyJump:    bastionAddr,
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
		ProxyJump:    firstAddr + "," + secondAddr,
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
		ProxyJump:    "127.0.0.1:1", // nothing listens on port 1
	})
	if err == nil {
		t.Fatal("dialling through an unreachable bastion succeeded")
	}
	if !strings.Contains(err.Error(), "ProxyJump") || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error %q names neither ProxyJump nor the hop", err)
	}
}
