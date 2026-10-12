package transport

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// shellConn records what reaches the login user's shell. It plays a
// target where escalation succeeds: it answers every wrapped command
// with the success marker, then whatever reply says. Its own Put, Fetch
// and Remove fail the test, because a become-wrapped transfer must not
// fall through to them -- that fall-through is the bug.
type shellConn struct {
	t      *testing.T
	cmds   []string
	stdins []string
	reply  func(cmd string) Result
}

var markerRe = regexp.MustCompile(`BECOME-SUCCESS-[0-9a-f]+`)

func (c *shellConn) Exec(_ context.Context, cmd string, stdin io.Reader) (Result, error) {
	c.cmds = append(c.cmds, cmd)
	in := ""
	if stdin != nil {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return Result{}, err
		}
		in = string(b)
	}
	c.stdins = append(c.stdins, in)
	res := Result{}
	if c.reply != nil {
		res = c.reply(cmd)
	}
	res.Stdout = markerRe.FindString(cmd) + "\n" + res.Stdout
	return res, nil
}

func (c *shellConn) Put(context.Context, string, string, PutOptions) error {
	c.t.Fatal("Put reached the unprivileged connection")
	return nil
}

func (c *shellConn) Fetch(context.Context, string, string) error {
	c.t.Fatal("Fetch reached the unprivileged connection")
	return nil
}

func (c *shellConn) Remove(context.Context, string) error {
	c.t.Fatal("Remove reached the unprivileged connection")
	return nil
}

func (c *shellConn) TempPath(base string) string { return "/tmp/" + base }
func (c *shellConn) Close() error                { return nil }

func localFile(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBecomePutWritesThroughEscalation(t *testing.T) {
	inner := &shellConn{t: t}
	conn := Become(inner, BecomeConfig{})
	err := conn.Put(context.Background(), localFile(t, "10.0.0.1 a\n"), "/etc/hosts", PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inner.cmds) != 1 {
		t.Fatalf("commands = %q, want one", inner.cmds)
	}
	cmd := inner.cmds[0]
	if !strings.HasPrefix(cmd, "sudo -H -S -n -u root") || !strings.Contains(cmd, "cat > ") || !strings.Contains(cmd, "/etc/hosts") {
		t.Errorf("command = %q, want an escalated cat > /etc/hosts", cmd)
	}
	if inner.stdins[0] != "10.0.0.1 a\n" {
		t.Errorf("stdin = %q, want the file's bytes", inner.stdins[0])
	}
}

func TestBecomePutPasswordComesBeforeTheFile(t *testing.T) {
	inner := &shellConn{t: t}
	conn := Become(inner, BecomeConfig{Password: "pw"})
	if err := conn.Put(context.Background(), localFile(t, "data"), "/root/f", PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if inner.stdins[0] != "pw\ndata" {
		t.Errorf("stdin = %q, want the password line, then the file", inner.stdins[0])
	}
}

func TestBecomePutMkdirAndExecutable(t *testing.T) {
	inner := &shellConn{t: t}
	conn := Become(inner, BecomeConfig{})
	if err := conn.Put(context.Background(), localFile(t, "x"), "/opt/a b/run", PutOptions{MkdirParents: true, Executable: true}); err != nil {
		t.Fatal(err)
	}
	if len(inner.cmds) != 3 {
		t.Fatalf("commands = %q, want mkdir, cat, chmod", inner.cmds)
	}
	for i, want := range []string{"mkdir -p", "cat > ", "chmod +x"} {
		if !strings.Contains(inner.cmds[i], want) || !strings.HasPrefix(inner.cmds[i], "sudo ") {
			t.Errorf("command %d = %q, want an escalated %q", i, inner.cmds[i], want)
		}
	}
}

func TestBecomePutRootDirectoryIsNotCreated(t *testing.T) {
	inner := &shellConn{t: t}
	if err := Become(inner, BecomeConfig{}).Put(context.Background(), localFile(t, "x"), "/f", PutOptions{MkdirParents: true}); err != nil {
		t.Fatal(err)
	}
	if len(inner.cmds) != 1 {
		t.Errorf("commands = %q, want no mkdir for /", inner.cmds)
	}
}

func TestBecomePutReportsFailures(t *testing.T) {
	ctx := context.Background()
	failing := func(match string) *shellConn {
		return &shellConn{t: t, reply: func(cmd string) Result {
			if strings.Contains(cmd, match) {
				return Result{RC: 1, Stderr: "denied"}
			}
			return Result{}
		}}
	}
	for _, match := range []string{"mkdir -p", "cat > ", "chmod +x"} {
		err := Become(failing(match), BecomeConfig{}).Put(ctx, localFile(t, "x"), "/a/b", PutOptions{MkdirParents: true, Executable: true})
		if err == nil || !strings.Contains(err.Error(), "denied") {
			t.Errorf("%s failing: err = %v", match, err)
		}
	}
	if err := Become(&shellConn{t: t}, BecomeConfig{}).Put(ctx, filepath.Join(t.TempDir(), "missing"), "/a", PutOptions{}); err == nil {
		t.Error("a missing local file was put")
	}
}

func TestBecomeFetchReadsThroughEscalation(t *testing.T) {
	inner := &shellConn{t: t, reply: func(string) Result { return Result{Stdout: "secret\n"} }}
	dst := filepath.Join(t.TempDir(), "out")
	if err := Become(inner, BecomeConfig{}).Fetch(context.Background(), "/etc/munge/munge.key", dst); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(inner.cmds[0], "sudo ") || !strings.Contains(inner.cmds[0], "cat ") {
		t.Errorf("command = %q", inner.cmds[0])
	}
	if b, _ := os.ReadFile(dst); string(b) != "secret\n" {
		t.Errorf("fetched %q, want the file without the become marker", b)
	}
	bad := &shellConn{t: t, reply: func(string) Result { return Result{RC: 1, Stderr: "no such file"} }}
	if err := Become(bad, BecomeConfig{}).Fetch(context.Background(), "/nope", dst); err == nil {
		t.Error("a failed cat was fetched")
	}
}

func TestBecomeRemoveThroughEscalation(t *testing.T) {
	inner := &shellConn{t: t}
	if err := Become(inner, BecomeConfig{}).Remove(context.Background(), "/etc/x"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(inner.cmds[0], "sudo ") || !strings.Contains(inner.cmds[0], "rm -f") {
		t.Errorf("command = %q", inner.cmds[0])
	}
}

type brokenConn struct{ shellConn }

func (c *brokenConn) Exec(context.Context, string, io.Reader) (Result, error) {
	return Result{}, errors.New("connection lost")
}

func TestBecomeTransferSurfacesExecErrors(t *testing.T) {
	conn := Become(&brokenConn{shellConn{t: t}}, BecomeConfig{})
	ctx := context.Background()
	if err := conn.Put(ctx, localFile(t, "x"), "/a", PutOptions{}); err == nil || !strings.Contains(err.Error(), "connection lost") {
		t.Errorf("Put err = %v", err)
	}
	if err := conn.Fetch(ctx, "/a", filepath.Join(t.TempDir(), "o")); err == nil {
		t.Error("Fetch over a lost connection succeeded")
	}
	if err := conn.Remove(ctx, "/a"); err == nil {
		t.Error("Remove over a lost connection succeeded")
	}
}
