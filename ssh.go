package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHConfig configures an SSH connection to a Unix-like remote host.
type SSHConfig struct {
	Host string
	Port int // default 22
	User string

	Password             string // optional
	PrivateKeyFile       string // optional, e.g. ~/.ssh/id_ed25519
	PrivateKeyBytes      []byte // optional, an already-loaded key (e.g. from inventory)
	PrivateKeyPassphrase string
	UseAgent             bool // authenticate via SSH_AUTH_SOCK

	// HostKeyCheck: when true (the default), the remote host key is
	// verified against KnownHostsFile (default ~/.ssh/known_hosts) and
	// the connection is refused on any mismatch or unknown host.
	HostKeyCheck   bool
	KnownHostsFile string

	// TempDir is the remote directory TempPath builds paths under.
	// Defaults to /tmp.
	TempDir string

	// TTY requests a pseudo-terminal for every Exec (best-effort: a
	// server that refuses it does not fail the command).
	TTY bool

	Timeout time.Duration // default 30s

	// Dialer establishes the transport-level TCP connection. Defaults
	// to net.Dialer honoring Timeout. Tests inject a dialer that reaches
	// an in-process server.
	//
	// With ProxyJump set, Dialer makes the one connection that leaves
	// this machine -- the one to the FIRST jump host -- and nothing
	// else. Every later hop, and the target, is reached through the
	// previous hop's tunnel. That is the only reading under which both
	// fields can mean what they say at once: a Dialer that pins egress
	// to an interface, a SOCKS proxy or an in-process test server is
	// still honoured, and ProxyJump still decides the route after it.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

	// ProxyJump reaches the target through one or more jump hosts, in
	// order -- the comma-separated list of OpenSSH's `ssh -J a,b` or
	// `-o ProxyJump=a,b`. The first hop is dialled directly (via
	// Dialer, if set); each later hop, and finally the target, is a
	// direct-tcpip channel opened through the hop before it, so the
	// target's sshd sees a connection from the last jump host, exactly
	// as with OpenSSH.
	//
	// Every hop is a full SSH session of its own, and gets its own
	// host-key verification, checked against the hop's OWN Host:Port.
	// The target is checked against the target's Host:Port, never
	// against the address of the hop that carries it -- which is what
	// OpenSSH does, and the only thing that makes a known_hosts entry
	// for the target mean anything once it is behind a bastion.
	//
	// What a hop inherits from this (the target's) config, and what it
	// does not, is decided field by field:
	//
	//   - Host is required. Port defaults to 22, like any SSHConfig.
	//   - User is NOT inherited and is required. OpenSSH does not give
	//     a jump host the target's user either: a hop without one gets
	//     the local user or ssh_config's, and that is a policy for the
	//     caller to apply, not something a library should guess.
	//   - Authentication (Password, PrivateKeyFile/PrivateKeyBytes/
	//     PrivateKeyPassphrase, UseAgent) is inherited as a whole when
	//     the hop configures none of it, and not at all when it
	//     configures any. Mixing a hop's password with the target's key
	//     would be a combination nobody wrote down.
	//   - Host-key checking can only get stricter. A hop is verified
	//     when EITHER its own HostKeyCheck or the target's is true, and
	//     an empty KnownHostsFile falls back to the target's. A bool's
	//     zero value is false, so letting the hop's own field win would
	//     turn verification off for every hop a caller wrote without
	//     mentioning it -- the same trap WinRMConfig.SSLVerify fell into.
	//   - Timeout, TempDir and TTY are ignored. Nothing is executed on
	//     a hop, and the target's Timeout already bounds the one TCP
	//     dial this machine makes (to the first hop) exactly as it
	//     bounds the direct dial without ProxyJump. Neither path bounds
	//     the SSH handshake itself; ctx bounds the opening of each
	//     tunnel channel.
	//   - Dialer and ProxyJump on a hop are rejected, not ignored. A
	//     chain is written flat here, as OpenSSH's comma list is.
	ProxyJump []SSHConfig
}

// SSH is a live SSH connection to one target host. Every Exec opens its
// own session, matching how SSH sessions work (one command per session).
type SSH struct {
	client  *ssh.Client
	hops    []*ssh.Client // jump hosts, in dial order; closed in reverse
	tempDir string
	tty     bool
}

// sshDialStep is one fully-prepared SSH handshake: everything that can
// fail without touching the network has already been resolved.
type sshDialStep struct {
	addr  string
	label string // "" for the target, "jump host N (addr)" for a hop
	cfg   *ssh.ClientConfig
}

// DialSSH connects and authenticates to cfg.Host, trying (in order)
// explicit password, private key, and ssh-agent — whichever of those
// cfg populates. With cfg.ProxyJump set, it first connects to each jump
// host in turn and reaches the target through them (see ProxyJump).
//
// Every configuration error -- a missing key file, an unreadable
// known_hosts, a hop with no User -- is reported before the first
// packet is sent. A failure part-way along the chain closes every hop
// already connected, in reverse order, so nothing is left holding a
// session open on a bastion.
func DialSSH(ctx context.Context, cfg SSHConfig) (*SSH, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.TempDir == "" {
		cfg.TempDir = "/tmp"
	}

	targetAuths, err := sshAuthMethods(cfg)
	if err != nil {
		return nil, err
	}

	hopSteps := make([]sshDialStep, 0, len(cfg.ProxyJump))
	for i, hop := range cfg.ProxyJump {
		step, err := jumpHostStep(cfg, targetAuths, i, hop)
		if err != nil {
			return nil, err
		}
		hopSteps = append(hopSteps, step)
	}
	hkc, err := sshHostKeyCallback(cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	target := sshDialStep{
		addr: net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port)),
		cfg: &ssh.ClientConfig{
			User:            cfg.User,
			Auth:            targetAuths,
			HostKeyCallback: hkc,
			Timeout:         cfg.Timeout,
		},
	}

	dial := cfg.Dialer
	if dial == nil {
		d := net.Dialer{Timeout: cfg.Timeout}
		dial = d.DialContext
	}

	var hops []*ssh.Client
	for _, step := range hopSteps {
		client, err := sshHandshake(ctx, dial, step, hops)
		if err != nil {
			closeSSHClients(hops)
			return nil, err
		}
		hops = append(hops, client)
		// The next connection is a direct-tcpip channel through this
		// hop. DialContext honours ctx while the channel is being
		// opened, as net.Dialer does for the first one.
		dial = client.DialContext
	}
	client, err := sshHandshake(ctx, dial, target, hops)
	if err != nil {
		closeSSHClients(hops)
		return nil, err
	}
	return &SSH{client: client, hops: hops, tempDir: cfg.TempDir, tty: cfg.TTY}, nil
}

// sshHandshake opens the transport connection for one step and runs the
// SSH handshake over it. hops is only used to word the error: an error
// reaching the target through a bastion should say so, because "dialing
// 10.0.0.5:22: connect: administratively prohibited" reads as a
// firewall problem on this machine otherwise.
func sshHandshake(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), step sshDialStep, hops []*ssh.Client) (*ssh.Client, error) {
	what := step.addr
	if step.label != "" {
		what = step.label
	}
	via := ""
	if len(hops) > 0 {
		via = fmt.Sprintf(" via jump host %d", len(hops))
	}
	conn, err := dial(ctx, "tcp", step.addr)
	if err != nil {
		return nil, fmt.Errorf("transport: dialing %s%s: %w", what, via, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, step.addr, step.cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("transport: ssh handshake with %s%s: %w", what, via, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// jumpHostStep resolves hop i of cfg.ProxyJump into a dial step,
// applying the inheritance rules documented on SSHConfig.ProxyJump.
func jumpHostStep(target SSHConfig, targetAuths []ssh.AuthMethod, i int, hop SSHConfig) (sshDialStep, error) {
	if hop.Port == 0 {
		hop.Port = 22
	}
	addr := net.JoinHostPort(hop.Host, fmt.Sprintf("%d", hop.Port))
	label := fmt.Sprintf("jump host %d (%s)", i+1, addr)
	switch {
	case hop.Host == "":
		return sshDialStep{}, fmt.Errorf("transport: jump host %d has no Host", i+1)
	case hop.User == "":
		return sshDialStep{}, fmt.Errorf("transport: %s has no User (a jump host does not inherit the target's)", label)
	case hop.Dialer != nil:
		return sshDialStep{}, fmt.Errorf("transport: %s sets Dialer; only the target config's Dialer is used, for the first hop", label)
	case len(hop.ProxyJump) > 0:
		return sshDialStep{}, fmt.Errorf("transport: %s sets its own ProxyJump; list every hop, in order, in the target's ProxyJump", label)
	}

	auths := targetAuths
	if hop.Password != "" || hop.PrivateKeyFile != "" || hop.PrivateKeyBytes != nil || hop.UseAgent {
		var err error
		if auths, err = sshAuthMethods(hop); err != nil {
			return sshDialStep{}, fmt.Errorf("%w (%s)", err, label)
		}
	}

	hop.HostKeyCheck = hop.HostKeyCheck || target.HostKeyCheck
	if hop.KnownHostsFile == "" {
		hop.KnownHostsFile = target.KnownHostsFile
	}
	hkc, err := sshHostKeyCallback(hop)
	if err != nil {
		return sshDialStep{}, fmt.Errorf("transport: %s: %w", label, err)
	}
	return sshDialStep{
		addr:  addr,
		label: label,
		cfg: &ssh.ClientConfig{
			User:            hop.User,
			Auth:            auths,
			HostKeyCallback: hkc,
			Timeout:         target.Timeout,
		},
	}, nil
}

// sshAuthMethods turns cfg's credentials into ssh.AuthMethods, in the
// order DialSSH documents: password, private key, agent.
func sshAuthMethods(cfg SSHConfig) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod
	if cfg.Password != "" {
		auths = append(auths, ssh.Password(cfg.Password))
	}
	keyBytes := cfg.PrivateKeyBytes
	if keyBytes == nil && cfg.PrivateKeyFile != "" {
		data, err := os.ReadFile(cfg.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("transport: reading private key: %w", err)
		}
		keyBytes = data
	}
	if keyBytes != nil {
		signer, err := parsePrivateKey(keyBytes, cfg.PrivateKeyPassphrase)
		if err != nil {
			return nil, fmt.Errorf("transport: loading private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if cfg.UseAgent {
		agentAuth, err := agentAuthMethod()
		if err != nil {
			return nil, fmt.Errorf("transport: ssh-agent: %w", err)
		}
		auths = append(auths, agentAuth)
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("transport: no SSH authentication method configured (need Password, PrivateKeyFile/PrivateKeyBytes, or UseAgent)")
	}
	return auths, nil
}

// closeSSHClients closes clients in reverse order -- innermost first --
// so each tunnel is torn down before the connection that carries it.
func closeSSHClients(clients []*ssh.Client) error {
	var errs []error
	for i := len(clients) - 1; i >= 0; i-- {
		if err := clients[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func sshHostKeyCallback(cfg SSHConfig) (ssh.HostKeyCallback, error) {
	if !cfg.HostKeyCheck {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	p := cfg.KnownHostsFile
	if p == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolving default known_hosts path: %w", err)
		}
		p = filepath.Join(home, ".ssh", "known_hosts")
	}
	cb, err := knownhosts.New(p)
	if err != nil {
		return nil, fmt.Errorf("reading known_hosts %s: %w (set HostKeyCheck=false to disable)", p, err)
	}
	return cb, nil
}

func parsePrivateKey(data []byte, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(data)
}

func (s *SSH) Exec(ctx context.Context, cmd string, stdin io.Reader) (Result, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("transport: opening ssh session: %w", err)
	}
	defer session.Close()

	if s.tty {
		// Best-effort PTY; a server that refuses it must not fail the
		// command.
		_ = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	}

	var stdout, stderr bytes.Buffer
	session.Stdin = stdin
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		return Result{}, ctx.Err()
	case err := <-done:
		rc := 0
		if err != nil {
			if exitErr, ok := err.(*ssh.ExitError); ok {
				rc = exitErr.ExitStatus()
			} else {
				return Result{}, fmt.Errorf("transport: ssh exec: %w", err)
			}
		}
		return Result{Stdout: stdout.String(), Stderr: stderr.String(), RC: rc}, nil
	}
}

// NewSession opens a live streaming session over a fresh *ssh.Session on
// the already-dialed client, implementing Streamer. TTY is honored the
// same best-effort way Exec honors it: a RequestPty before Start, ignored
// if the server refuses it.
func (s *SSH) NewSession(ctx context.Context) (Session, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("transport: opening ssh session: %w", err)
	}
	if s.tty {
		_ = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	}
	return &sshSession{session: session, ctx: ctx, stopWatch: make(chan struct{})}, nil
}

// sshSession adapts a real *ssh.Session (whose StdinPipe/StdoutPipe/
// StderrPipe/Start/Wait/Close already match Session's shape almost
// exactly) to the Session interface, additionally watching ctx so a
// caller's cancellation kills the remote process the same way Exec's
// ctx.Done handling does.
type sshSession struct {
	session *ssh.Session
	ctx     context.Context

	once      sync.Once
	stopWatch chan struct{}
}

func (s *sshSession) StdinPipe() (io.WriteCloser, error) {
	w, err := s.session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("transport: ssh session stdin pipe: %w", err)
	}
	return w, nil
}

func (s *sshSession) StdoutPipe() (io.Reader, error) {
	r, err := s.session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("transport: ssh session stdout pipe: %w", err)
	}
	return r, nil
}

func (s *sshSession) StderrPipe() (io.Reader, error) {
	r, err := s.session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("transport: ssh session stderr pipe: %w", err)
	}
	return r, nil
}

func (s *sshSession) Start(cmd string) error {
	if err := s.session.Start(cmd); err != nil {
		return fmt.Errorf("transport: ssh session start: %w", err)
	}
	go func() {
		select {
		case <-s.ctx.Done():
			_ = s.session.Signal(ssh.SIGKILL)
			_ = s.session.Close()
		case <-s.stopWatch:
		}
	}()
	return nil
}

func (s *sshSession) Wait() (int, error) {
	err := s.session.Wait()
	s.stop()

	rc := 0
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			rc = exitErr.ExitStatus()
		} else {
			return 0, fmt.Errorf("transport: ssh session wait: %w", err)
		}
	}
	return rc, nil
}

// Close terminates the session (if still running) and stops the ctx
// watcher. Safe to call after Wait, and safe to call more than once.
func (s *sshSession) Close() error {
	s.stop()
	return s.session.Close()
}

func (s *sshSession) stop() {
	s.once.Do(func() { close(s.stopWatch) })
}

// Put streams localPath's contents to remotePath over a plain `cat >`
// session. This avoids an SFTP dependency; it needs only /bin/sh, cat,
// mkdir and chmod on the target — universally present.
func (s *SSH) Put(ctx context.Context, localPath, remotePath string, opts PutOptions) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	if opts.MkdirParents {
		if dir := path.Dir(remotePath); dir != "." && dir != "/" {
			if res, err := s.Exec(ctx, "mkdir -p "+shellQuote(dir), nil); err != nil || res.RC != 0 {
				return fmt.Errorf("transport: preparing %s: %w (stderr: %s)", dir, err, res.Stderr)
			}
		}
	}
	res, err := s.Exec(ctx, "cat > "+shellQuote(remotePath), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("transport: put %s: %w", remotePath, err)
	}
	if res.RC != 0 {
		return fmt.Errorf("transport: put %s: exit %d: %s", remotePath, res.RC, res.Stderr)
	}
	if opts.Executable {
		if res, err := s.Exec(ctx, "chmod +x "+shellQuote(remotePath), nil); err != nil || res.RC != 0 {
			return fmt.Errorf("transport: chmod +x %s: %w (stderr: %s)", remotePath, err, res.Stderr)
		}
	}
	return nil
}

func (s *SSH) Fetch(ctx context.Context, remotePath, localPath string) error {
	res, err := s.Exec(ctx, "cat "+shellQuote(remotePath), nil)
	if err != nil {
		return fmt.Errorf("transport: fetch %s: %w", remotePath, err)
	}
	if res.RC != 0 {
		return fmt.Errorf("transport: fetch %s: exit %d: %s", remotePath, res.RC, res.Stderr)
	}
	return os.WriteFile(localPath, []byte(res.Stdout), 0o644)
}

func (s *SSH) Remove(ctx context.Context, remotePath string) error {
	res, err := s.Exec(ctx, "rm -f "+shellQuote(remotePath), nil)
	if err != nil {
		return fmt.Errorf("transport: remove %s: %w", remotePath, err)
	}
	if res.RC != 0 {
		return fmt.Errorf("transport: remove %s: exit %d: %s", remotePath, res.RC, res.Stderr)
	}
	return nil
}

func (s *SSH) TempPath(base string) string {
	dir := s.tempDir
	if dir == "" {
		dir = "/tmp"
	}
	return path.Join(dir, fmt.Sprintf("remoteexec_%d_%s", time.Now().UnixNano(), base))
}

// Close closes the connection to the target and then every jump host,
// innermost first. Each hop is closed even if an earlier Close failed,
// and every error is returned, joined.
func (s *SSH) Close() error {
	all := make([]*ssh.Client, 0, len(s.hops)+1)
	all = append(all, s.hops...)
	return closeSSHClients(append(all, s.client))
}
