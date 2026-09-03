package transport

import (
	"bytes"
	"context"
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
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

// SSH is a live SSH connection to one target host. Every Exec opens its
// own session, matching how SSH sessions work (one command per session).
type SSH struct {
	client  *ssh.Client
	tempDir string
	tty     bool
}

// DialSSH connects and authenticates to cfg.Host, trying (in order)
// explicit password, private key, and ssh-agent — whichever of those
// cfg populates.
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

	hkc, err := sshHostKeyCallback(cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auths,
		HostKeyCallback: hkc,
		Timeout:         cfg.Timeout,
	}

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	dial := cfg.Dialer
	if dial == nil {
		d := net.Dialer{Timeout: cfg.Timeout}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: dialing %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, clientCfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("transport: ssh handshake with %s: %w", addr, err)
	}
	return &SSH{client: ssh.NewClient(sshConn, chans, reqs), tempDir: cfg.TempDir, tty: cfg.TTY}, nil
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

func (s *SSH) Close() error {
	return s.client.Close()
}
