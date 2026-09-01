package transport

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentAuthMethod connects to the running ssh-agent (via SSH_AUTH_SOCK)
// and returns an AuthMethod backed by whatever keys it holds.
func agentAuthMethod() (ssh.AuthMethod, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK is not set (no ssh-agent running)")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("connecting to ssh-agent at %s: %w", sock, err)
	}
	client := agent.NewClient(conn)
	return ssh.PublicKeysCallback(client.Signers), nil
}
