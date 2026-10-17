package transport

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// inheritJumpCredentials fills in what a hop left unset from the target's
// own config. A caller that parsed `-o ProxyJump=bastion` knows the
// bastion's host, and its user and port when the spec named them; it
// does not know which key or password to use, and in OpenSSH that comes
// from ssh_config. There is no ssh_config here, so the target's
// credentials and host-key policy are the sensible stand-in -- and they
// are what makes a bare `-o ProxyJump=bastion` work at all.
//
// A hop that DOES name something keeps it, so a bastion reached with its
// own key stays possible.
func inheritJumpCredentials(hop, target SSHConfig) SSHConfig {
	if hop.User == "" {
		hop.User = target.User
	}
	if hop.Port == 0 {
		hop.Port = 22
	}
	if hop.Password == "" && hop.PrivateKeyFile == "" && hop.PrivateKeyBytes == nil && !hop.UseAgent {
		hop.Password = target.Password
		hop.PrivateKeyFile = target.PrivateKeyFile
		hop.PrivateKeyBytes = target.PrivateKeyBytes
		hop.PrivateKeyPassphrase = target.PrivateKeyPassphrase
		hop.UseAgent = target.UseAgent
	}
	if hop.KnownHostsFile == "" {
		hop.KnownHostsFile = target.KnownHostsFile
	}
	// HostKeyCheck is a bool with a meaningful false, so it cannot be
	// told apart from "unset". It follows the target: a run that does
	// not verify the target's key gains nothing from verifying the
	// bastion's, and a run that does verify would otherwise be
	// silently downgraded for the hop.
	hop.HostKeyCheck = target.HostKeyCheck
	if hop.Timeout == 0 {
		hop.Timeout = target.Timeout
	}
	// A hop is a tunnel, never a place commands run: it must not carry
	// the target's ProxyJump (which would recurse) and has no use for
	// its TempDir or TTY.
	hop.ProxyJump = nil
	hop.TempDir = ""
	hop.TTY = false
	return hop
}

// dialThroughJumps opens the ProxyJump chain and returns a dialer that
// reaches the target from the last hop, plus the connections it opened
// so the caller can close them with the target's.
func dialThroughJumps(ctx context.Context, cfg SSHConfig) (func(context.Context, string, string) (net.Conn, error), []*SSH, error) {
	var opened []*SSH
	closeAll := func() {
		for i := len(opened) - 1; i >= 0; i-- {
			opened[i].Close()
		}
	}

	// The first hop is reached the ordinary way; every later hop is
	// reached THROUGH the one before it, which is the whole point.
	dial := cfg.Dialer
	for _, raw := range cfg.ProxyJump {
		hop := inheritJumpCredentials(raw, cfg)
		hop.Dialer = dial
		if hop.Host == "" {
			closeAll()
			return nil, nil, fmt.Errorf("a ProxyJump hop has no Host")
		}
		hopSSH, err := DialSSH(ctx, hop)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("via %s: %w", net.JoinHostPort(hop.Host, strconv.Itoa(hop.Port)), err)
		}
		opened = append(opened, hopSSH)
		client := hopSSH.client
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.DialContext(ctx, network, addr)
		}
	}
	return dial, opened, nil
}
