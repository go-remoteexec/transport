package transport

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// jumpHop is one bastion in a ProxyJump chain.
type jumpHop struct {
	user string // empty: inherit the target's User
	host string
	port int // 0: 22
}

// parseProxyJump parses an OpenSSH ProxyJump / -J specification: one or
// more hops, comma separated, each [user@]host[:port], dialled left to
// right with the last one reaching the target.
//
// The literal "none" disables jumping, which is OpenSSH's own way of
// cancelling a ProxyJump set earlier in a config file; it returns no
// hops rather than looking for a host called "none".
//
// IPv6 literals are accepted in brackets, [::1]:2222, because that is
// the only way a colon can appear in a host without being the port
// separator.
func parseProxyJump(spec string) ([]jumpHop, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "none" {
		return nil, nil
	}

	var hops []jumpHop
	for _, raw := range strings.Split(spec, ",") {
		part := strings.TrimSpace(raw)
		if part == "" {
			return nil, fmt.Errorf("empty hop in ProxyJump %q", spec)
		}
		var hop jumpHop
		if at := strings.LastIndex(part, "@"); at >= 0 {
			hop.user, part = part[:at], part[at+1:]
			if hop.user == "" {
				return nil, fmt.Errorf("empty user in ProxyJump hop %q", raw)
			}
		}
		host, port, err := splitHostPort(part)
		if err != nil {
			return nil, fmt.Errorf("ProxyJump hop %q: %w", raw, err)
		}
		hop.host, hop.port = host, port
		if hop.host == "" {
			return nil, fmt.Errorf("empty host in ProxyJump hop %q", raw)
		}
		hops = append(hops, hop)
	}
	return hops, nil
}

// splitHostPort handles "host", "host:port", "[::1]" and "[::1]:port".
func splitHostPort(s string) (string, int, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("unclosed [ in %q", s)
		}
		host := s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return host, 0, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("trailing %q after ] in %q", rest, s)
		}
		p, err := strconv.Atoi(rest[1:])
		if err != nil {
			return "", 0, fmt.Errorf("port %q: %w", rest[1:], err)
		}
		return host, p, nil
	}
	// A bare IPv6 address has more than one colon and no brackets: it
	// cannot be told from host:port, and OpenSSH requires brackets too.
	if strings.Count(s, ":") > 1 {
		return "", 0, fmt.Errorf("IPv6 address %q must be bracketed", s)
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		p, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return "", 0, fmt.Errorf("port %q: %w", s[i+1:], err)
		}
		return s[:i], p, nil
	}
	return s, 0, nil
}

// dialThroughJumps opens the ProxyJump chain and returns a dialer that
// reaches the target from the last hop, plus the clients it opened so
// the caller can close them with the connection.
//
// Each hop inherits the target's credentials and host-key policy,
// overriding only what its own spec names. OpenSSH instead reads each
// hop's settings from ssh_config; there is no ssh_config here, and
// inheriting is what makes `-o ProxyJump=bastion` work with the key the
// run already uses.
func dialThroughJumps(ctx context.Context, cfg SSHConfig, hops []jumpHop) (func(context.Context, string, string) (net.Conn, error), []*SSH, error) {
	var opened []*SSH
	closeAll := func() {
		for i := len(opened) - 1; i >= 0; i-- {
			opened[i].Close()
		}
	}

	// The first hop is reached the ordinary way; every later hop is
	// reached THROUGH the one before it, which is the whole point.
	dial := cfg.Dialer
	for _, hop := range hops {
		hopCfg := cfg
		hopCfg.ProxyJump = "" // or this would recurse forever
		hopCfg.Dialer = dial
		hopCfg.Host = hop.host
		hopCfg.Port = hop.port
		if hop.user != "" {
			hopCfg.User = hop.user
		}
		// A hop is a tunnel, not a place we run commands: its TempDir
		// and TTY are irrelevant, and leaving them inherited is
		// harmless.
		hopSSH, err := DialSSH(ctx, hopCfg)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("via %s: %w", net.JoinHostPort(hop.host, strconv.Itoa(hopCfg.Port)), err)
		}
		opened = append(opened, hopSSH)
		client := hopSSH.client
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.DialContext(ctx, network, addr)
		}
	}
	return dial, opened, nil
}
