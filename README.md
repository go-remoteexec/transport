# transport

Pure-Go (CGO=0) remote command execution — local, SSH, and WinRM connections,
plus sudo/su/doas privilege escalation — shared across orchestration tools
(consumed by [go-ansible](https://github.com/go-ansible) and
[go-puppet-bolt](https://github.com/go-puppet-bolt)).

[![CI](https://github.com/go-remoteexec/transport/actions/workflows/ci.yml/badge.svg)](https://github.com/go-remoteexec/transport/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-remoteexec/transport.svg)](https://pkg.go.dev/github.com/go-remoteexec/transport)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

## Escalation covers file transfer too

`Become(conn, cfg)` wraps a connection so `Exec` runs as the become user —
and so do `Put`, `Fetch` and `Remove`, each carried out through that same
escalated `Exec`.

They used to pass through unescalated, on the reasoning that Ansible's own
become affects command execution and not file transfer. That holds for
Ansible, whose controller writes into a temporary directory and has an
escalated module move the file into place. It did not hold for this package's
callers: go-ansible's `copy`, `template`, `lineinfile` and `blockinfile` `Put`
straight to the destination, so with `become: true` every one of them failed
on a root-owned file —

```
writing /etc/hosts: transport: put /etc/hosts: exit 1:
bash: line 1: /etc/hosts: Permission denied
```

— the task asked for root and the write was made as the login user. Fixed in
**v0.8.0** ([#24](https://github.com/go-remoteexec/transport/pull/24)).
`Close` still passes through, and the wrapper still does not implement
`Streamer` even when the underlying connection does.

## Jump hosts

`SSHConfig.ProxyJump` is a `[]SSHConfig` — resolved hops, not an OpenSSH
`-J` string left to be re-parsed — so a target behind one or more bastions is
reached by dialling each hop through the previous one. A hop inherits the
target's credentials unless it carries its own, and the tunnels unwind
innermost-first on `Close`. Added in **v0.7.0**; v0.6.0 took a `string` and is
retracted in `go.mod`.
