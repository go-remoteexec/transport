module github.com/go-remoteexec/transport

go 1.27.1

require (
	github.com/Azure/go-ntlmssp v0.1.1
	golang.org/x/crypto v0.58.0
)

require golang.org/x/sys v0.49.0 // indirect

// v0.6.0 shipped ProxyJump as a string -- the OpenSSH `-J` spec, parsed
// here. It was replaced within minutes by []SSHConfig, because the
// caller that needed it (go-ansible/playbook) already parses that
// syntax along with the rest of ansible_ssh_common_args and had no use
// for a second parser. Nothing consumed v0.6.0; retracted so nothing
// starts to.
retract v0.6.0
