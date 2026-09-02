package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

// WinRMConfig configures a WinRM connection to a Windows remote host. It
// speaks WS-Management (SOAP 1.2 with WS-Addressing over HTTP/HTTPS)
// driving the MS-WSMV shell protocol: Create shell -> Command -> Send
// (stdin) -> Receive (stdout/stderr/CommandState/ExitCode) -> Signal
// (terminate) -> Delete shell.
//
// Authentication is selected by Transport: "basic" sends HTTP Basic
// credentials, "negotiate" (the default) performs NTLM via the pure-Go
// github.com/Azure/go-ntlmssp round-tripper, and "ssl" uses TLS
// client-certificate authentication. Kerberos is not implemented.
type WinRMConfig struct {
	Host string
	Port int // default 5986 (SSL) or 5985
	User string

	Password string

	SSL       bool   // default true
	SSLVerify bool   // default true
	CACert    string // path to a CA certificate PEM (custom trust root)

	// Transport selects the auth scheme: "negotiate" (default), "basic",
	// or "ssl" (TLS client certificate — set ClientCert/ClientKey).
	Transport  string
	ClientCert string
	ClientKey  string

	ConnectTimeout time.Duration // default 60s
	TempDir        string        // default `C:\Windows\Temp`
	Path           string        // WS-Man endpoint path, default "/wsman"

	// Environment is set on the shell at creation time (the WS-Man
	// protocol's own Environment block), so every Exec/ExecArgv on this
	// connection sees these variables — e.g. Bolt's PT_-prefixed task
	// parameters for the "environment" input method.
	Environment map[string]string

	// NewDoer builds the HTTP client used to reach the target. Defaults
	// to buildWinRMClient(cfg). Tests inject a doer that reaches an
	// in-process WS-Man server.
	NewDoer func(WinRMConfig) (HTTPDoer, error)
}

func (c *WinRMConfig) setDefaults() {
	if c.Transport == "" {
		c.Transport = "negotiate"
	}
	if c.Port == 0 {
		if c.SSL {
			c.Port = 5986
		} else {
			c.Port = 5985
		}
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 60 * time.Second
	}
	if c.TempDir == "" {
		c.TempDir = `C:\Windows\Temp`
	}
	if c.Path == "" {
		c.Path = "/wsman"
	}
}

func (c WinRMConfig) endpointURL() string {
	scheme := "http"
	if c.SSL {
		scheme = "https"
	}
	p := c.Path
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, c.Host, c.Port, p)
}

// authBasic reports whether requests carry HTTP Basic credentials. Both
// "basic" and "negotiate" set them (go-ntlmssp reads the Basic header
// and upgrades it to NTLM); "ssl" authenticates with a client
// certificate instead.
func (c WinRMConfig) authBasic() bool {
	return c.Transport == "basic" || c.Transport == "negotiate"
}

// HTTPDoer is the seam through which WinRM performs HTTP requests. The
// default implementation is an *http.Client; tests inject a fake.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// buildWinRMClient builds the default HTTP client for a resolved config.
func buildWinRMClient(c WinRMConfig) (HTTPDoer, error) {
	switch c.Transport {
	case "negotiate", "basic", "ssl":
	default:
		return nil, fmt.Errorf("winrm: unknown transport %q", c.Transport)
	}
	tr := &http.Transport{}
	if c.SSL {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if !c.SSLVerify {
			tlsCfg.InsecureSkipVerify = true
		}
		if c.CACert != "" {
			pemBytes, err := os.ReadFile(c.CACert)
			if err != nil {
				return nil, fmt.Errorf("winrm: reading cacert %q: %w", c.CACert, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("winrm: cacert %q contains no certificates", c.CACert)
			}
			tlsCfg.RootCAs = pool
		}
		if c.Transport == "ssl" {
			if c.ClientCert == "" || c.ClientKey == "" {
				return nil, fmt.Errorf("winrm: transport ssl requires ClientCert and ClientKey")
			}
			cert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("winrm: loading client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		tr.TLSClientConfig = tlsCfg
	} else if c.Transport == "ssl" {
		return nil, fmt.Errorf("winrm: transport ssl requires SSL: true")
	}
	var rt http.RoundTripper = tr
	if c.Transport == "negotiate" {
		rt = ntlmssp.Negotiator{RoundTripper: tr}
	}
	return &http.Client{Transport: rt, Timeout: c.ConnectTimeout}, nil
}

// WinRM is a live WinRM connection to one target host: one WS-Man shell,
// opened at Dial time and reused across every Exec/Put/Fetch/Remove
// until Close.
type WinRM struct {
	doer     HTTPDoer
	cfg      WinRMConfig
	endpoint string
	shellID  string
}

// DialWinRM opens a WS-Man shell on cfg.Host.
func DialWinRM(ctx context.Context, cfg WinRMConfig) (*WinRM, error) {
	cfg.setDefaults()
	if cfg.Host == "" {
		return nil, fmt.Errorf("winrm: no host configured")
	}
	newDoer := cfg.NewDoer
	if newDoer == nil {
		newDoer = buildWinRMClient
	}
	doer, err := newDoer(cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	w := &WinRM{doer: doer, cfg: cfg, endpoint: cfg.endpointURL()}
	if err := w.openShell(); err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	return w, nil
}

// WS-Management / MS-WSMV constants.
const (
	winrmNSAddressing = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	winrmNSShell      = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	winrmResourceCmd  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"

	winrmActionCreate  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	winrmActionDelete  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	winrmActionCommand = winrmNSShell + "/Command"
	winrmActionSend    = winrmNSShell + "/Send"
	winrmActionReceive = winrmNSShell + "/Receive"
	winrmActionSignal  = winrmNSShell + "/Signal"
	winrmSignalTerm    = winrmNSShell + "/signal/terminate"
)

func (w *WinRM) openShell() error {
	envBlock := ""
	if len(w.cfg.Environment) > 0 {
		var b strings.Builder
		b.WriteString("<rsp:Environment>")
		for _, k := range sortedStringKeys(w.cfg.Environment) {
			fmt.Fprintf(&b, "<rsp:Variable Name=%q>%s</rsp:Variable>", k, winrmEsc(w.cfg.Environment[k]))
		}
		b.WriteString("</rsp:Environment>")
		envBlock = b.String()
	}
	body := "<rsp:Shell>" + envBlock +
		"<rsp:InputStreams>stdin</rsp:InputStreams>" +
		"<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>" +
		"</rsp:Shell>"
	env, err := w.do("create", winrmActionCreate, "", body)
	if err != nil {
		return err
	}
	id := extractShellID(env)
	if id == "" {
		return fmt.Errorf("winrm: create: response carried no ShellId")
	}
	w.shellID = id
	return nil
}

func (w *WinRM) command(command string, args []string) (string, error) {
	var b strings.Builder
	b.WriteString("<rsp:CommandLine><rsp:Command>")
	b.WriteString(winrmEsc(command))
	b.WriteString("</rsp:Command>")
	for _, a := range args {
		b.WriteString("<rsp:Arguments>")
		b.WriteString(winrmEsc(a))
		b.WriteString("</rsp:Arguments>")
	}
	b.WriteString("</rsp:CommandLine>")
	env, err := w.do("command", winrmActionCommand, w.shellID, b.String())
	if err != nil {
		return "", err
	}
	if env.Body.CommandResponse == nil || env.Body.CommandResponse.CommandID == "" {
		return "", fmt.Errorf("winrm: command: response carried no CommandId")
	}
	return env.Body.CommandResponse.CommandID, nil
}

func (w *WinRM) send(cmdID, stdin string) error {
	b64 := base64.StdEncoding.EncodeToString([]byte(stdin))
	body := fmt.Sprintf(`<rsp:Send><rsp:Stream Name="stdin" CommandId=%q End="true">%s</rsp:Stream></rsp:Send>`, cmdID, b64)
	_, err := w.do("send", winrmActionSend, w.shellID, body)
	return err
}

func (w *WinRM) receive(cmdID string) (string, string, int, error) {
	var stdout, stderr strings.Builder
	for {
		body := fmt.Sprintf(`<rsp:Receive><rsp:DesiredStream CommandId=%q>stdout stderr</rsp:DesiredStream></rsp:Receive>`, cmdID)
		env, err := w.do("receive", winrmActionReceive, w.shellID, body)
		if err != nil {
			return "", "", -1, err
		}
		rr := env.Body.ReceiveResponse
		if rr == nil {
			return "", "", -1, fmt.Errorf("winrm: receive: response carried no ReceiveResponse")
		}
		for _, st := range rr.Streams {
			data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(st.Data))
			if err != nil {
				return "", "", -1, fmt.Errorf("winrm: receive: decoding %s stream: %w", st.Name, err)
			}
			if st.Name == "stderr" {
				stderr.Write(data)
			} else {
				stdout.Write(data)
			}
		}
		if strings.HasSuffix(rr.CommandState.State, "/Done") {
			code, err := strconv.Atoi(strings.TrimSpace(rr.CommandState.ExitCode))
			if err != nil {
				return "", "", -1, fmt.Errorf("winrm: receive: parsing exit code %q: %w", rr.CommandState.ExitCode, err)
			}
			return stdout.String(), stderr.String(), code, nil
		}
	}
}

func (w *WinRM) signal(cmdID string) {
	body := fmt.Sprintf(`<rsp:Signal CommandId=%q><rsp:Code>%s</rsp:Code></rsp:Signal>`, cmdID, winrmSignalTerm)
	_, _ = w.do("signal", winrmActionSignal, w.shellID, body)
}

// run executes command with args, feeds stdin, and returns the captured
// output with the remote exit code. A non-zero exit is not an error.
func (w *WinRM) run(command string, args []string, stdin string) (string, string, int, error) {
	cmdID, err := w.command(command, args)
	if err != nil {
		return "", "", -1, err
	}
	if stdin != "" {
		if err := w.send(cmdID, stdin); err != nil {
			return "", "", -1, err
		}
	}
	stdout, stderr, code, err := w.receive(cmdID)
	w.signal(cmdID)
	return stdout, stderr, code, err
}

// Exec runs cmd through cmd.exe /c on the target's open shell. cmd is
// parsed by cmd.exe itself, with its own quoting rules; a caller that
// already has a program and a clean argv (no cmd.exe requoting wanted —
// e.g. running an uploaded executable with arguments that may contain
// spaces or quotes) should use [WinRM.ExecArgv] instead.
func (w *WinRM) Exec(ctx context.Context, cmd string, stdin io.Reader) (Result, error) {
	return w.ExecArgv(ctx, "cmd.exe", []string{"/c", cmd}, stdin)
}

// ExecArgv runs command with args as the WS-Man protocol's own Command
// and Arguments elements — no cmd.exe requoting layer, so each argument
// reaches the target byte for byte regardless of embedded spaces or
// quotes. Prefer this over Exec whenever the caller already has a
// program and a clean argv.
func (w *WinRM) ExecArgv(ctx context.Context, command string, args []string, stdin io.Reader) (Result, error) {
	var in string
	if stdin != nil {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return Result{}, fmt.Errorf("transport: reading stdin: %w", err)
		}
		in = string(data)
	}
	stdout, stderr, code, err := w.run(command, args, in)
	if err != nil {
		return Result{}, fmt.Errorf("transport: winrm exec: %w", err)
	}
	return Result{Stdout: stdout, Stderr: stderr, RC: code}, nil
}

// Put writes content to dst by streaming base64 to a PowerShell decoder
// (WinRM has no plain file-transfer primitive). opts.Executable is
// ignored: Windows has no exec bit.
func (w *WinRM) Put(ctx context.Context, localPath, remotePath string, opts PutOptions) error {
	content, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	if opts.MkdirParents {
		if dir := winrmDir(remotePath); dir != "" {
			// A nonzero exit here is not itself an error: cmd's mkdir
			// exits nonzero when the directory already exists, which is
			// the common case, not a failure.
			if _, _, _, err := w.run("cmd.exe", []string{"/c", "mkdir", dir}, ""); err != nil {
				return fmt.Errorf("transport: preparing %s: %w", dir, err)
			}
		}
	}
	b64 := base64.StdEncoding.EncodeToString(content)
	ps := fmt.Sprintf(`$in=[Console]::In.ReadToEnd();[IO.File]::WriteAllBytes(%s,[Convert]::FromBase64String($in))`, psSingleQuote(remotePath))
	_, stderr, code, err := w.run("powershell.exe", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps}, b64)
	if err != nil {
		return fmt.Errorf("transport: put %s: %w", remotePath, err)
	}
	if code != 0 {
		return fmt.Errorf("transport: put %s: exit %d: %s", remotePath, code, strings.TrimSpace(stderr))
	}
	return nil
}

// Fetch reads remotePath by streaming its base64 encoding to stdout via
// PowerShell.
func (w *WinRM) Fetch(ctx context.Context, remotePath, localPath string) error {
	ps := fmt.Sprintf(`[Console]::Out.Write([Convert]::ToBase64String([IO.File]::ReadAllBytes(%s)))`, psSingleQuote(remotePath))
	stdout, stderr, code, err := w.run("powershell.exe", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps}, "")
	if err != nil {
		return fmt.Errorf("transport: fetch %s: %w", remotePath, err)
	}
	if code != 0 {
		return fmt.Errorf("transport: fetch %s: exit %d: %s", remotePath, code, strings.TrimSpace(stderr))
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(stdout))
	if err != nil {
		return fmt.Errorf("transport: fetch %s: decoding: %w", remotePath, err)
	}
	return os.WriteFile(localPath, data, 0o644)
}

func (w *WinRM) Remove(ctx context.Context, remotePath string) error {
	_, _, _, _ = w.run("cmd.exe", []string{"/c", "del", "/f", "/q", remotePath}, "")
	return nil
}

func (w *WinRM) TempPath(base string) string {
	dir := strings.TrimRight(w.cfg.TempDir, `\`)
	return fmt.Sprintf(`%s\remoteexec_%d_%s`, dir, time.Now().UnixNano(), base)
}

func (w *WinRM) Close() error {
	if w.shellID == "" {
		return nil
	}
	_, err := w.do("delete", winrmActionDelete, w.shellID, "")
	return err
}

func (w *WinRM) do(step, action, shellID, body string) (*winrmEnvelope, error) {
	envelope := w.envelope(action, shellID, body)
	req, err := http.NewRequest(http.MethodPost, w.endpoint, strings.NewReader(envelope))
	if err != nil {
		return nil, fmt.Errorf("winrm: %s: building request: %w", step, err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	if w.cfg.authBasic() {
		req.SetBasicAuth(w.cfg.User, w.cfg.Password)
	}
	resp, err := w.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("winrm: %s: %w", step, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("winrm: %s: reading response: %w", step, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("winrm: %s: authentication failed (HTTP 401)", step)
	}
	var env winrmEnvelope
	perr := xml.Unmarshal(data, &env)
	if env.Body.Fault != nil {
		return nil, fmt.Errorf("winrm: %s: soap fault: %s", step, env.Body.Fault.text())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("winrm: %s: HTTP %d", step, resp.StatusCode)
	}
	if perr != nil {
		return nil, fmt.Errorf("winrm: %s: parsing response: %w", step, perr)
	}
	return &env, nil
}

func (w *WinRM) envelope(action, shellID, body string) string {
	selector := ""
	if shellID != "" {
		selector = fmt.Sprintf(`<w:SelectorSet><w:Selector Name="ShellId">%s</w:Selector></w:SelectorSet>`, winrmEsc(shellID))
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` +
		` xmlns:a="` + winrmNSAddressing + `"` +
		` xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"` +
		` xmlns:rsp="` + winrmNSShell + `">` +
		`<s:Header>` +
		`<a:To>` + winrmEsc(w.endpoint) + `</a:To>` +
		`<w:ResourceURI s:mustUnderstand="true">` + winrmResourceCmd + `</w:ResourceURI>` +
		`<a:ReplyTo><a:Address s:mustUnderstand="true">` +
		`http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous` +
		`</a:Address></a:ReplyTo>` +
		`<a:Action s:mustUnderstand="true">` + action + `</a:Action>` +
		`<w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>` +
		`<a:MessageID>uuid:` + winrmNewUUID() + `</a:MessageID>` +
		`<w:Locale xml:lang="en-US" s:mustUnderstand="false"/>` +
		`<w:OperationTimeout>PT60S</w:OperationTimeout>` +
		selector +
		`</s:Header>` +
		`<s:Body>` + body + `</s:Body>` +
		`</s:Envelope>`
}

type winrmEnvelope struct {
	XMLName xml.Name
	Body    struct {
		Fault           *winrmFault    `xml:"Fault"`
		Shell           *winrmShell    `xml:"Shell"`
		ResourceCreated *winrmCreated  `xml:"ResourceCreated"`
		CommandResponse *winrmCmdResp  `xml:"CommandResponse"`
		ReceiveResponse *winrmRecvResp `xml:"ReceiveResponse"`
	} `xml:"Body"`
}

type winrmFault struct {
	Reason struct {
		Text string `xml:"Text"`
	} `xml:"Reason"`
	Code struct {
		Subcode struct {
			Value string `xml:"Value"`
		} `xml:"Subcode"`
	} `xml:"Code"`
}

func (f *winrmFault) text() string {
	if t := strings.TrimSpace(f.Reason.Text); t != "" {
		return t
	}
	if v := strings.TrimSpace(f.Code.Subcode.Value); v != "" {
		return v
	}
	return "unknown fault"
}

type winrmShell struct {
	ShellID string `xml:"ShellId"`
}

type winrmCreated struct {
	Selectors []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"ReferenceParameters>SelectorSet>Selector"`
}

type winrmCmdResp struct {
	CommandID string `xml:"CommandId"`
}

type winrmRecvResp struct {
	Streams []struct {
		Name string `xml:"Name,attr"`
		End  string `xml:"End,attr"`
		Data string `xml:",chardata"`
	} `xml:"Stream"`
	CommandState struct {
		State    string `xml:"State,attr"`
		ExitCode string `xml:"ExitCode"`
	} `xml:"CommandState"`
}

// extractShellID pulls the ShellId out of a create response, tolerating
// both the rsp:Shell/ShellId form and a ResourceCreated selector named
// ShellId.
func extractShellID(env *winrmEnvelope) string {
	if env.Body.Shell != nil && env.Body.Shell.ShellID != "" {
		return strings.TrimSpace(env.Body.Shell.ShellID)
	}
	if env.Body.ResourceCreated != nil {
		for _, sel := range env.Body.ResourceCreated.Selectors {
			if sel.Name == "ShellId" {
				return strings.TrimSpace(sel.Value)
			}
		}
	}
	return ""
}

// winrmDir returns the parent directory of a Windows path, or "" if p
// has none worth creating.
func winrmDir(p string) string {
	i := strings.LastIndexAny(p, `\/`)
	if i <= 0 {
		return ""
	}
	dir := p[:i]
	if strings.HasSuffix(dir, ":") { // e.g. "C:"
		return ""
	}
	return dir
}

func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func winrmEsc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func winrmNewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func sortedStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
