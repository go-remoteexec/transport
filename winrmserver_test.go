// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-remoteexec/transport authors

package transport

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeWSMan is an in-process WS-Management (MS-WSMV shell) server. It implements
// the shell state machine — Create → Command → Send → Receive → Signal →
// Delete — returning canned SOAP responses, so the WinRM transport is exercised
// end-to-end with no real Windows host. It does not run a real OS: a per-test
// hook maps a reconstructed command line to (stdout, stderr, exitCode).
type fakeWSMan struct {
	srv *httptest.Server

	// output maps a reconstructed command line to its result. Defaults to a
	// zero-exit echo of the command.
	output func(cmdline, stdin string) (stdout, stderr string, exit int)

	// auth policy: when user is set, requests must carry matching Basic creds or
	// receive 401.
	user, password string
	// requireNTLM makes the server drive an NTLM handshake before serving.
	requireNTLM bool
	// receiveChunks > 1 splits stdout across that many Receive responses, so the
	// client's receive loop iterates.
	receiveChunks int

	mu       sync.Mutex
	shells   map[string]bool
	commands map[string]*fakeCmd  // commandID -> command
	envs     map[string][]envPair // shellID -> environment recorded at create
	// recorded requests for assertions
	lastCommand string
	lastStdin   string
	lastArgs    []string
	lastEnv     []envPair
	allCommands []string
	allArgs     [][]string
}

type envPair struct{ Name, Value string }

type fakeCmd struct {
	shellID string
	line    string
	args    []string
	stdin   string
	served  int // number of Receive responses already returned
}

var actionRE = regexp.MustCompile(`<a:Action[^>]*>([^<]+)</a:Action>`)

func startFakeWSMan(t *testing.T, tls bool, configure func(*fakeWSMan)) *fakeWSMan {
	t.Helper()
	f := &fakeWSMan{
		shells:        map[string]bool{},
		commands:      map[string]*fakeCmd{},
		envs:          map[string][]envPair{},
		receiveChunks: 1,
	}
	if configure != nil {
		configure(f)
	}
	handler := http.HandlerFunc(f.handle)
	if tls {
		f.srv = httptest.NewTLSServer(handler)
	} else {
		f.srv = httptest.NewServer(handler)
	}
	t.Cleanup(f.srv.Close)
	return f
}

// hostPort returns the server's host and port.
func (f *fakeWSMan) hostPort() (string, string) {
	u := strings.TrimPrefix(strings.TrimPrefix(f.srv.URL, "http://"), "https://")
	host, port, _ := strings.Cut(u, ":")
	return host, port
}

func (f *fakeWSMan) handle(w http.ResponseWriter, r *http.Request) {
	if f.requireNTLM && !f.ntlmOK(w, r) {
		return
	}
	if f.user != "" {
		u, p, ok := r.BasicAuth()
		if !ok || u != f.user || p != f.password {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"winrm\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	body, _ := io.ReadAll(r.Body)
	m := actionRE.FindSubmatch(body)
	if m == nil {
		http.Error(w, "no action", http.StatusBadRequest)
		return
	}
	action := string(m[1])
	switch {
	case action == winrmActionCreate:
		f.doCreate(w, body)
	case action == winrmActionCommand:
		f.doCommand(w, body)
	case action == winrmActionSend:
		f.doSend(w, body)
	case action == winrmActionReceive:
		f.doReceive(w, body)
	case action == winrmActionSignal:
		f.reply(w, `<rsp:SignalResponse/>`)
	case action == winrmActionDelete:
		f.mu.Lock()
		delete(f.shells, extractSelector(body, "ShellId"))
		f.mu.Unlock()
		f.reply(w, ``)
	default:
		f.fault(w, "unknown action "+action)
	}
}

// ntlmOK completes a minimal NTLM handshake, returning false (and having written
// a response) until the client presents an authenticate (type 3) message.
func (f *fakeWSMan) ntlmOK(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	if strings.HasPrefix(auth, "NTLM ") {
		tok, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "NTLM "))
		if len(tok) > 8 && tok[8] == 1 { // type 1: reply with a challenge (type 2)
			w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(ntlmType2()))
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
	}
	return true // type 3 (or anything else) accepted
}

// ntlmType2 builds a minimal, parseable NTLM challenge message.
func ntlmType2() []byte {
	b := &bytes.Buffer{}
	b.WriteString("NTLMSSP\x00")
	binary.Write(b, binary.LittleEndian, uint32(2))        // message type
	binary.Write(b, binary.LittleEndian, [8]byte{})        // TargetName varfield
	binary.Write(b, binary.LittleEndian, uint32(1|(1<<9))) // flags: UNICODE|NTLM
	b.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8})                // server challenge
	b.Write(make([]byte, 8))                               // reserved
	binary.Write(b, binary.LittleEndian, [8]byte{})        // TargetInfo varfield
	return b.Bytes()
}

func (f *fakeWSMan) doCreate(w http.ResponseWriter, body []byte) {
	id := "SHELL-" + fmt.Sprint(len(f.shells)+1)
	f.mu.Lock()
	f.shells[id] = true
	env := extractEnv(body)
	f.envs[id] = env
	f.lastEnv = env
	f.mu.Unlock()
	f.reply(w, fmt.Sprintf(`<rsp:Shell><rsp:ShellId>%s</rsp:ShellId></rsp:Shell>`, id))
}

func (f *fakeWSMan) doCommand(w http.ResponseWriter, body []byte) {
	shellID := extractSelector(body, "ShellId")
	f.mu.Lock()
	ok := f.shells[shellID]
	f.mu.Unlock()
	if !ok {
		f.fault(w, "unknown shell "+shellID)
		return
	}
	cmd, args := extractCommand(body)
	cmdID := fmt.Sprintf("CMD-%d", len(f.commands)+1)
	line := cmd
	if len(args) > 0 {
		line += " " + strings.Join(args, " ")
	}
	f.mu.Lock()
	f.commands[cmdID] = &fakeCmd{shellID: shellID, line: line, args: args}
	f.lastCommand = line
	f.lastArgs = args
	f.allCommands = append(f.allCommands, line)
	f.allArgs = append(f.allArgs, args)
	f.mu.Unlock()
	f.reply(w, fmt.Sprintf(`<rsp:CommandResponse><rsp:CommandId>%s</rsp:CommandId></rsp:CommandResponse>`, cmdID))
}

func (f *fakeWSMan) doSend(w http.ResponseWriter, body []byte) {
	cmdID := extractStreamCommandID(body)
	data := extractStreamData(body)
	f.mu.Lock()
	if c := f.commands[cmdID]; c != nil {
		c.stdin = data
		f.lastStdin = data
	}
	f.mu.Unlock()
	f.reply(w, `<rsp:SendResponse/>`)
}

func (f *fakeWSMan) doReceive(w http.ResponseWriter, body []byte) {
	cmdID := extractDesiredStreamCommandID(body)
	f.mu.Lock()
	c := f.commands[cmdID]
	f.mu.Unlock()
	if c == nil {
		f.fault(w, "unknown command "+cmdID)
		return
	}
	out := func(cmdline, stdin string) (string, string, int) { return cmdline + "\n", "", 0 }
	if f.output != nil {
		out = f.output
	}
	stdout, stderr, exit := out(c.line, c.stdin)

	chunks := f.receiveChunks
	if chunks < 1 {
		chunks = 1
	}
	c.served++
	last := c.served >= chunks

	var sb strings.Builder
	// Split stdout across chunks; emit stderr only on the final chunk.
	part := chunkOf(stdout, chunks, c.served-1)
	if part != "" {
		fmt.Fprintf(&sb, `<rsp:Stream Name="stdout" CommandId=%q>%s</rsp:Stream>`,
			cmdID, base64.StdEncoding.EncodeToString([]byte(part)))
	}
	if last {
		if stderr != "" {
			fmt.Fprintf(&sb, `<rsp:Stream Name="stderr" CommandId=%q End="true">%s</rsp:Stream>`,
				cmdID, base64.StdEncoding.EncodeToString([]byte(stderr)))
		}
		fmt.Fprintf(&sb, `<rsp:CommandState State="%s/CommandState/Done"><rsp:ExitCode>%d</rsp:ExitCode></rsp:CommandState>`, winrmNSShell, exit)
	} else {
		fmt.Fprintf(&sb, `<rsp:CommandState State="%s/CommandState/Running"/>`, winrmNSShell)
	}
	f.reply(w, `<rsp:ReceiveResponse>`+sb.String()+`</rsp:ReceiveResponse>`)
}

func chunkOf(s string, n, i int) string {
	if n <= 1 {
		if i == 0 {
			return s
		}
		return ""
	}
	size := (len(s) + n - 1) / n
	start := i * size
	if start >= len(s) {
		return ""
	}
	end := start + size
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func (f *fakeWSMan) reply(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
	fmt.Fprintf(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="%s"><s:Body>%s</s:Body></s:Envelope>`, winrmNSShell, body)
}

func (f *fakeWSMan) fault(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Reason><s:Text>%s</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>`, reason)
}

// --- request parsers (regex/token based; sufficient for the envelopes we emit) ---

func extractSelector(body []byte, name string) string {
	re := regexp.MustCompile(`<w:Selector Name="` + name + `">([^<]*)</w:Selector>`)
	if m := re.FindSubmatch(body); m != nil {
		return string(m[1])
	}
	return ""
}

func extractCommand(body []byte) (string, []string) {
	var out struct {
		Command string   `xml:"Body>CommandLine>Command"`
		Args    []string `xml:"Body>CommandLine>Arguments"`
	}
	_ = xml.Unmarshal(body, &out)
	return out.Command, out.Args
}

func extractStreamCommandID(body []byte) string {
	re := regexp.MustCompile(`<rsp:Stream[^>]*CommandId="([^"]*)"`)
	if m := re.FindSubmatch(body); m != nil {
		return string(m[1])
	}
	return ""
}

func extractStreamData(body []byte) string {
	re := regexp.MustCompile(`<rsp:Stream[^>]*>([^<]*)</rsp:Stream>`)
	m := re.FindSubmatch(body)
	if m == nil {
		return ""
	}
	data, _ := base64.StdEncoding.DecodeString(string(m[1]))
	return string(data)
}

func extractDesiredStreamCommandID(body []byte) string {
	re := regexp.MustCompile(`<rsp:DesiredStream CommandId="([^"]*)"`)
	if m := re.FindSubmatch(body); m != nil {
		return string(m[1])
	}
	return ""
}

func extractEnv(body []byte) []envPair {
	var out struct {
		Vars []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Body>Shell>Environment>Variable"`
	}
	_ = xml.Unmarshal(body, &out)
	var pairs []envPair
	for _, v := range out.Vars {
		pairs = append(pairs, envPair{v.Name, v.Value})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Name < pairs[j].Name })
	return pairs
}
