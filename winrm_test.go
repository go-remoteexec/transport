package transport

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func dialFakeWinRM(t *testing.T, f *fakeWSMan) *WinRM {
	t.Helper()
	host, portStr := f.hostPort()
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	w, err := DialWinRM(context.Background(), WinRMConfig{
		Host: host,
		Port: port,
		User: "tester",
		SSL:  false,
		NewDoer: func(WinRMConfig) (httpDoer, error) {
			return f.srv.Client(), nil
		},
	})
	if err != nil {
		t.Fatalf("DialWinRM: %v", err)
	}
	return w
}

func TestWinRMExec(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.output = func(cmdline, stdin string) (string, string, int) {
			return "hello\n", "", 0
		}
	})
	w := dialFakeWinRM(t, f)
	defer w.Close()

	res, err := w.Exec(context.Background(), "echo hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(res.Stdout) != "hello" {
		t.Errorf("stdout = %q", res.Stdout)
	}
	if res.RC != 0 {
		t.Errorf("rc = %d", res.RC)
	}
}

func TestWinRMExecNonZero(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.output = func(cmdline, stdin string) (string, string, int) {
			return "", "boom", 5
		}
	})
	w := dialFakeWinRM(t, f)
	defer w.Close()

	res, err := w.Exec(context.Background(), "false", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.RC != 5 {
		t.Errorf("rc = %d, want 5", res.RC)
	}
	if strings.TrimSpace(res.Stderr) != "boom" {
		t.Errorf("stderr = %q", res.Stderr)
	}
}

func TestWinRMExecStdin(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.output = func(cmdline, stdin string) (string, string, int) {
			return stdin, "", 0
		}
	})
	w := dialFakeWinRM(t, f)
	defer w.Close()

	res, err := w.Exec(context.Background(), "cat", strings.NewReader("piped"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "piped" {
		t.Errorf("stdout = %q", res.Stdout)
	}
}

func TestWinRMPutFetch(t *testing.T) {
	var lastWritten string
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.output = func(cmdline, stdin string) (string, string, int) {
			switch {
			case strings.Contains(cmdline, "WriteAllBytes"):
				data, _ := base64.StdEncoding.DecodeString(stdin)
				lastWritten = string(data)
				return "", "", 0
			case strings.Contains(cmdline, "ReadAllBytes"):
				return base64.StdEncoding.EncodeToString([]byte(lastWritten)), "", 0
			default:
				return "", "", 0
			}
		}
	})
	w := dialFakeWinRM(t, f)
	defer w.Close()

	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	if err := os.WriteFile(src, []byte("winrm payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := w.Put(context.Background(), src, `C:\Windows\Temp\dst.txt`, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if lastWritten != "winrm payload" {
		t.Fatalf("server received %q", lastWritten)
	}

	fetched := filepath.Join(dir, "fetched.txt")
	if err := w.Fetch(context.Background(), `C:\Windows\Temp\dst.txt`, fetched); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fetched)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "winrm payload" {
		t.Errorf("fetched = %q", data)
	}
}

func TestWinRMTempPath(t *testing.T) {
	w := &WinRM{cfg: WinRMConfig{TempDir: `C:\Windows\Temp`}}
	p := w.TempPath("task.exe")
	if !strings.HasPrefix(p, `C:\Windows\Temp\remoteexec_`) {
		t.Errorf("TempPath = %q", p)
	}
	if !strings.HasSuffix(p, "_task.exe") {
		t.Errorf("TempPath = %q, want _task.exe suffix", p)
	}
}

func TestWinRMBasicAuthRejected(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.user, f.password = "admin", "correct"
	})
	host, portStr := f.hostPort()
	port, perr := strconv.Atoi(portStr)
	if perr != nil {
		t.Fatal(perr)
	}

	_, err := DialWinRM(context.Background(), WinRMConfig{
		Host: host, Port: port, User: "admin", Password: "wrong", Transport: "basic", SSL: false,
		NewDoer: func(c WinRMConfig) (httpDoer, error) { return f.srv.Client(), nil },
	})
	// The dial itself opens a shell, which will hit the 401 — expect an error.
	if err == nil {
		t.Fatal("expected auth failure")
	}
}
