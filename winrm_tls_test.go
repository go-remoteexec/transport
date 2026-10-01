package transport

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/Azure/go-ntlmssp"
)

// tlsConfigOf digs the *tls.Config out of whatever buildWinRMClient
// returned. It has to look through the NTLM negotiator, because
// "negotiate" is the default transport and the wrapper is exactly what
// made an earlier version of this test skip instead of fail -- a skip
// that read as a pass and left the defect below unnoticed.
func tlsConfigOf(t *testing.T, d HTTPDoer) *tls.Config {
	t.Helper()
	cl, ok := d.(*http.Client)
	if !ok {
		t.Fatalf("doer is %T, want *http.Client", d)
	}
	switch rt := cl.Transport.(type) {
	case *http.Transport:
		return rt.TLSClientConfig
	case ntlmssp.Negotiator:
		inner, ok := rt.RoundTripper.(*http.Transport)
		if !ok {
			t.Fatalf("negotiator wraps %T, want *http.Transport", rt.RoundTripper)
		}
		return inner.TLSClientConfig
	default:
		t.Fatalf("unexpected round tripper %T", rt)
		return nil
	}
}

// A config that says nothing about certificate verification must verify.
// This is the whole point of naming the field InsecureSkipVerify: the
// previous field was SSLVerify, commented "default true", and read as
// `if !c.SSLVerify { InsecureSkipVerify = true }` -- so the natural
// config verified nothing while the comment promised the opposite, and
// the HTTP Basic credentials went to an unverified endpoint.
//
// Both transports are checked because only one of them wraps the
// http.Transport, and testing the unwrapped one alone would not have
// covered the default.
func TestTLSVerifiesUnlessAskedNotTo(t *testing.T) {
	for _, tr := range []string{"negotiate", "basic"} {
		c := WinRMConfig{Host: "win.example", SSL: true, User: "u", Password: "p", Transport: tr}
		c.setDefaults()
		d, err := buildWinRMClient(c)
		if err != nil {
			t.Fatalf("%s: %v", tr, err)
		}
		tc := tlsConfigOf(t, d)
		if tc == nil {
			t.Fatalf("%s: SSL is on but there is no tls.Config", tr)
		}
		if tc.InsecureSkipVerify {
			t.Errorf("%s: a config that never mentions verification does not verify", tr)
		}
		if tc.MinVersion != tls.VersionTLS12 {
			t.Errorf("%s: MinVersion = %x, want TLS 1.2", tr, tc.MinVersion)
		}
	}
}

// And opting out still works, since a self-signed WinRM listener is the
// common case on a lab machine. It has to be typed to happen.
func TestTLSSkipVerifyWhenAsked(t *testing.T) {
	c := WinRMConfig{Host: "win.example", SSL: true, User: "u", Password: "p",
		Transport: "basic", InsecureSkipVerify: true}
	c.setDefaults()
	d, err := buildWinRMClient(c)
	if err != nil {
		t.Fatal(err)
	}
	if tc := tlsConfigOf(t, d); !tc.InsecureSkipVerify {
		t.Error("InsecureSkipVerify was asked for and did not take effect")
	}
}
