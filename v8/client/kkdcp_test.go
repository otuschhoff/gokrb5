package client

import (
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/kadmin"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type errorResponseBody struct{ err error }

func (body errorResponseBody) Read([]byte) (int, error) { return 0, body.err }
func (errorResponseBody) Close() error                  { return nil }

func TestKKDCPTransport(t *testing.T) {
	request := []byte{0x6a, 0x03, 0x02, 0x01, 0x05}
	reply := []byte{0x6b, 0x03, 0x02, 0x01, 0x05}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != kkdcpContentType {
			t.Errorf("content type = %q, want %q", got, kkdcpContentType)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		var proxyRequest types.KDCProxyMessage
		if err := proxyRequest.Unmarshal(body); err != nil {
			t.Errorf("decode proxy request: %v", err)
			http.Error(w, "decode request", http.StatusBadRequest)
			return
		}
		message, err := proxyRequest.KerberosMessage()
		if err != nil {
			t.Errorf("unwrap proxy request: %v", err)
			http.Error(w, "unwrap request", http.StatusBadRequest)
			return
		}
		if string(message) != string(request) || proxyRequest.TargetDomain != "EXAMPLE.ORG" {
			t.Errorf("proxy request = %x for %q", message, proxyRequest.TargetDomain)
		}
		proxyReply, err := types.NewKDCProxyMessage(reply, "", 0)
		if err != nil {
			t.Errorf("build proxy reply: %v", err)
			http.Error(w, "build reply", http.StatusInternalServerError)
			return
		}
		encoded, err := proxyReply.Marshal()
		if err != nil {
			t.Errorf("marshal proxy reply: %v", err)
			http.Error(w, "marshal reply", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", kkdcpContentType)
		_, _ = w.Write(encoded)
	}))
	defer server.Close()

	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{{Realm: "EXAMPLE.ORG", KDC: []string{server.URL}}}
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg, KKDCPClient(server.Client()))
	got, err := cl.sendToKDC(request, "EXAMPLE.ORG")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(reply) {
		t.Fatalf("reply = %x, want %x", got, reply)
	}
}

func TestKKDCPRejectsInvalidResponses(t *testing.T) {
	invalidFrame := types.KDCProxyMessage{KerbMessage: []byte{0, 0, 0, 2, 1}}
	invalidFrameBytes, err := invalidFrame.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		status      int
		contentType string
		body        []byte
	}{
		{name: "HTTP status", status: http.StatusForbidden, contentType: kkdcpContentType},
		{name: "content type", status: http.StatusOK, contentType: "text/plain"},
		{name: "ASN.1", status: http.StatusOK, contentType: kkdcpContentType, body: []byte("invalid")},
		{name: "message length", status: http.StatusOK, contentType: kkdcpContentType, body: invalidFrameBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			cfg := config.New()
			cl := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg, KKDCPClient(server.Client()))
			if _, err := cl.sendKKDCP(server.URL, "EXAMPLE.ORG", []byte("request")); err == nil {
				t.Fatal("invalid KKDCP response was accepted")
			}
		})
	}
}

func TestKKDCPReportsErrorResponseReadFailure(t *testing.T) {
	readErr := errors.New("response read failed")
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Body:       errorResponseBody{err: readErr},
			Header:     make(http.Header),
		}, nil
	})}
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", config.New(), KKDCPClient(httpClient))
	_, err := cl.sendKKDCP("https://proxy.example.org/KdcProxy", "EXAMPLE.ORG", []byte("request"))
	if !errors.Is(err, readErr) {
		t.Fatalf("error %v does not wrap response read failure", err)
	}
}

func TestKKDCPDoesNotFollowRedirects(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalls++
	}))
	defer destination.Close()
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer proxy.Close()
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", config.New(), KKDCPClient(proxy.Client()))
	if _, err := cl.sendKKDCP(proxy.URL, "EXAMPLE.ORG", []byte("request")); err == nil {
		t.Fatal("KKDCP redirect was accepted")
	}
	if destinationCalls != 0 {
		t.Fatal("Kerberos request body was forwarded to a redirect destination")
	}
}

func TestKKDCPRejectsNonHTTPSURL(t *testing.T) {
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", config.New())
	if _, err := cl.sendKKDCP("http://proxy.example.org/KdcProxy", "EXAMPLE.ORG", []byte("request")); err == nil {
		t.Fatal("non-HTTPS KKDCP URL was accepted")
	}
}

func TestKKDCPPasswordTransport(t *testing.T) {
	kdcErr := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KRB_ERR_GENERIC, "password response")
	kdcErr.EData = []byte{0, 0}
	krbErrorBytes, err := kdcErr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	passwordReply := make([]byte, 6+len(krbErrorBytes))
	binary.BigEndian.PutUint16(passwordReply[0:2], uint16(len(passwordReply)))
	binary.BigEndian.PutUint16(passwordReply[2:4], 1)
	copy(passwordReply[6:], krbErrorBytes)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read request: %v", readErr)
			return
		}
		var proxyRequest types.KDCProxyMessage
		if decodeErr := proxyRequest.Unmarshal(body); decodeErr != nil {
			t.Errorf("decode request: %v", decodeErr)
			return
		}
		if _, unwrapErr := proxyRequest.KerberosMessage(); unwrapErr != nil {
			t.Errorf("unwrap password request: %v", unwrapErr)
			return
		}
		proxyReply, buildErr := types.NewKDCProxyMessage(passwordReply, "", 0)
		if buildErr != nil {
			t.Errorf("build response: %v", buildErr)
			return
		}
		encoded, marshalErr := proxyReply.Marshal()
		if marshalErr != nil {
			t.Errorf("marshal response: %v", marshalErr)
			return
		}
		w.Header().Set("Content-Type", kkdcpContentType)
		_, _ = w.Write(encoded)
	}))
	defer server.Close()

	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{{Realm: "EXAMPLE.ORG", KPasswdServer: []string{server.URL}}}
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg, KKDCPClient(server.Client()))
	reply, err := cl.sendToKPasswd(kadmin.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if !reply.IsKRBError || reply.ResultCode != KRB5_KPASSWD_SUCCESS {
		t.Fatalf("unexpected password reply: %#v", reply)
	}
}
