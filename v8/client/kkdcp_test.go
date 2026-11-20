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
	server := httptest.NewTLSServer(kkdcpTestHandler(t, request, reply))
	defer server.Close()

	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{kdcTestRealmConfig(clientTestOrgRealm, []string{server.URL})}
	cl := NewWithPassword("user", clientTestOrgRealm, "password", cfg, KKDCPClient(server.Client()))
	got, err := cl.sendToKDC(request, clientTestOrgRealm)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(reply) {
		t.Fatalf("reply = %x, want %x", got, reply)
	}
}

func kkdcpTestHandler(t *testing.T, request, reply []byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
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
		if ierr := proxyRequest.Unmarshal(body); ierr != nil {
			t.Errorf("decode proxy request: %v", ierr)
			http.Error(w, "decode request", http.StatusBadRequest)
			return
		}
		message, err := proxyRequest.KerberosMessage()
		if err != nil {
			t.Errorf("unwrap proxy request: %v", err)
			http.Error(w, "unwrap request", http.StatusBadRequest)
			return
		}
		if string(message) != string(request) || proxyRequest.TargetDomain != clientTestOrgRealm {
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
	}
}

func TestKKDCPRejectsInvalidResponses(t *testing.T) {
	var invalidFrame types.KDCProxyMessage
	invalidFrame.KerbMessage = []byte{0, 0, 0, 2, 1}
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
		{name: "HTTP status", status: http.StatusForbidden, contentType: kkdcpContentType, body: nil},
		{name: "content type", status: http.StatusOK, contentType: "text/plain", body: nil},
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
			cl := NewWithPassword("user", clientTestOrgRealm, "password", cfg, KKDCPClient(server.Client()))
			if _, err := cl.sendKKDCP(server.URL, clientTestOrgRealm, []byte("request")); err == nil {
				t.Fatal("invalid KKDCP response was accepted")
			}
		})
	}
}

func TestKKDCPReportsErrorResponseReadFailure(t *testing.T) {
	readErr := errors.New("response read failed")
	var httpClient http.Client
	httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		var response http.Response
		response.StatusCode = http.StatusBadGateway
		response.Status = "502 Bad Gateway"
		response.Body = errorResponseBody{err: readErr}
		response.Header = make(http.Header)
		return &response, nil
	})
	cl := NewWithPassword("user", clientTestOrgRealm, "password", config.New(), KKDCPClient(&httpClient))
	_, err := cl.sendKKDCP("https://proxy.example.org/KdcProxy", clientTestOrgRealm, []byte("request"))
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
		http.Redirect(w, new(http.Request), destination.URL, http.StatusTemporaryRedirect)
	}))
	defer proxy.Close()
	cl := NewWithPassword("user", clientTestOrgRealm, "password", config.New(), KKDCPClient(proxy.Client()))
	if _, err := cl.sendKKDCP(proxy.URL, clientTestOrgRealm, []byte("request")); err == nil {
		t.Fatal("KKDCP redirect was accepted")
	}
	if destinationCalls != 0 {
		t.Fatal("Kerberos request body was forwarded to a redirect destination")
	}
}

func TestKKDCPRejectsNonHTTPSURL(t *testing.T) {
	cl := NewWithPassword("user", clientTestOrgRealm, "password", config.New())
	if _, err := cl.sendKKDCP("http://proxy.example.org/KdcProxy", clientTestOrgRealm, []byte("request")); err == nil {
		t.Fatal("non-HTTPS KKDCP URL was accepted")
	}
}

func TestKKDCPPasswordTransport(t *testing.T) {
	var principal types.PrincipalName
	kdcErr := messages.NewKRBError(principal, clientTestOrgRealm, errorcode.KRB_ERR_GENERIC, "password response")
	kdcErr.EData = []byte{0, 0}
	krbErrorBytes, err := kdcErr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	passwordReply := make([]byte, 6+len(krbErrorBytes))
	length, err := clientUint16FromInt("KKDCP password reply length", len(passwordReply))
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(passwordReply[0:2], length)
	binary.BigEndian.PutUint16(passwordReply[2:4], 1)
	copy(passwordReply[6:], krbErrorBytes)

	server := httptest.NewTLSServer(kkdcpPasswordTestHandler(t, passwordReply))
	defer server.Close()

	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	var realm config.Realm
	realm.Realm = clientTestOrgRealm
	realm.KPasswdServer = []string{server.URL}
	cfg.Realms = []config.Realm{realm}
	cl := NewWithPassword("user", clientTestOrgRealm, "password", cfg, KKDCPClient(server.Client()))
	var passwordRequest kadmin.Request
	reply, err := cl.sendToKPasswd(passwordRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !reply.IsKRBError || reply.ResultCode != KRB5_KPASSWD_SUCCESS {
		t.Fatalf("unexpected password reply: %#v", reply)
	}
}

func kkdcpPasswordTestHandler(t *testing.T, passwordReply []byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
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
	}
}
