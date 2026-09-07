package spnego

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/goidentity/v6"
	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/service"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
)

type coverageSessionManager struct {
	value  []byte
	getErr error
	newErr error
	saved  []byte
}

func (manager *coverageSessionManager) Get(*http.Request, string) ([]byte, error) {
	return manager.value, manager.getErr
}

func (manager *coverageSessionManager) New(_ http.ResponseWriter, _ *http.Request, _ string, value []byte) error {
	manager.saved = append([]byte(nil), value...)
	return manager.newErr
}

func (*testMechanismContext) Credentials() *credentials.Credentials {
	credential := credentials.New("http-user", "EXAMPLE.COM")
	credential.SetAuthenticated(true)
	return credential
}

func TestLegacyHTTPHelperResponses(t *testing.T) {
	mechanism := SPNEGOService(keytab.New())
	request := httptest.NewRequest(http.MethodGet, "http://server.example.org", nil)

	if _, err := SetSPNEGOHeaderWithOptions(nil, request, "HTTP/server.example.org", KRB5TokenAPREQOptions{GSSAPIFlags: []int{gssapi.ContextFlagDCEStyle}}); err == nil {
		t.Fatal("DCE-style HTTP exchange was accepted")
	}
	localClient := client.NewWithPassword("alice", "EXAMPLE.ORG", "password", config.New())
	if err := SetSPNEGOHeader(localClient, request, "HTTP/server.example.org"); err == nil {
		t.Fatal("unconfigured client returned no error")
	}

	missing := httptest.NewRecorder()
	if token, err := getAuthorizationNegotiationHeaderAsSPNEGOToken(mechanism, request, missing); token != nil || err == nil || missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing authorization = %v, %v, %d", token, err, missing.Code)
	}
	request.Header.Set(HTTPHeaderAuthRequest, "Negotiate !!!")
	invalid := httptest.NewRecorder()
	if token, err := getAuthorizationNegotiationHeaderAsSPNEGOToken(mechanism, request, invalid); token != nil || err == nil || invalid.Code != http.StatusUnauthorized || invalid.Header().Get(HTTPHeaderAuthResponse) != spnegoNegTokenRespIncompleteKRB5 {
		t.Fatalf("invalid authorization = %v, %v, %d, %q", token, err, invalid.Code, invalid.Header().Get(HTTPHeaderAuthResponse))
	}
	if _, err := getSessionCredentials(mechanism, request); err == nil {
		t.Fatal("missing session manager returned credentials")
	}
	identity := credentials.New("alice", "EXAMPLE.ORG")
	if err := newSession(mechanism, request, httptest.NewRecorder(), identity); err != nil {
		t.Fatal(err)
	}

	continueResponse := httptest.NewRecorder()
	spnegoNegotiateKRB5MechType(mechanism, continueResponse, "continue")
	if continueResponse.Code != http.StatusUnauthorized || continueResponse.Header().Get(HTTPHeaderAuthResponse) != spnegoNegTokenRespIncompleteKRB5 {
		t.Fatalf("continue response = %d/%q", continueResponse.Code, continueResponse.Header().Get(HTTPHeaderAuthResponse))
	}
	rejectResponse := httptest.NewRecorder()
	spnegoResponseReject(mechanism, rejectResponse, "reject")
	if rejectResponse.Code != http.StatusUnauthorized || rejectResponse.Header().Get(HTTPHeaderAuthResponse) != spnegoNegTokenRespReject {
		t.Fatalf("reject response = %d/%q", rejectResponse.Code, rejectResponse.Header().Get(HTTPHeaderAuthResponse))
	}
	acceptResponse := httptest.NewRecorder()
	spnegoResponseAcceptCompleted(mechanism, acceptResponse, "accept")
	if acceptResponse.Header().Get(HTTPHeaderAuthResponse) != spnegoNegTokenRespKRBAcceptCompleted {
		t.Fatalf("accept response = %q", acceptResponse.Header().Get(HTTPHeaderAuthResponse))
	}
	internalResponse := httptest.NewRecorder()
	spnegoInternalServerError(mechanism, internalResponse, "failure")
	if internalResponse.Code != http.StatusInternalServerError {
		t.Fatalf("internal response = %d", internalResponse.Code)
	}
}

func TestLegacyHTTPSessionPaths(t *testing.T) {
	identity := credentials.New("alice", "EXAMPLE.ORG")
	identity.SetAuthenticated(true)
	encoded, err := identity.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	manager := &coverageSessionManager{value: encoded}
	mechanism := SPNEGOService(keytab.New(), service.SessionManager(manager))
	request := httptest.NewRequest(http.MethodGet, "http://server.example.org", nil)
	got, err := getSessionCredentials(mechanism, request)
	if err != nil || !got.Authenticated() || got.UserName() != "alice" {
		t.Fatalf("session credentials = %+v, %v", got, err)
	}
	manager.value = []byte("malformed")
	if _, err := getSessionCredentials(mechanism, request); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed session error = %v", err)
	}
	manager.value = nil
	manager.getErr = errors.New("store unavailable")
	if _, err := getSessionCredentials(mechanism, request); err == nil || !strings.Contains(err.Error(), "getting session") {
		t.Fatalf("session lookup error = %v", err)
	}

	manager.getErr = nil
	manager.newErr = errors.New("save failed")
	response := httptest.NewRecorder()
	if err := newSession(mechanism, request, response, identity); err == nil || response.Code != http.StatusInternalServerError {
		t.Fatalf("session creation = %v, status %d", err, response.Code)
	}
	manager.newErr = nil
	if err := newSession(mechanism, request, httptest.NewRecorder(), identity); err != nil || len(manager.saved) == 0 {
		t.Fatalf("successful session creation = %v, bytes %d", err, len(manager.saved))
	}
}

func TestLegacyHTTPMiddlewareUsesAuthenticatedSession(t *testing.T) {
	identity := credentials.New("alice", "EXAMPLE.ORG")
	identity.SetAuthenticated(true)
	encoded, err := identity.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, remoteAddress := range []string{"192.0.2.1:1234", "malformed"} {
		t.Run(remoteAddress, func(t *testing.T) {
			manager := &coverageSessionManager{value: encoded}
			called := false
			handler := SPNEGOKRB5Authenticate(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				called = true
				writer.WriteHeader(http.StatusNoContent)
			}), keytab.New(), service.SessionManager(manager))
			request := httptest.NewRequest(http.MethodGet, "http://server.example.org", nil)
			request.RemoteAddr = remoteAddress
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if !called || response.Code != http.StatusNoContent {
				t.Fatalf("session bypass = called %v, status %d", called, response.Code)
			}
		})
	}
}

func TestLegacyHTTPMiddlewareAuthenticatesAndCreatesSession(t *testing.T) {
	_, _, initial := newContextExchange(t, []int{gssapi.ContextFlagInteg})
	tokenBytes, err := initial.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	keytabBytes, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	if err != nil {
		t.Fatal(err)
	}
	kt := keytab.New()
	if err := kt.Unmarshal(keytabBytes); err != nil {
		t.Fatal(err)
	}
	manager := new(coverageSessionManager)
	called := false
	handler := SPNEGOKRB5Authenticate(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called = true
		identity := goidentity.FromHTTPRequestContext(request)
		if identity == nil || !identity.Authenticated() {
			t.Fatalf("authenticated identity missing from request context: %#v", identity)
		}
		writer.WriteHeader(http.StatusNoContent)
	}), kt, service.SessionManager(manager), service.DecodePAC(false))
	request := httptest.NewRequest(http.MethodGet, "http://server.example", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set(HTTPHeaderAuthRequest, "Negotiate "+base64.StdEncoding.EncodeToString(tokenBytes))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !called || response.Code != http.StatusNoContent || len(manager.saved) == 0 {
		t.Fatalf("authenticated request = called %v, status %d, session bytes %d", called, response.Code, len(manager.saved))
	}
	if response.Header().Get(HTTPHeaderAuthResponse) == "" {
		t.Fatal("successful response omitted the SPNEGO completion token")
	}
}

func TestNegotiatingClientHTTPExchange(t *testing.T) {
	acceptor := NewNegotiator(newTestContextMechanism(1, "http"))
	var mu sync.Mutex
	var bodies []string
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		mu.Lock()
		bodies = append(bodies, string(body))
		requests++
		attempt := requests
		mu.Unlock()

		if attempt == 1 {
			if request.Header.Get(HTTPHeaderAuthRequest) != "" {
				t.Error("initial request unexpectedly had authorization")
			}
			http.SetCookie(writer, &http.Cookie{Name: contextHTTPExchangeCookie, Value: "exchange-id"})
			writer.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			http.Error(writer, UnauthorizedMsg, http.StatusUnauthorized)
			return
		}
		cookie, err := request.Cookie(contextHTTPExchangeCookie)
		if err != nil || cookie.Value != "exchange-id" {
			t.Errorf("exchange cookie = %v, %v", cookie, err)
		}
		input, present, err := decodeNegotiateHeader(request.Header.Get(HTTPHeaderAuthRequest))
		if err != nil || !present || len(input) == 0 {
			t.Errorf("authorization header: present=%v len=%d err=%v", present, len(input), err)
			http.Error(writer, "bad authorization", http.StatusBadRequest)
			return
		}
		output, _, done, err := acceptor.AcceptSecContext(input)
		if err != nil || !done {
			t.Errorf("accept context: done=%v err=%v", done, err)
			http.Error(writer, "accept failed", http.StatusBadRequest)
			return
		}
		writer.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey+" "+base64.StdEncoding.EncodeToString(output))
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	factoryCalls := 0
	client := NewNegotiatingClient(server.Client(), "HTTP/server.example", func() gssapi.ContextMechanism {
		factoryCalls++
		return newTestContextMechanism(1, "http")
	})
	request, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("request body"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || client.Context() == nil {
		t.Fatalf("status/context = %d/%v", response.StatusCode, client.Context())
	}
	if factoryCalls != 1 || requests != 2 {
		t.Fatalf("factory/requests = %d/%d", factoryCalls, requests)
	}
	if len(bodies) != 2 || bodies[0] != "request body" || bodies[1] != "request body" {
		t.Fatalf("request bodies = %q", bodies)
	}
}

func TestNegotiatingClientProtocolGuards(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "http://server.example", nil)
	if _, err := NewNegotiatingClient(nil, "service", nil).Do(request); err == nil || !strings.Contains(err.Error(), "factory is required") {
		t.Fatalf("nil factory error = %v", err)
	}
	if _, err := NewNegotiatingClient(nil, "service", func() gssapi.ContextMechanism { return nil }).Do(request); err == nil || !strings.Contains(err.Error(), "returned nil") {
		t.Fatalf("nil mechanism error = %v", err)
	}

	response := func(status int, challenge string) *http.Response {
		header := make(http.Header)
		if challenge != "" {
			header.Set(HTTPHeaderAuthResponse, challenge)
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader("body"))}
	}
	tests := map[string]struct {
		transport negotiatingRoundTripFunc
		want      string
	}{
		"missing challenge": {
			transport: func(*http.Request) (*http.Response, error) { return response(http.StatusUnauthorized, ""), nil },
			want:      "does not advertise",
		},
		"malformed challenge": {
			transport: func(*http.Request) (*http.Response, error) {
				return response(http.StatusUnauthorized, "Negotiate !!!"), nil
			},
			want: "decode HTTP Negotiate",
		},
		"premature success": {
			transport: func(current *http.Request) (*http.Response, error) {
				if current.Header.Get(HTTPHeaderAuthRequest) == "" {
					return response(http.StatusUnauthorized, HTTPHeaderAuthResponseValueKey), nil
				}
				return response(http.StatusOK, ""), nil
			},
			want: "without mutual",
		},
		"completed mechanism on unauthorized response": {
			transport: func() negotiatingRoundTripFunc {
				acceptor := NewNegotiator(newTestContextMechanism(1, "guard"))
				return func(current *http.Request) (*http.Response, error) {
					if current.Header.Get(HTTPHeaderAuthRequest) == "" {
						return response(http.StatusUnauthorized, HTTPHeaderAuthResponseValueKey), nil
					}
					input, _, err := decodeNegotiateHeader(current.Header.Get(HTTPHeaderAuthRequest))
					if err != nil {
						return nil, err
					}
					output, _, _, err := acceptor.AcceptSecContext(input)
					if err != nil {
						return nil, err
					}
					return response(http.StatusUnauthorized, "Negotiate "+base64.StdEncoding.EncodeToString(output)), nil
				}
			}(),
			want: "no HTTP continuation token",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := NewNegotiatingClient(&http.Client{Transport: test.transport}, "service", func() gssapi.ContextMechanism {
				return newTestContextMechanism(1, "guard")
			})
			current, _ := http.NewRequest(http.MethodGet, "http://server.example", nil)
			if _, err := client.Do(current); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("protocol guard error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSPNEGOContextHTTPExchange(t *testing.T) {
	innerCalls := 0
	handler := SPNEGOContextAuthenticate(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		innerCalls++
		writer.WriteHeader(http.StatusNoContent)
	}), func() gssapi.ContextMechanism {
		return newTestContextMechanism(1, "context-http")
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewNegotiatingClient(server.Client(), "HTTP/server.example", func() gssapi.ContextMechanism {
		return newTestContextMechanism(1, "context-http")
	})
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || innerCalls != 1 {
		t.Fatalf("status/inner calls = %d/%d", response.StatusCode, innerCalls)
	}
	if client.Context() == nil {
		t.Fatal("client did not retain established context")
	}
	if got := response.Header.Get(HTTPHeaderAuthResponse); !strings.HasPrefix(got, HTTPHeaderAuthResponseValueKey+" ") {
		t.Fatalf("final authentication header = %q", got)
	}
	expired := false
	for _, cookie := range response.Cookies() {
		if cookie.Name == contextHTTPExchangeCookie && cookie.MaxAge < 0 {
			expired = true
		}
	}
	if !expired {
		t.Fatal("server did not expire the exchange cookie")
	}
}

func TestSPNEGOContextAuthenticateRejectsInvalidExchanges(t *testing.T) {
	initial, _, _, err := NewNegotiator(newTestContextMechanism(1, "http")).InitSecContext("target", nil)
	if err != nil {
		t.Fatal(err)
	}
	authorization := HTTPHeaderAuthResponseValueKey + " " + base64.StdEncoding.EncodeToString(initial)
	tests := []struct {
		name    string
		header  string
		factory ContextMechanismFactory
	}{
		{name: "missing authorization", factory: func() gssapi.ContextMechanism { return newTestContextMechanism(1, "http") }},
		{name: "invalid authorization", header: "Negotiate !!!", factory: func() gssapi.ContextMechanism { return newTestContextMechanism(1, "http") }},
		{name: "nil factory", header: authorization},
		{name: "nil mechanism", header: authorization, factory: func() gssapi.ContextMechanism { return nil }},
		{name: "mechanism failure", header: authorization, factory: func() gssapi.ContextMechanism { return newTestContextMechanism(1, "other") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := SPNEGOContextAuthenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("inner handler called")
			}), test.factory)
			request := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
			request.Header.Set(HTTPHeaderAuthRequest, test.header)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
}

type negotiatingRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip negotiatingRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type failingReadCloser struct {
	readErr  error
	closeErr error
}

func (closer failingReadCloser) Read([]byte) (int, error) {
	if closer.readErr == nil {
		return 0, io.EOF
	}
	return 0, closer.readErr
}
func (closer failingReadCloser) Close() error { return closer.closeErr }

func TestNegotiatingClientErrors(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	client := NewNegotiatingClient(nil, "target", nil)
	if _, err := client.Do(request); err == nil || !strings.Contains(err.Error(), "factory is required") {
		t.Fatalf("nil factory error = %v", err)
	}
	client = NewNegotiatingClient(nil, "target", func() gssapi.ContextMechanism { return nil })
	if _, err := client.Do(request); err == nil || !strings.Contains(err.Error(), "returned nil") {
		t.Fatalf("nil mechanism error = %v", err)
	}

	tests := []struct {
		name       string
		challenge  string
		wantErr    string
		statusCode int
	}{
		{name: "missing Negotiate", challenge: "Basic", wantErr: "does not advertise Negotiate", statusCode: http.StatusUnauthorized},
		{name: "malformed challenge", challenge: "Negotiate one two", wantErr: "invalid HTTP Negotiate challenge", statusCode: http.StatusUnauthorized},
		{name: "invalid base64", challenge: "Negotiate !!!", wantErr: "decode HTTP Negotiate challenge", statusCode: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			httpClient := &http.Client{Transport: negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set(HTTPHeaderAuthResponse, test.challenge)
				return &http.Response{
					StatusCode: test.statusCode,
					Header:     header,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			})}
			client := NewNegotiatingClient(httpClient, "target", func() gssapi.ContextMechanism {
				return newTestContextMechanism(1, "http")
			})
			if _, err := client.Do(request); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestNegotiatingClientTransportAndRoundLimit(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	transportErr := errors.New("transport failed")
	client := NewNegotiatingClient(&http.Client{Transport: negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})}, "target", func() gssapi.ContextMechanism { return newTestContextMechanism(1, "http") })
	if _, err := client.Do(request); !errors.Is(err, transportErr) {
		t.Fatalf("transport error = %v", err)
	}

	challenge, err := marshalSPNEGOToken(&SPNEGOToken{Resp: true, NegTokenResp: NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
		SupportedMech: newTestContextMechanism(1, "http").OID(),
		ResponseToken: []byte("http-challenge"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	httpClient := &http.Client{Transport: negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		header := make(http.Header)
		if calls == 1 {
			header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		} else {
			header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey+" "+base64.StdEncoding.EncodeToString(challenge))
		}
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: header, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})}
	client = NewNegotiatingClient(httpClient, "target", func() gssapi.ContextMechanism {
		return newTestContextMechanism(1, "http")
	})
	if _, err := client.Do(request); err == nil || !strings.Contains(err.Error(), "exceeded 10 round trips") {
		t.Fatalf("round limit error = %v", err)
	}
	if calls != 10 {
		t.Fatalf("HTTP attempts = %d", calls)
	}
}

func TestNegotiationRequestAndHeaderHelpers(t *testing.T) {
	request, _ := http.NewRequest(http.MethodPost, "http://example.test", io.NopCloser(strings.NewReader("body")))
	if _, err := cloneNegotiationRequest(request, 1); err == nil || !strings.Contains(err.Error(), "cannot be replayed") {
		t.Fatalf("non-replayable body error = %v", err)
	}
	getBodyErr := errors.New("get body failed")
	request.GetBody = func() (io.ReadCloser, error) { return nil, getBodyErr }
	if _, err := cloneNegotiationRequest(request, 1); !errors.Is(err, getBodyErr) {
		t.Fatalf("GetBody error = %v", err)
	}

	for _, value := range []string{"", "Basic abc"} {
		decoded, present, err := decodeNegotiateHeader(value)
		if err != nil || present || decoded != nil {
			t.Fatalf("decodeNegotiateHeader(%q) = %x, %v, %v", value, decoded, present, err)
		}
	}
	decoded, present, err := decodeNegotiateHeader("nEgOtIaTe")
	if err != nil || !present || decoded != nil {
		t.Fatalf("bare Negotiate = %x, %v, %v", decoded, present, err)
	}
}

func TestLegacyHTTPClientMethodsWithoutChallenge(t *testing.T) {
	type receivedRequest struct {
		method      string
		body        string
		contentType string
	}
	var received []receivedRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		received = append(received, receivedRequest{
			method: request.Method, body: string(body), contentType: request.Header.Get("Content-Type"),
		})
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(nil, server.Client(), "HTTP/server.example")
	responses := make([]*http.Response, 0, 4)
	response, err := client.Get(server.URL + "/get")
	if err != nil {
		t.Fatal(err)
	}
	responses = append(responses, response)
	response, err = client.Post(server.URL+"/post", "text/plain", strings.NewReader("post body"))
	if err != nil {
		t.Fatal(err)
	}
	responses = append(responses, response)
	response, err = client.PostForm(server.URL+"/form", map[string][]string{"key": {"value"}})
	if err != nil {
		t.Fatal(err)
	}
	responses = append(responses, response)
	response, err = client.Head(server.URL + "/head")
	if err != nil {
		t.Fatal(err)
	}
	responses = append(responses, response)
	for _, response := range responses {
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d", response.StatusCode)
		}
		response.Body.Close()
	}
	if len(received) != 4 || received[0].method != http.MethodGet || received[1].body != "post body" ||
		received[2].body != "key=value" || received[3].method != http.MethodHead {
		t.Fatalf("received requests = %+v", received)
	}
	if received[1].contentType != "text/plain" || received[2].contentType != "application/x-www-form-urlencoded" {
		t.Fatalf("content types = %q/%q", received[1].contentType, received[2].contentType)
	}
}

func TestLegacyHTTPHelpers(t *testing.T) {
	client := NewClientWithOptions(nil, nil, "service", KRB5TokenAPREQOptions{})
	if client.Jar == nil || client.CheckRedirect == nil {
		t.Fatal("default HTTP client was not initialized")
	}
	redirectRequest, _ := http.NewRequest(http.MethodGet, "http://example.test/next", nil)
	if err := client.CheckRedirect(redirectRequest, nil); err == nil || !strings.Contains(err.Error(), "redirect to") {
		t.Fatalf("redirect error = %v", err)
	}

	unauthorized := &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header)}
	unauthorized.Header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
	if !respUnauthorizedNegotiate(unauthorized) {
		t.Fatal("Negotiate challenge was not recognized")
	}
	unauthorized.StatusCode = http.StatusOK
	if respUnauthorizedNegotiate(unauthorized) {
		t.Fatal("successful response treated as an authentication challenge")
	}

	request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/path", nil)
	principal, err := setRequestSPN(request)
	if err != nil || !strings.HasPrefix(principal.PrincipalNameString(), "HTTP/") || request.Host == "" {
		t.Fatalf("SPN/host/error = %q/%q/%v", principal.PrincipalNameString(), request.Host, err)
	}
	request.URL.Host = "host:port:extra"
	if _, err := setRequestSPN(request); err == nil {
		t.Fatal("malformed host accepted")
	}

	response := &http.Response{Header: make(http.Header)}
	if token, err := responseSPNEGOToken(response); err != nil || token != nil {
		t.Fatalf("missing response token = %v, %v", token, err)
	}
	response.Header.Set(HTTPHeaderAuthResponse, "Negotiate !!!")
	if _, err := responseSPNEGOToken(response); err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Fatalf("invalid response token error = %v", err)
	}
}

func TestLegacyHTTPClientChallengeAndRedirectGuards(t *testing.T) {
	request, _ := http.NewRequest(http.MethodPost, "http://example.test/start", strings.NewReader("body"))
	httpClient := &http.Client{Transport: negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: header, Body: io.NopCloser(strings.NewReader("challenge"))}, nil
	})}
	legacy := NewClient(client.NewWithPassword("alice", "EXAMPLE.ORG", "password", config.New()), httpClient, "HTTP/server.example.org")
	if _, err := legacy.Do(request); err == nil || !strings.Contains(err.Error(), "acquire client credential") {
		t.Fatalf("challenge error = %v", err)
	}

	redirects := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		redirects++
		http.Redirect(writer, request, "/next", http.StatusFound)
	}))
	defer server.Close()
	legacy = NewClient(nil, server.Client(), "HTTP/server.example.org")
	request, _ = http.NewRequest(http.MethodPost, server.URL, strings.NewReader("body"))
	if _, err := legacy.Do(request); err == nil || !strings.Contains(err.Error(), "10 redirects") {
		t.Fatalf("redirect limit error = %v", err)
	}
	if redirects != 10 {
		t.Fatalf("redirect requests = %d", redirects)
	}
}

func TestLegacyHTTPClientClearsContextBeforeNegotiation(t *testing.T) {
	initiator, _, _ := newContextExchange(t, []int{gssapi.ContextFlagInteg})
	httpClient := &http.Client{Transport: negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: header, Body: http.NoBody}, nil
	})}
	legacy := NewClient(client.NewWithPassword("alice", "EXAMPLE.ORG", "password", config.New()), httpClient, "HTTP/server.example.org")
	legacy.setContext(initiator.SecurityContext())
	if legacy.Context() == nil {
		t.Fatal("initial context is nil")
	}

	request, requestErr := http.NewRequest(http.MethodGet, "http://example.test", nil)
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	_, err := legacy.Do(request)
	if err == nil {
		t.Fatal("negotiation unexpectedly succeeded")
	}
	if legacy.Context() != nil {
		t.Fatal("stale context was not cleared")
	}
}

func TestLegacyHTTPMutualAndBodyFailureGuards(t *testing.T) {
	readErr := errors.New("read failed")
	closeErr := errors.New("close failed")
	if err := discardAndClose(failingReadCloser{readErr: readErr, closeErr: closeErr}); err == nil || !strings.Contains(err.Error(), "close also failed") {
		t.Fatalf("combined body error = %v", err)
	}
	if err := discardAndClose(failingReadCloser{readErr: nil, closeErr: closeErr}); !errors.Is(err, closeErr) {
		t.Fatalf("close error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	response := &http.Response{Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil))}
	legacy := NewClientWithOptions(nil, nil, "service", KRB5TokenAPREQOptions{GSSAPIFlags: []int{gssapi.ContextFlagMutual}})
	legacy.contexts.Store(request, SPNEGOService(keytab.New()))
	if err := legacy.verifyMutualResponse(request, response); err == nil || !strings.Contains(err.Error(), "did not return") {
		t.Fatalf("missing mutual token error = %v", err)
	}
	legacy.contexts.Store(request, SPNEGOService(keytab.New()))
	response.Header.Set(HTTPHeaderAuthResponse, "Negotiate !!!")
	if err := legacy.verifyMutualResponse(request, response); err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Fatalf("invalid mutual token error = %v", err)
	}
}

func TestLegacySPNEGOHandlerUnauthenticatedRequests(t *testing.T) {
	innerCalls := 0
	handler := SPNEGOKRB5Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		innerCalls++
	}), keytab.New())
	for _, remoteAddr := range []string{"192.0.2.1:1234", "malformed"} {
		request := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
		request.RemoteAddr = remoteAddr
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || response.Header().Get(HTTPHeaderAuthResponse) != HTTPHeaderAuthResponseValueKey {
			t.Fatalf("unauthenticated response for %q = %d/%q", remoteAddr, response.Code, response.Header().Get(HTTPHeaderAuthResponse))
		}
	}
	if innerCalls != 0 {
		t.Fatalf("inner handler calls = %d", innerCalls)
	}
}
