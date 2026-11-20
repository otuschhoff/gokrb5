package spnego

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jcmturner/goidentity/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	{
		var options KRB5TokenAPREQOptions
		options.GSSAPIFlags = []int{gssapi.ContextFlagDCEStyle}
		_, err := SetSPNEGOHeaderWithOptions(nil, request, "HTTP/server.example.org", options)
		require.Error(t, err)
	}
	localClient := client.NewWithPassword("alice", "EXAMPLE.ORG", "password", config.New())
	{
		err := SetSPNEGOHeader(localClient, request, "HTTP/server.example.org")
		require.Error(t, err)
	}

	missing := httptest.NewRecorder()
	{
		token, err := getAuthorizationNegotiationHeaderAsSPNEGOToken(mechanism, request, missing)
		require.Nil(t, token)
		require.Error(t, err)
		require.Equal(t, http.StatusUnauthorized, missing.Code)
	}
	request.Header.Set(HTTPHeaderAuthRequest, malformedNegotiateHeader)
	invalid := httptest.NewRecorder()
	{
		token, err := getAuthorizationNegotiationHeaderAsSPNEGOToken(mechanism, request, invalid)
		require.Nil(t, token)
		require.Error(t, err)
		require.Equal(t, http.StatusUnauthorized, invalid.Code)
		require.Equal(t, spnegoNegTokenRespIncompleteKRB5, invalid.Header().Get(HTTPHeaderAuthResponse))
	}
	{
		_, err := getSessionCredentials(mechanism, request)
		require.Error(t, err)
	}
	identity := credentials.New("alice", "EXAMPLE.ORG")
	{
		err := newSession(mechanism, request, httptest.NewRecorder(), identity)
		require.NoError(t, err)
	}

	continueResponse := httptest.NewRecorder()
	spnegoNegotiateKRB5MechType(mechanism, continueResponse, "continue")
	require.Equal(t, http.StatusUnauthorized, continueResponse.Code)
	require.Equal(t, spnegoNegTokenRespIncompleteKRB5, continueResponse.Header().Get(HTTPHeaderAuthResponse))
	rejectResponse := httptest.NewRecorder()
	spnegoResponseReject(mechanism, rejectResponse, "reject")
	require.Equal(t, http.StatusUnauthorized, rejectResponse.Code)
	require.Equal(t, spnegoNegTokenRespReject, rejectResponse.Header().Get(HTTPHeaderAuthResponse))
	acceptResponse := httptest.NewRecorder()
	spnegoResponseAcceptCompleted(mechanism, acceptResponse, "accept")
	require.Equal(t, spnegoNegTokenRespKRBAcceptCompleted, acceptResponse.Header().Get(HTTPHeaderAuthResponse))
	internalResponse := httptest.NewRecorder()
	spnegoInternalServerError(mechanism, internalResponse, "failure")
	require.Equal(t, http.StatusInternalServerError, internalResponse.Code)
}

func TestLegacyHTTPSessionPaths(t *testing.T) {
	identity := credentials.New("alice", "EXAMPLE.ORG")
	identity.SetAuthenticated(true)
	encoded, err := identity.Marshal()
	require.NoError(t, err)
	manager := &coverageSessionManager{
		getErr: nil,
		newErr: nil,
		saved:  nil,
		value:  encoded,
	}
	mechanism := SPNEGOService(keytab.New(), service.SessionManager(manager))
	request := httptest.NewRequest(http.MethodGet, "http://server.example.org", nil)
	got, err := getSessionCredentials(mechanism, request)
	require.NoError(t, err)
	require.True(t, got.Authenticated())
	require.Equal(t, "alice", got.UserName())
	manager.value = []byte("malformed")
	{
		_, err := getSessionCredentials(mechanism, request)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "malformed"))
	}
	manager.value = nil
	manager.getErr = errors.New("store unavailable")
	{
		_, err := getSessionCredentials(mechanism, request)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "getting session"))
	}

	manager.getErr = nil
	manager.newErr = errors.New("save failed")
	response := httptest.NewRecorder()
	{
		err := newSession(mechanism, request, response, identity)
		require.Error(t, err)
		require.Equal(t, http.StatusInternalServerError, response.Code)
	}
	manager.newErr = nil
	{
		err := newSession(mechanism, request, httptest.NewRecorder(), identity)
		require.NoError(t, err)
		require.False(t, len(manager.saved) == 0)
	}
}

func TestLegacyHTTPMiddlewareUsesAuthenticatedSession(t *testing.T) {
	identity := credentials.New("alice", "EXAMPLE.ORG")
	identity.SetAuthenticated(true)
	encoded, err := identity.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, remoteAddress := range []string{testRemoteAddress, "malformed"} {
		t.Run(remoteAddress, func(t *testing.T) {
			manager := &coverageSessionManager{
				getErr: nil,
				newErr: nil,
				saved:  nil,
				value:  encoded,
			}
			called := false
			handler := SPNEGOKRB5Authenticate(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
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
	request.RemoteAddr = testRemoteAddress
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
			http.SetCookie(writer, contextHTTPExchangeCookieForRequest(request, "exchange-id", 0))
			writer.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			http.Error(writer, UnauthorizedMsg, http.StatusUnauthorized)
			return
		}
		finishTestHTTPExchange(t, writer, request, acceptor)
	}))
	defer server.Close()

	factoryCalls := 0
	client := NewNegotiatingClient(server.Client(), "HTTP/server.example", func() gssapi.ContextMechanism {
		factoryCalls++
		return newTestContextMechanism(1, "http")
	})
	request, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("request body"))
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close() //nolint:errcheck // test response cleanup is intentionally best effort
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.NotNil(t, client.Context())
	require.Equal(t, 1, factoryCalls)
	require.Equal(t, 2, requests)
	require.Equal(t, 2, len(bodies))
	require.Equal(t, "request body", bodies[0])
	require.Equal(t, "request body", bodies[1])
}

func finishTestHTTPExchange(t *testing.T, writer http.ResponseWriter, request *http.Request, acceptor *Negotiator) {
	t.Helper()
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
	header := HTTPHeaderAuthResponseValueKey + " " + base64.StdEncoding.EncodeToString(output)
	writer.Header().Set(HTTPHeaderAuthResponse, header)
	writer.WriteHeader(http.StatusOK)
}

func TestNegotiatingClientRequiresFactoryAndMechanism(t *testing.T) {
	request := mustHTTPRequest(t, http.MethodGet, "http://server.example", nil)
	unexpectedResponse, err := NewNegotiatingClient(nil, "service", nil).Do(request)
	if unexpectedResponse != nil {
		_ = unexpectedResponse.Body.Close()
	}
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "factory is required"))
	nilMechanism := NewNegotiatingClient(nil, "service", func() gssapi.ContextMechanism { return nil })
	unexpectedResponse, err = nilMechanism.Do(request)
	if unexpectedResponse != nil {
		_ = unexpectedResponse.Body.Close()
	}
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "returned nil"))
}

func TestNegotiatingClientProtocolGuards(t *testing.T) {
	response := func(status int, challenge string) *http.Response {
		header := make(http.Header)
		if challenge != "" {
			header.Set(HTTPHeaderAuthResponse, challenge)
		}
		return testHTTPResponse(status, header, io.NopCloser(strings.NewReader("body")))
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
				return response(http.StatusUnauthorized, malformedNegotiateHeader), nil
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
			transport: completedUnauthorizedExchange(response),
			want:      "no HTTP continuation token",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := NewNegotiatingClient(testHTTPClient(test.transport), "service", func() gssapi.ContextMechanism {
				return newTestContextMechanism(1, "guard")
			})
			current, _ := http.NewRequest(http.MethodGet, "http://server.example", nil)
			unexpectedResponse, err := client.Do(current)
			if unexpectedResponse != nil {
				_ = unexpectedResponse.Body.Close()
			}
			require.Error(t, err)
			require.True(t, strings.Contains(err.Error(), test.want))
		})
	}
}

func completedUnauthorizedExchange(response func(int, string) *http.Response) negotiatingRoundTripFunc {
	acceptor := NewNegotiator(newTestContextMechanism(1, "guard"))
	return func(current *http.Request) (*http.Response, error) {
		header := current.Header.Get(HTTPHeaderAuthRequest)
		if header == "" {
			return response(http.StatusUnauthorized, HTTPHeaderAuthResponseValueKey), nil
		}
		input, _, err := decodeNegotiateHeader(header)
		if err != nil {
			return nil, err
		}
		output, _, _, err := acceptor.AcceptSecContext(input)
		if err != nil {
			return nil, err
		}
		return response(http.StatusUnauthorized, "Negotiate "+base64.StdEncoding.EncodeToString(output)), nil
	}
}

func TestContextHTTPExchangeCookieAttributes(t *testing.T) {
	httpsRequest := mustHTTPRequest(t, http.MethodGet, "https://server.example", nil)
	httpsRequest.TLS = new(tls.ConnectionState)
	cookie := contextHTTPExchangeCookieForRequest(httpsRequest, "exchange", 60)
	require.True(t, cookie.HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	require.True(t, cookie.Secure)
	require.Equal(t, "/", cookie.Path)
	require.Equal(t, 60, cookie.MaxAge)
	httpRequest := mustHTTPRequest(t, http.MethodGet, "http://server.example", nil)
	if contextHTTPExchangeCookieForRequest(httpRequest, "exchange", 60).Secure {
		t.Fatal("plaintext HTTP exchange cookie unexpectedly marked Secure")
	}
}

func TestSPNEGOContextHTTPExchange(t *testing.T) {
	innerCalls := 0
	handler := SPNEGOContextAuthenticate(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		innerCalls++
		writer.WriteHeader(http.StatusNoContent)
	}), func() gssapi.ContextMechanism {
		return newTestContextMechanism(1, "context-http")
	})
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	client := NewNegotiatingClient(server.Client(), "HTTP/server.example", func() gssapi.ContextMechanism {
		return newTestContextMechanism(1, "context-http")
	})
	request := mustHTTPRequest(t, http.MethodGet, server.URL, nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck // test response cleanup is intentionally best effort
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
		{
			header: "",
			name:   "missing authorization", factory: func() gssapi.ContextMechanism {
				return newTestContextMechanism(
					1,
					"http",
				)
			},
		},
		{
			name:    "invalid authorization",
			header:  malformedNegotiateHeader,
			factory: func() gssapi.ContextMechanism { return newTestContextMechanism(1, "http") },
		},
		{
			factory: nil,
			name:    "nil factory", header: authorization,
		},
		{name: "nil mechanism", header: authorization, factory: func() gssapi.ContextMechanism { return nil }},
		{
			name:    "mechanism failure",
			header:  authorization,
			factory: func() gssapi.ContextMechanism { return newTestContextMechanism(1, "other") },
		},
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

const (
	malformedNegotiateHeader = "Negotiate !!!"
	testRemoteAddress        = "192.0.2.1:1234"
)

func testHTTPResponse(status int, header http.Header, body io.ReadCloser) *http.Response {
	response := new(http.Response)
	response.StatusCode = status
	response.Header = header
	response.Body = body
	return response
}

func testHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Transport: transport, CheckRedirect: nil, Jar: nil, Timeout: 0}
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
	request := mustHTTPRequest(t, http.MethodGet, "http://example.test", nil)
	client := NewNegotiatingClient(nil, "target", nil)
	unexpectedResponse, err := client.Do(request)
	if unexpectedResponse != nil {
		_ = unexpectedResponse.Body.Close()
	}
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "factory is required"))
	client = NewNegotiatingClient(nil, "target", func() gssapi.ContextMechanism { return nil })
	unexpectedResponse, err = client.Do(request)
	if unexpectedResponse != nil {
		_ = unexpectedResponse.Body.Close()
	}
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "returned nil"))

	tests := []struct {
		name       string
		challenge  string
		wantErr    string
		statusCode int
	}{
		{
			name:       "missing Negotiate",
			challenge:  "Basic",
			wantErr:    "does not advertise Negotiate",
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "malformed challenge",
			challenge:  "Negotiate one two",
			wantErr:    "invalid HTTP Negotiate challenge",
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "invalid base64",
			challenge:  malformedNegotiateHeader,
			wantErr:    "decode HTTP Negotiate challenge",
			statusCode: http.StatusUnauthorized,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			httpClient := testHTTPClient(negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set(HTTPHeaderAuthResponse, test.challenge)
				return testHTTPResponse(test.statusCode, header, io.NopCloser(bytes.NewReader(nil))), nil
			}))
			client := NewNegotiatingClient(httpClient, "target", func() gssapi.ContextMechanism {
				return newTestContextMechanism(1, "http")
			})
			unexpectedResponse, err := client.Do(request)
			if unexpectedResponse != nil {
				_ = unexpectedResponse.Body.Close()
			}
			require.Error(t, err)
			require.True(t, strings.Contains(err.Error(), test.wantErr))
		})
	}
}

func TestNegotiatingClientTransportAndRoundLimit(t *testing.T) {
	request := mustHTTPRequest(t, http.MethodGet, "http://example.test", nil)
	transportErr := errors.New("transport failed")
	client := NewNegotiatingClient(testHTTPClient(negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})), "target", func() gssapi.ContextMechanism { return newTestContextMechanism(1, "http") })
	unexpectedResponse, err := client.Do(request)
	if unexpectedResponse != nil {
		_ = unexpectedResponse.Body.Close()
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("transport error = %v", err)
	}

	challenge, err := marshalMechanismResponse(mechanismResponse(
		NegStateAcceptIncomplete, newTestContextMechanism(1, "http").OID(), []byte("http-challenge"),
	))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	httpClient := testHTTPClient(negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		header := make(http.Header)
		if calls == 1 {
			header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		} else {
			header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey+" "+base64.StdEncoding.EncodeToString(challenge))
		}
		return testHTTPResponse(http.StatusUnauthorized, header, io.NopCloser(bytes.NewReader(nil))), nil
	}))
	client = NewNegotiatingClient(httpClient, "target", func() gssapi.ContextMechanism {
		return newTestContextMechanism(1, "http")
	})
	unexpectedResponse, err = client.Do(request)
	if unexpectedResponse != nil {
		_ = unexpectedResponse.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "exceeded 10 round trips") {
		t.Fatalf("round limit error = %v", err)
	}
	if calls != 10 {
		t.Fatalf("HTTP attempts = %d", calls)
	}
}

func TestNegotiationRequestAndHeaderHelpers(t *testing.T) {
	request := mustHTTPRequest(t, http.MethodPost, "http://example.test", io.NopCloser(strings.NewReader("body")))
	{
		_, err := cloneNegotiationRequest(request, 1)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "cannot be replayed"))
	}
	getBodyErr := errors.New("get body failed")
	request.GetBody = func() (io.ReadCloser, error) { return nil, getBodyErr }
	{
		_, err := cloneNegotiationRequest(request, 1)
		require.True(t, errors.Is(err, getBodyErr))
	}

	for _, value := range []string{"", "Basic abc"} {
		decoded, present, err := decodeNegotiateHeader(value)
		require.NoError(t, err)
		require.False(t, present)
		require.Nil(t, decoded)
	}
	decoded, present, err := decodeNegotiateHeader("nEgOtIaTe")
	require.NoError(t, err)
	require.True(t, present)
	require.Nil(t, decoded)
}

func TestLegacyHTTPClientMethodsWithoutChallenge(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		method      string
		body        string
		contentType string
		send        func(*Client, string) (*http.Response, error)
	}{
		{name: "get", path: "/get", method: http.MethodGet, body: "", contentType: "", send: (*Client).Get},
		{
			name: "post", path: "/post", method: http.MethodPost, body: "post body", contentType: "text/plain",
			send: func(c *Client, target string) (*http.Response, error) {
				return c.Post(target, "text/plain", strings.NewReader("post body"))
			},
		},
		{
			name: "post form", path: "/form", method: http.MethodPost, body: "key=value",
			contentType: "application/x-www-form-urlencoded",
			send: func(c *Client, target string) (*http.Response, error) {
				return c.PostForm(target, map[string][]string{"key": {"value"}})
			},
		},
		{name: "head", path: "/head", method: http.MethodHead, body: "", contentType: "", send: (*Client).Head},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				body, readErr := io.ReadAll(request.Body)
				assert.NoError(t, readErr)
				assert.Equal(t, tt.method, request.Method)
				assert.Equal(t, tt.path, request.URL.Path)
				assert.Equal(t, tt.body, string(body))
				assert.Equal(t, tt.contentType, request.Header.Get("Content-Type"))
				assert.Empty(t, request.Header.Get(HTTPHeaderAuthRequest))
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			c := NewClient(nil, server.Client(), "HTTP/server.example")
			resp, err := tt.send(c, server.URL+tt.path)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
			assert.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestLegacyHTTPHelpers(t *testing.T) {
	var options KRB5TokenAPREQOptions
	client := NewClientWithOptions(nil, nil, "service", options)
	require.NotNil(t, client.Jar)
	require.NotNil(t, client.CheckRedirect)
	redirectRequest, _ := http.NewRequest(http.MethodGet, "http://example.test/next", nil)
	{
		err := client.CheckRedirect(redirectRequest, nil)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "redirect to"))
	}

	var unauthorized http.Response
	unauthorized.StatusCode = http.StatusUnauthorized
	unauthorized.Header = make(http.Header)
	unauthorized.Header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
	require.True(t, respUnauthorizedNegotiate(&unauthorized))
	unauthorized.StatusCode = http.StatusOK
	require.False(t, respUnauthorizedNegotiate(&unauthorized))

	request := mustHTTPRequest(t, http.MethodGet, "http://127.0.0.1:8080/path", nil)
	principal, err := setRequestSPN(request)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(principal.PrincipalNameString(), "HTTP/"))
	require.False(t, request.Host == "")
	request.URL.Host = "host:port:extra"
	{
		_, err := setRequestSPN(request)
		require.Error(t, err)
	}

	var response http.Response
	response.Header = make(http.Header)
	{
		_, present, err := responseSPNEGOToken(&response)
		require.NoError(t, err)
		require.False(t, present)
	}
	response.Header.Set(HTTPHeaderAuthResponse, malformedNegotiateHeader)
	{
		_, _, err := responseSPNEGOToken(&response)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "encoding"))
	}
}

func TestLegacyHTTPClientChallengeAndRedirectGuards(t *testing.T) {
	request := mustHTTPRequest(t, http.MethodPost, "http://example.test/start", strings.NewReader("body"))
	httpClient := testHTTPClient(negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		return testHTTPResponse(http.StatusUnauthorized, header, io.NopCloser(strings.NewReader("challenge"))), nil
	}))
	legacy := NewClient(
		client.NewWithPassword("alice", "EXAMPLE.ORG", "password", config.New()),
		httpClient,
		"HTTP/server.example.org",
	)
	unexpectedResponse, err := legacy.Do(request)
	if unexpectedResponse != nil {
		_ = unexpectedResponse.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "acquire client credential") {
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
	redirectResponse, err := legacy.Do(request)
	if redirectResponse != nil {
		defer redirectResponse.Body.Close() //nolint:errcheck // test response cleanup is intentionally best effort
	}
	if err == nil || !strings.Contains(err.Error(), "10 redirects") {
		t.Fatalf("redirect limit error = %v", err)
	}
	if redirects != 10 {
		t.Fatalf("redirect requests = %d", redirects)
	}
}

func TestLegacyHTTPClientClearsContextBeforeNegotiation(t *testing.T) {
	initiator, _, _ := newContextExchange(t, []int{gssapi.ContextFlagInteg})
	httpClient := testHTTPClient(negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		return testHTTPResponse(http.StatusUnauthorized, header, http.NoBody), nil
	}))
	legacy := NewClient(
		client.NewWithPassword("alice", "EXAMPLE.ORG", "password", config.New()),
		httpClient,
		"HTTP/server.example.org",
	)
	legacy.setContext(initiator.SecurityContext())
	if legacy.Context() == nil {
		t.Fatal("initial context is nil")
	}

	request, requestErr := http.NewRequest(http.MethodGet, "http://example.test", nil)
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	response, err := legacy.Do(request)
	if response != nil {
		defer response.Body.Close() //nolint:errcheck // Best-effort test cleanup.
	}
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
	if err := discardAndClose(failingReadCloser{
		readErr:  readErr,
		closeErr: closeErr,
	}); err == nil || !strings.Contains(err.Error(), "close also failed") {
		t.Fatalf("combined body error = %v", err)
	}
	if err := discardAndClose(failingReadCloser{readErr: nil, closeErr: closeErr}); !errors.Is(err, closeErr) {
		t.Fatalf("close error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	var response http.Response
	response.Header = make(http.Header)
	var options KRB5TokenAPREQOptions
	options.GSSAPIFlags = []int{gssapi.ContextFlagMutual}
	legacy := NewClientWithOptions(nil, nil, "service", options)
	legacy.contexts.Store(request, SPNEGOService(keytab.New()))
	if err := legacy.verifyMutualResponse(
		request,
		&response,
	); err == nil || !strings.Contains(err.Error(), "did not return") {
		t.Fatalf("missing mutual token error = %v", err)
	}
	legacy.contexts.Store(request, SPNEGOService(keytab.New()))
	response.Header.Set(HTTPHeaderAuthResponse, malformedNegotiateHeader)
	if err := legacy.verifyMutualResponse(request, &response); err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Fatalf("invalid mutual token error = %v", err)
	}
}

func TestLegacySPNEGOHandlerUnauthenticatedRequests(t *testing.T) {
	innerCalls := 0
	handler := SPNEGOKRB5Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		innerCalls++
	}), keytab.New())
	for _, remoteAddr := range []string{testRemoteAddress, "malformed"} {
		request := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
		request.RemoteAddr = remoteAddr
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		header := response.Header().Get(HTTPHeaderAuthResponse)
		if response.Code != http.StatusUnauthorized || header != HTTPHeaderAuthResponseValueKey {
			t.Fatalf(
				"unauthenticated response for %q = %d/%q",
				remoteAddr,
				response.Code,
				header,
			)
		}
	}
	if innerCalls != 0 {
		t.Fatalf("inner handler calls = %d", innerCalls)
	}
}
