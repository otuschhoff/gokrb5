package spnego

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/service"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type ownedResponseBody struct {
	io.Reader
	closeErr error
	closes   int
}

func (body *ownedResponseBody) Close() error { body.closes++; return body.closeErr }

func TestNegotiatingClientResponseOwnership(t *testing.T) {
	cleanup := errors.New("injected HTTP close failure")
	for _, tt := range []struct {
		name      string
		challenge string
		status    int
		wantErr   bool
	}{
		{name: "invalid challenge", challenge: malformedNegotiateHeader, status: http.StatusUnauthorized, wantErr: true},
		{name: "missing mechanism", challenge: "Basic", status: http.StatusUnauthorized, wantErr: true},
		{
			challenge: "",
			wantErr:   false,
			name:      "caller owns successful body", status: http.StatusOK,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := &ownedResponseBody{
				closes: 0,
				Reader: strings.NewReader("body"), closeErr: cleanup,
			}
			transport := testHTTPClient(negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set(HTTPHeaderAuthResponse, tt.challenge)
				return testHTTPResponse(tt.status, header, body), nil
			}))
			client := NewNegotiatingClient(transport, "target", func() gssapi.ContextMechanism {
				return newTestContextMechanism(1, "http")
			})
			request, err := http.NewRequest(http.MethodGet, "http://example.test", nil)
			require.NoError(t, err)
			response, err := client.Do(request)
			if tt.wantErr {
				require.Nil(t, response)
				require.True(t, errors.Is(err, cleanup))
				require.Equal(t, 1, body.closes)
				if _, ok := errors.AsType[base64.CorruptInputError](err); tt.challenge == malformedNegotiateHeader && !ok {
					t.Fatalf("malformed challenge lost its decoding cause: %v", err)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, response)
			require.Equal(t, 0, body.closes)
			{
				err := response.Body.Close()
				require.True(t, errors.Is(err, cleanup))
			}
		})
	}
}

func TestHTTPClientsPreserveCancellationAndRejectNilRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := func() *http.Client {
		return testHTTPClient(negotiatingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return nil, request.Context().Err()
		}))
	}
	for _, tt := range []struct {
		name        string
		wantContext string
		do          func(*http.Request) (*http.Response, error)
	}{
		{name: "legacy", wantContext: "send SPNEGO HTTP request:", do: NewClient(nil, transport(), "").Do},
		{
			name:        "generic",
			wantContext: "send Negotiate HTTP request:",
			do: NewNegotiatingClient(transport(), "target", func() gssapi.ContextMechanism {
				return newTestContextMechanism(1, "http")
			}).Do,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response, err := tt.do(nil)
			if response != nil {
				if closeErr := response.Body.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if err == nil {
				t.Fatal("nil request accepted")
			}
			response, err = tt.do(request)
			if response != nil {
				if closeErr := response.Body.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled request = %v", err)
			}
			require.ErrorContains(t, err, tt.wantContext)
			require.ErrorAs(t, err, new(*url.Error))
		})
	}
}

func TestLegacyHTTPMissingKerberosReturnsOwnedResponse(t *testing.T) {
	body := &ownedResponseBody{
		closeErr: nil,
		closes:   0,
		Reader:   strings.NewReader("challenge"),
	}
	transport := testHTTPClient(negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		return testHTTPResponse(http.StatusUnauthorized, header, body), nil
	}))
	request, err := http.NewRequest(http.MethodGet, "http://example.test", nil)
	require.NoError(t, err)
	response, err := NewClient(nil, transport, "HTTP/server.test").Do(request)
	require.ErrorContains(t, err, "kerberos client is nil")
	require.NotNil(t, response)
	require.Zero(t, body.closes)
	require.NoError(t, response.Body.Close())
	require.Equal(t, 1, body.closes)
}

func TestLegacyHTTPRedirectBudgetIsPerRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/start" {
			http.Redirect(writer, request, "/end", http.StatusFound)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := NewClient(nil, server.Client(), "")
	var workers sync.WaitGroup
	failures := make(chan error, 20)
	for range 20 {
		workers.Go(func() {
			response, err := client.Get(server.URL + "/start")
			if err != nil {
				failures <- err
				return
			}
			if closeErr := response.Body.Close(); closeErr != nil {
				failures <- closeErr
			}
			if response.StatusCode != http.StatusNoContent {
				failures <- errors.New("unexpected redirect response")
			}
		})
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestLegacyHTTPRedirectBodyReplay(t *testing.T) {
	cause := errors.New("injected redirected body replay failure")
	for _, tt := range []struct {
		name       string
		status     int
		failReplay bool
	}{
		{
			failReplay: false,
			name:       "307 reopens closed file", status: http.StatusTemporaryRedirect,
		},
		{
			failReplay: false,
			name:       "303 drops POST body", status: http.StatusSeeOther,
		},
		{name: "307 reopen failure", status: http.StatusTemporaryRedirect, failReplay: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(testRedirectHandler(tt.status))
			defer server.Close()
			var replayError error
			if tt.failReplay {
				replayError = cause
			}
			request, replay := testRedirectRequest(t, server.URL, replayError)
			response, err := NewClient(nil, server.Client(), "").Do(request)
			if response != nil {
				require.NoError(t, response.Body.Close())
			}
			if tt.failReplay {
				require.ErrorIs(t, err, cause)
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				require.Equal(t, http.StatusNoContent, response.StatusCode)
			}
			wantReplays := 2
			if tt.status == http.StatusSeeOther {
				wantReplays = 0
			}
			require.Equal(t, wantReplays, replay.calls)
			for _, file := range replay.opened {
				_, err := file.Read(make([]byte, 1))
				require.ErrorIs(t, err, os.ErrClosed)
			}
		})
	}
}

func testRedirectHandler(status int) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/start" {
			http.Redirect(writer, request, "/end", status)
			return
		}
		body, err := io.ReadAll(request.Body)
		wantMethod, wantBody := http.MethodPost, "payload"
		if status == http.StatusSeeOther {
			wantMethod, wantBody = http.MethodGet, ""
		}
		if err != nil || request.Method != wantMethod || string(body) != wantBody {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}
}

type redirectReplay struct {
	calls  int
	opened []*os.File
}

func testRedirectRequest(t *testing.T, url string, replayError error) (*http.Request, *redirectReplay) {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	require.NoError(t, root.WriteFile("request", []byte("payload"), 0o600))
	body, err := root.Open("request")
	require.NoError(t, err)
	replay := &redirectReplay{calls: 0, opened: []*os.File{body}}
	t.Cleanup(func() {
		for _, file := range replay.opened {
			if closeErr := file.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
				t.Error(closeErr)
			}
		}
	})
	request, err := http.NewRequest(http.MethodPost, url+"/start", body)
	require.NoError(t, err)
	request.GetBody = func() (io.ReadCloser, error) {
		replay.calls++
		if replayError != nil && replay.calls == 2 {
			return nil, replayError
		}
		file, openErr := root.Open("request")
		if openErr != nil {
			return nil, openErr
		}
		replay.opened = append(replay.opened, file)
		return file, nil
	}
	return request, replay
}

func newHTTPKerberosClient(t *testing.T) *client.Client {
	t.Helper()
	const realm = "EXAMPLE.COM"
	now := time.Now().UTC()
	cname := types.NewPrincipalName(1, "alice")
	cache := credentials.NewCCache(cname, realm)
	keys := keytab.New()
	for _, name := range []string{"krbtgt/" + realm, "HTTP/server.test"} {
		require.NoError(t, keys.AddEntry(name, realm, "test password", now, 1, 18))
		sname := types.NewPrincipalName(2, name)
		ticket, key, err := messages.NewTicket(cname, realm, sname, realm, types.NewKrbFlags(), keys, 18, 1,
			now, now, now.Add(time.Hour), now.Add(2*time.Hour))
		require.NoError(t, err)
		wire, err := ticket.Marshal()
		require.NoError(t, err)
		cache.AddCredential(&credentials.Credential{
			IsSKey:       false,
			Addresses:    nil,
			AuthData:     nil,
			SecondTicket: nil,

			Client: credentials.Principal{Realm: realm, PrincipalName: cname},
			Server: credentials.Principal{Realm: realm, PrincipalName: sname},
			Key:    key, AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour),
			RenewTill: now.Add(2 * time.Hour), TicketFlags: types.NewKrbFlags(), Ticket: wire,
		})
	}
	kerberos, err := client.NewFromCCache(cache, config.New())
	require.NoError(t, err)
	t.Cleanup(kerberos.Destroy)
	return kerberos
}

type authFailureCase struct {
	name            string
	noReplay        bool
	replayErr       error
	readErr         error
	closeErr        error
	alwaysChallenge bool
	wantCalls       int
	wantErr         error
}

func TestLegacyHTTPAuthenticationFailureContracts(t *testing.T) {
	replayFailure := errors.New("injected request replay failure")
	readFailure := errors.New("injected response read failure")
	closeFailure := errors.New("injected response close failure")
	for _, tt := range []authFailureCase{
		{
			noReplay:        false,
			replayErr:       nil,
			readErr:         nil,
			closeErr:        nil,
			alwaysChallenge: false,
			wantErr:         nil,
			name:            "successful replay with nil headers", wantCalls: 2,
		},
		{
			replayErr:       nil,
			readErr:         nil,
			closeErr:        nil,
			alwaysChallenge: false,
			wantErr:         nil,
			name:            "unreplayable", noReplay: true, wantCalls: 1,
		},
		{
			noReplay:        false,
			readErr:         nil,
			closeErr:        nil,
			alwaysChallenge: false,
			name:            "replay failure", replayErr: replayFailure, wantCalls: 1, wantErr: replayFailure,
		},
		{
			noReplay:        false,
			replayErr:       nil,
			alwaysChallenge: false,
			name:            "read and close", readErr: readFailure, closeErr: closeFailure, wantCalls: 1, wantErr: readFailure,
		},
		{
			noReplay:  false,
			replayErr: nil,
			readErr:   nil,
			closeErr:  nil,
			wantErr:   nil,
			name:      "challenge budget", alwaysChallenge: true, wantCalls: 10,
		},
	} {
		t.Run(tt.name, func(t *testing.T) { testHTTPAuthenticationFailure(t, tt) })
	}
}

func testHTTPAuthenticationFailure(t *testing.T, tt authFailureCase) {
	t.Helper()
	kerberos := newHTTPKerberosClient(t)
	var bodies []*ownedResponseBody
	transport := testHTTPClient(negotiatingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		data, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		require.NoError(t, request.Body.Close())
		require.Equal(t, "payload", string(data))
		var reader io.Reader = strings.NewReader("")
		if tt.readErr != nil {
			reader = failingReadCloser{closeErr: nil, readErr: tt.readErr}
		}
		body := &ownedResponseBody{Reader: reader, closeErr: tt.closeErr, closes: 0}
		bodies = append(bodies, body)
		status := http.StatusOK
		header := make(http.Header)
		if len(bodies) == 1 || tt.alwaysChallenge {
			status = http.StatusUnauthorized
			header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		}
		return testHTTPResponse(status, header, body), nil
	}))
	negotiating := NewClient(kerberos, transport, "HTTP/server.test")
	request := mustHTTPRequest(t, http.MethodPost, "http://server.test", strings.NewReader("payload"))
	request.Header = nil
	if tt.noReplay {
		request.GetBody = nil
	}
	if tt.replayErr != nil {
		request.GetBody = func() (io.ReadCloser, error) { return nil, tt.replayErr }
	}
	response, err := negotiating.Do(request)
	if response != nil {
		require.NoError(t, response.Body.Close())
	}
	checkHTTPAuthOutcome(t, tt, err)
	require.Len(t, bodies, tt.wantCalls)
	for _, body := range bodies {
		require.Equal(t, 1, body.closes)
	}
}

func checkHTTPAuthOutcome(t *testing.T, tt authFailureCase, err error) {
	t.Helper()
	if tt.wantErr != nil {
		require.ErrorIs(t, err, tt.wantErr)
	}
	if tt.closeErr != nil {
		require.ErrorIs(t, err, tt.closeErr)
	}
	if tt.noReplay || tt.alwaysChallenge {
		require.Error(t, err)
	}
	if tt.name == "successful replay with nil headers" {
		require.NoError(t, err)
	}
}

func TestHTTPBodyReplayContract(t *testing.T) {
	cause := errors.New("injected replay failure")
	request, err := http.NewRequest(http.MethodPost, "http://example.test", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header = nil
	clone, err := cloneNegotiationRequest(request, 1)
	if err != nil || clone.Header == nil {
		t.Fatalf("clone = %v, %v", clone, err)
	}
	if closeErr := clone.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	request.GetBody = func() (io.ReadCloser, error) { return nil, cause }
	failedClone, cloneErr := cloneNegotiationRequest(request, 1)
	require.Nil(t, failedClone)
	require.ErrorIs(t, cloneErr, cause)
	require.ErrorContains(t, cloneErr, "replay HTTP request body:")
	if replayErr := replayRequestBody(request, request); !errors.Is(replayErr, cause) {
		t.Fatal(replayErr)
	}
	request.GetBody = nil
	if replayErr := replayRequestBody(request, request); replayErr == nil {
		t.Fatal("non-replayable body accepted")
	}
	if closeErr := request.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	request.Body = http.NoBody
	request.GetBody = nil
	clone, err = cloneNegotiationRequest(request, 1)
	require.NoError(t, err)
	require.Equal(t, http.NoBody, clone.Body)
}

func TestLegacyHTTPNewRequestErrors(t *testing.T) {
	t.Parallel()

	transport := new(http.Client)
	transport.Transport = negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected transport call")
	})
	client := NewClient(nil, transport, "")
	for _, tt := range []struct {
		name   string
		method string
		send   func(string) (*http.Response, error)
	}{
		{name: "get", method: http.MethodGet, send: client.Get},
		{name: "head", method: http.MethodHead, send: client.Head},
		{name: "post", method: http.MethodPost, send: func(u string) (*http.Response, error) {
			return client.Post(u, "", nil)
		}},
		{name: "post form", method: http.MethodPost, send: func(u string) (*http.Response, error) {
			return client.PostForm(u, url.Values{})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response, err := tt.send("http://example.test/%")
			if response != nil && response.Body != nil {
				require.NoError(t, response.Body.Close())
			}
			require.Nil(t, response)
			require.ErrorContains(t, err, "create HTTP "+tt.method+" request:")
			require.ErrorAs(t, err, new(*url.Error))
			require.ErrorAs(t, err, new(url.EscapeError))
		})
	}
}

func TestRequestSPNRetainsInvalidHostError(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	request.URL.Host = "[::1"
	principal, err := setRequestSPN(request)
	require.Empty(t, principal.NameString)
	require.Equal(t, "example.test", request.Host)
	require.ErrorContains(t, err, "split HTTP host and port:")
	require.ErrorAs(t, err, new(*net.AddrError))
}

func TestLegacyHTTPSessionFailureContexts(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	t.Run("empty session", func(t *testing.T) {
		manager := new(coverageSessionManager)
		mechanism := SPNEGOService(keytab.New(), service.SessionManager(manager))
		identity, err := getSessionCredentials(mechanism, request)
		require.False(t, identity.Authenticated())
		require.EqualError(t, err, "no credentials in HTTP session")
	})
	t.Run("encode credentials", func(t *testing.T) {
		manager := new(coverageSessionManager)
		mechanism := SPNEGOService(keytab.New(), service.SessionManager(manager))
		identity := credentials.New("user", "EXAMPLE.COM")
		identity.SetAttribute("unregistered", struct{ Enabled bool }{Enabled: true})
		response := httptest.NewRecorder()
		err := newSession(mechanism, request, response, identity)
		require.ErrorContains(t, err, "encode HTTP session credentials:")
		require.ErrorContains(t, errors.Unwrap(err), "encode credentials gob:")
		require.Empty(t, manager.saved)
		require.Equal(t, http.StatusInternalServerError, response.Code)
		require.Equal(t, "Internal Server Error\n", response.Body.String())
	})
	t.Run("save credentials", func(t *testing.T) {
		manager := new(coverageSessionManager)
		manager.newErr = errors.New("injected session store failure")
		mechanism := SPNEGOService(keytab.New(), service.SessionManager(manager))
		identity := credentials.New("user", "EXAMPLE.COM")
		response := httptest.NewRecorder()
		err := newSession(mechanism, request, response, identity)
		require.ErrorContains(t, err, "create HTTP session:")
		require.ErrorIs(t, err, manager.newErr)
		require.Equal(t, http.StatusInternalServerError, response.Code)
		require.Equal(t, "Internal Server Error\n", response.Body.String())
	})
}

func TestSPNEGOHTTPNilRequestAndResponseGuards(t *testing.T) {
	if _, err := cloneNegotiationRequest(nil, 0); err == nil {
		t.Fatal("nil negotiation request was accepted")
	}
	if _, err := setRequestSPN(nil); err == nil {
		t.Fatal("nil request SPN was accepted")
	}
	request := new(http.Request)
	if _, err := setRequestSPN(request); err == nil {
		t.Fatal("request with nil URL was accepted")
	}
	if err := SetSPNEGOHeader(nil, nil, "HTTP/server.example"); err == nil {
		t.Fatal("nil request/header input was accepted")
	}
	if _, _, err := responseSPNEGOToken(nil); err == nil {
		t.Fatal("nil response was accepted")
	}
}
