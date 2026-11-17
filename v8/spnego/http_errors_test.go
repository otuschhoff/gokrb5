package spnego

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
		{name: "invalid challenge", challenge: "Negotiate !!!", status: http.StatusUnauthorized, wantErr: true},
		{name: "missing mechanism", challenge: "Basic", status: http.StatusUnauthorized, wantErr: true},
		{name: "caller owns successful body", status: http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := &ownedResponseBody{Reader: strings.NewReader("body"), closeErr: cleanup}
			transport := &http.Client{Transport: negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set(HTTPHeaderAuthResponse, tt.challenge)
				return &http.Response{StatusCode: tt.status, Header: header, Body: body}, nil
			})}
			client := NewNegotiatingClient(transport, "target", func() gssapi.ContextMechanism {
				return newTestContextMechanism(1, "http")
			})
			request, err := http.NewRequest(http.MethodGet, "http://example.test", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if tt.wantErr {
				if response != nil || !errors.Is(err, cleanup) || body.closes != 1 {
					t.Fatalf("failed negotiation = %v, %v, closes %d", response, err, body.closes)
				}
				if _, ok := errors.AsType[base64.CorruptInputError](err); tt.challenge == "Negotiate !!!" && !ok {
					t.Fatalf("malformed challenge lost its decoding cause: %v", err)
				}
				return
			}
			if err != nil || response == nil || body.closes != 0 {
				t.Fatalf("successful response ownership = %v, %v, closes %d", response, err, body.closes)
			}
			if err := response.Body.Close(); !errors.Is(err, cleanup) {
				t.Fatal(err)
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
		return &http.Client{Transport: negotiatingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return nil, request.Context().Err()
		})}
	}
	for _, tt := range []struct {
		name string
		do   func(*http.Request) (*http.Response, error)
	}{
		{name: "legacy", do: NewClient(nil, transport(), "").Do},
		{name: "generic", do: NewNegotiatingClient(transport(), "target", func() gssapi.ContextMechanism {
			return newTestContextMechanism(1, "http")
		}).Do},
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
		})
	}
}

func TestLegacyHTTPMissingKerberosReturnsOwnedResponse(t *testing.T) {
	body := &ownedResponseBody{Reader: strings.NewReader("challenge")}
	transport := &http.Client{Transport: negotiatingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     header, Body: body,
		}, nil
	})}
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
		{name: "307 reopens closed file", status: http.StatusTemporaryRedirect},
		{name: "303 drops POST body", status: http.StatusSeeOther},
		{name: "307 reopen failure", status: http.StatusTemporaryRedirect, failReplay: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/start" {
					http.Redirect(writer, request, "/end", tt.status)
					return
				}
				body, err := io.ReadAll(request.Body)
				wantMethod, wantBody := http.MethodPost, "payload"
				if tt.status == http.StatusSeeOther {
					wantMethod, wantBody = http.MethodGet, ""
				}
				if err != nil || request.Method != wantMethod || string(body) != wantBody {
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			root, err := os.OpenRoot(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, root.Close()) })
			require.NoError(t, root.WriteFile("request", []byte("payload"), 0o600))
			body, err := root.Open("request")
			require.NoError(t, err)
			opened := []*os.File{body}
			t.Cleanup(func() {
				for _, file := range opened {
					if closeErr := file.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
						t.Error(closeErr)
					}
				}
			})
			request, err := http.NewRequest(http.MethodPost, server.URL+"/start", body)
			require.NoError(t, err)
			replays := 0
			request.GetBody = func() (io.ReadCloser, error) {
				replays++
				if tt.failReplay && replays == 2 {
					return nil, cause
				}
				file, openErr := root.Open("request")
				if openErr != nil {
					return nil, openErr
				}
				opened = append(opened, file)
				return file, nil
			}
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
			require.Equal(t, wantReplays, replays)
			for _, file := range opened {
				_, err := file.Read(make([]byte, 1))
				require.ErrorIs(t, err, os.ErrClosed)
			}
		})
	}
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

func TestLegacyHTTPAuthenticationFailureContracts(t *testing.T) {
	replayFailure := errors.New("injected request replay failure")
	readFailure := errors.New("injected response read failure")
	closeFailure := errors.New("injected response close failure")
	for _, tt := range []struct {
		name            string
		noReplay        bool
		replayErr       error
		readErr         error
		closeErr        error
		alwaysChallenge bool
		wantCalls       int
		wantErr         error
	}{
		{name: "successful replay with nil headers", wantCalls: 2},
		{name: "unreplayable", noReplay: true, wantCalls: 1},
		{name: "replay failure", replayErr: replayFailure, wantCalls: 1, wantErr: replayFailure},
		{name: "read and close", readErr: readFailure, closeErr: closeFailure, wantCalls: 1, wantErr: readFailure},
		{name: "challenge budget", alwaysChallenge: true, wantCalls: 10},
	} {
		t.Run(tt.name, func(t *testing.T) {
			kerberos := newHTTPKerberosClient(t)
			var bodies []*ownedResponseBody
			calls := 0
			transport := &http.Client{Transport: negotiatingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				data, err := io.ReadAll(request.Body)
				require.NoError(t, err)
				require.NoError(t, request.Body.Close())
				require.Equal(t, "payload", string(data))
				var reader io.Reader = strings.NewReader("")
				if tt.readErr != nil {
					reader = failingReadCloser{readErr: tt.readErr}
				}
				body := &ownedResponseBody{Reader: reader, closeErr: tt.closeErr}
				bodies = append(bodies, body)
				status := http.StatusOK
				header := make(http.Header)
				if calls == 1 || tt.alwaysChallenge {
					status = http.StatusUnauthorized
					header.Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
				}
				return &http.Response{StatusCode: status, Header: header, Body: body}, nil
			})}
			negotiating := NewClient(kerberos, transport, "HTTP/server.test")
			request, err := http.NewRequest(http.MethodPost, "http://server.test", strings.NewReader("payload"))
			require.NoError(t, err)
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
			require.Equal(t, tt.wantCalls, calls)
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
			for _, body := range bodies {
				require.Equal(t, 1, body.closes)
			}
		})
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
