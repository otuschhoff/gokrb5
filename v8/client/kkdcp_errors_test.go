package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type faultProxyBody struct {
	io.Reader
	closeErr error
	closes   int
}

func (body *faultProxyBody) Close() error { body.closes++; return body.closeErr }

func TestKKDCPCloseAndPrimaryErrorIdentity(t *testing.T) {
	primary := errors.New("injected read failure")
	cleanup := errors.New("injected close failure")
	for _, tt := range []struct {
		name   string
		reader io.Reader
		want   error
	}{
		{name: "close after successful read", reader: bytes.NewReader(encodedProxyReply(t)), want: cleanup},
		{name: "read and close", reader: errorResponseBody{err: primary}, want: primary},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := &faultProxyBody{Reader: tt.reader, closeErr: cleanup, closes: 0}
			var transport http.Client
			transport.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				var response http.Response
				response.StatusCode = http.StatusOK
				response.Header = http.Header{"Content-Type": {kkdcpContentType}}
				response.Body = body
				return &response, nil
			})
			cl := NewWithPassword("user", clientTestComRealm, "password", config.New(), KKDCPClient(&transport))
			_, err := cl.sendKKDCP("https://proxy.example", clientTestComRealm, []byte("request"))
			if !errors.Is(err, tt.want) || !errors.Is(err, cleanup) || body.closes != 1 {
				t.Fatalf("proxy result = %v, closes = %d", err, body.closes)
			}
		})
	}
}

func encodedProxyReply(t *testing.T) []byte {
	t.Helper()
	reply, err := types.NewKDCProxyMessage([]byte("reply"), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := reply.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestKDCFailoverRetainsAllCauses(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{
		kdcTestRealmConfig(clientTestComRealm, []string{"https://first.example", "https://second.example"}),
	}
	var transport http.Client
	transport.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "first.example" {
			return nil, context.Canceled
		}
		return nil, os.ErrDeadlineExceeded
	})
	cl := NewWithPassword("user", clientTestComRealm, "password", cfg, KKDCPClient(&transport))
	_, err := cl.sendToKDC([]byte("request"), clientTestComRealm)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("failover lost an error cause: %v", err)
	}
}
