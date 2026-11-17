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
			body := &faultProxyBody{Reader: tt.reader, closeErr: cleanup}
			transport := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {kkdcpContentType}}, Body: body}, nil
			})}
			cl := NewWithPassword("user", "EXAMPLE.COM", "password", config.New(), KKDCPClient(transport))
			_, err := cl.sendKKDCP("https://proxy.example", "EXAMPLE.COM", []byte("request"))
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
	cfg.Realms = []config.Realm{{Realm: "EXAMPLE.COM", KDC: []string{"https://first.example", "https://second.example"}}}
	transport := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "first.example" {
			return nil, context.Canceled
		}
		return nil, os.ErrDeadlineExceeded
	})}
	cl := NewWithPassword("user", "EXAMPLE.COM", "password", cfg, KKDCPClient(transport))
	_, err := cl.sendToKDC([]byte("request"), "EXAMPLE.COM")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("failover lost an error cause: %v", err)
	}
}
