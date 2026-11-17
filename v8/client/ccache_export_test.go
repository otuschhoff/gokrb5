package client

import (
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/credentials"
)

func TestCCacheRejectsUninitializedClient(t *testing.T) {
	tests := []struct {
		name   string
		client *Client
	}{
		{name: "nil client"},
		{name: "missing credentials", client: &Client{}},
		{name: "missing session state", client: &Client{Credentials: credentials.New("user", "EXAMPLE.ORG")}},
		{
			name: "missing ticket cache",
			client: &Client{
				Credentials: credentials.New("user", "EXAMPLE.ORG"),
				sessions:    &sessions{},
			},
		},
		{
			name: "missing settings",
			client: &Client{
				Credentials: credentials.New("user", "EXAMPLE.ORG"),
				sessions:    &sessions{},
				cache:       NewCache(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := tt.client.CCache()
			if err == nil || cache != nil {
				t.Fatalf("CCache() = %v, %v; want nil cache and error", cache, err)
			}
		})
	}
}

func TestNewFromCCacheRejectsNil(t *testing.T) {
	client, err := NewFromCCache(nil, nil)
	if err == nil || client != nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("NewFromCCache(nil) = %v, %v; want nil client and error", client, err)
	}
}
