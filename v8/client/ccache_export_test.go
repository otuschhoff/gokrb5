package client

import (
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
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

func TestCCacheRejectsNilSessionEntry(t *testing.T) {
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", nil)
	cl.sessions.Entries["EXAMPLE.ORG"] = nil
	cache, err := cl.CCache()
	if err == nil || cache != nil || !strings.Contains(err.Error(), "session") {
		t.Fatalf("CCache() = %v, %v; want nil cache and session error", cache, err)
	}
}

func TestCCacheSessionTicketEncodingFailure(t *testing.T) {
	cl := NewWithPassword("user", "EXPORT.TEST", "unused", nil)
	ticket := unencodableExportTicket(cl.Credentials.Realm())
	sess := new(session)
	sess.realm = cl.Credentials.Realm()
	sess.tgt = ticket
	cl.sessions.update(sess)

	exported, err := cl.CCache()
	require.ErrorContains(t, err, "marshal session ticket for credential cache")
	var cause asn1.StructuralError
	require.ErrorAs(t, err, &cause)
	require.Nil(t, exported)

	require.True(t, cl.sessions.mux.TryLock(), "session store remained locked after export failed")
	cl.sessions.mux.Unlock()
	require.True(t, sess.mux.TryLock(), "session remained locked after export failed")
	sess.mux.Unlock()
}

func TestCCacheServiceTicketEncodingFailure(t *testing.T) {
	cl := NewWithPassword("user", "EXPORT.TEST", "unused", nil)
	ticket := unencodableExportTicket(cl.Credentials.Realm())
	var entry CacheEntry
	entry.Ticket = ticket
	cl.cache.Entries[ticket.SName.PrincipalNameString()] = entry

	exported, err := cl.CCache()
	require.ErrorContains(t, err, "marshal service ticket for credential cache")
	var cause asn1.StructuralError
	require.ErrorAs(t, err, &cause)
	require.Nil(t, exported)

	require.True(t, cl.cache.mux.TryLock(), "ticket cache remained locked after export failed")
	cl.cache.mux.Unlock()
}

func unencodableExportTicket(realm string) messages.Ticket {
	ticket := s4uTestTicket(realm, "HTTP/export.test")
	ticket.DecryptedEncPart.AuthTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	return ticket
}

func TestCCacheRejectsConfigurationOnlyEntries(t *testing.T) {
	for _, tt := range []struct {
		name        string
		preAuthType int32
	}{
		{name: "without preauthentication", preAuthType: 0},
		{name: "with preauthentication", preAuthType: patype.PA_ENC_TIMESTAMP},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cl := NewWithPassword("user", "EXPORT.TEST", "unused", nil)
			cl.settings.preAuthType = tt.preAuthType
			var entry CacheEntry
			entry.Ticket = s4uTestTicket("X-CACHECONF:", "HTTP/export.test")
			cl.cache.Entries[entry.Ticket.SName.PrincipalNameString()] = entry

			exported, err := cl.CCache()
			require.ErrorContains(t, err, "no credentials to export")
			require.Nil(t, exported)
		})
	}
}

func TestSessionCredentialRejectsNil(t *testing.T) {
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", nil)
	credential, err := sessionCredential(cl, nil)
	if err == nil || credential != nil {
		t.Fatalf("sessionCredential(nil) = %v, %v; want nil credential and error", credential, err)
	}
}

func TestNewFromCCacheRejectsNil(t *testing.T) {
	client, err := NewFromCCache(nil, nil)
	if err == nil || client != nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("NewFromCCache(nil) = %v, %v; want nil client and error", client, err)
	}
}
