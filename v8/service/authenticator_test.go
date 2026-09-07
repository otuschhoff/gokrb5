package service

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/jcmturner/goidentity/v6"
	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/stretchr/testify/assert"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	//s := new(SPNEGOAuthenticator)
	var s KRB5BasicAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, s, "SPNEGOAuthenticator type does not implement the goidentity.Authenticator interface")
}

func TestParseBasicHeaderValue(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		domain   string
		username string
		password string
	}{
		{name: "bare username", value: "alice:secret", username: "alice", password: "secret"},
		{name: "Windows domain", value: `EXAMPLE\alice:secret:with:colons`, domain: "EXAMPLE", username: "alice", password: "secret:with:colons"},
		{name: "realm suffix", value: "alice@EXAMPLE.COM:secret", domain: "EXAMPLE.COM", username: "alice", password: "secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString([]byte(test.value))
			domain, username, password, err := parseBasicHeaderValue(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if domain != test.domain || username != test.username || password != test.password {
				t.Fatalf("parsed = %q, %q, %q", domain, username, password)
			}
		})
	}
}

func TestParseBasicHeaderValueRejectsMalformedInput(t *testing.T) {
	if _, _, _, err := parseBasicHeaderValue("!!!"); err == nil {
		t.Fatal("invalid base64 accepted")
	}
	withoutSeparator := base64.StdEncoding.EncodeToString([]byte("alice"))
	if _, _, _, err := parseBasicHeaderValue(withoutSeparator); err == nil || !strings.Contains(err.Error(), "separator") {
		t.Fatalf("missing separator error = %v", err)
	}
}

func TestKRB5BasicAuthenticatorMetadataAndParseFailure(t *testing.T) {
	cfg := config.New()
	serviceSettings := NewSettings(nil)
	clientSettings := new(client.Settings)
	authenticator := NewKRB5BasicAuthenticator("!!!", cfg, serviceSettings, clientSettings)
	if authenticator.clientConfig != cfg || authenticator.serviceSettings != serviceSettings || authenticator.clientSettings != clientSettings {
		t.Fatal("constructor did not retain settings")
	}
	if authenticator.Mechanism() != "Kerberos Basic" {
		t.Fatalf("mechanism = %q", authenticator.Mechanism())
	}
	identity, ok, err := authenticator.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "could not parse") || ok || identity != nil {
		t.Fatalf("Authenticate = %v, %v, %v", identity, ok, err)
	}
}
