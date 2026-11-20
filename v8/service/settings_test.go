package service

import (
	"bytes"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type settingsSessionManager struct{}

func (settingsSessionManager) New(http.ResponseWriter, *http.Request, string, []byte) error {
	return nil
}
func (settingsSessionManager) Get(*http.Request, string) ([]byte, error) { return nil, nil }

func TestSettingsOptionsAndDefaults(t *testing.T) {
	const servicePrincipal = "HTTP/a.example.org"
	address := types.HostAddress{AddrType: 2, Address: []byte{127, 0, 0, 1}}
	logger := log.New(&bytes.Buffer{}, "", 0)
	manager := settingsSessionManager{}
	bindings := testApplicationBindings("tls binding")
	principals := []string{servicePrincipal, "HTTP/b.example.org"}
	settings := NewSettings(
		keytab.New(),
		RequireHostAddr(true),
		DecodePAC(false),
		ClientAddress(address),
		Logger(logger),
		KeytabPrincipal("HTTP/keytab.example.org"),
		MaxClockSkew(time.Minute),
		SName("HTTP/service.example.org"),
		SessionManager(manager),
		ExtendedProtection(ExtendedProtectionRequired),
		ChannelBindings(bindings),
		ServicePrincipals(principals...),
	)
	principals[0] = "mutated"
	checkServiceSettings(t, settings, address, logger)
	if settings.ExtendedProtection() != ExtendedProtectionRequired ||
		settings.ChannelBindings() != bindings ||
		settings.ServicePrincipals()[0] != servicePrincipal {
		t.Fatalf("settings = %+v", settings)
	}
	returned := settings.ServicePrincipals()
	returned[0] = "mutated again"
	if settings.ServicePrincipals()[0] != servicePrincipal {
		t.Fatal("ServicePrincipals exposed internal storage")
	}
	defaults := NewSettings(keytab.New())
	if !defaults.DecodePAC() ||
		defaults.MaxClockSkew() != 5*time.Minute ||
		defaults.Logger() != nil ||
		defaults.SessionManager() != nil ||
		defaults.SName() != "" {
		t.Fatalf("defaults = %+v", defaults)
	}
}

func checkServiceSettings(t *testing.T, settings *Settings, address types.HostAddress, logger *log.Logger) {
	t.Helper()
	if !settings.RequireHostAddr() ||
		settings.DecodePAC() ||
		settings.ClientAddress().AddrType != address.AddrType ||
		settings.Logger() != logger ||
		settings.KeytabPrincipal() == nil ||
		settings.KeytabPrincipal().PrincipalNameString() != "HTTP/keytab.example.org" ||
		settings.MaxClockSkew() != time.Minute ||
		settings.SName() != "HTTP/service.example.org" ||
		settings.SessionManager() == nil {
		t.Fatalf("settings = %+v", settings)
	}
}

func TestReplayCacheClearOldEntries(t *testing.T) {
	oldTime := time.Now().UTC().Add(-time.Hour)
	newTime := time.Now().UTC()
	clientKey := replayCacheClient{name: `["alice"]`, realm: ""}
	expiredClientKey := replayCacheClient{name: "expired", realm: ""}
	oldEntryKey := replayCacheKey{clientTime: oldTime, serviceName: ""}
	newEntryKey := replayCacheKey{clientTime: newTime, serviceName: ""}
	var cache Cache
	cache.entries = map[replayCacheClient]clientEntries{
		clientKey: {
			replayMap: map[replayCacheKey]replayCacheEntry{
				oldEntryKey: {presentedTime: oldTime},
				newEntryKey: {presentedTime: newTime},
			},
			seqNumber: 0,
			subKey:    types.EncryptionKey{KeyType: 0, KeyValue: nil},
		},
		expiredClientKey: {
			replayMap: map[replayCacheKey]replayCacheEntry{oldEntryKey: {presentedTime: oldTime}},
			seqNumber: 0,
			subKey:    types.EncryptionKey{KeyType: 0, KeyValue: nil},
		},
	}
	cache.ClearOldEntries(10 * time.Minute)
	if _, ok := cache.entries[expiredClientKey]; ok {
		t.Fatal("empty client cache was retained")
	}
	entries, ok := cache.entries[clientKey]
	if !ok || len(entries.replayMap) != 1 {
		t.Fatalf("remaining replay entries = %+v", cache.entries)
	}
}
