package service

import (
	"bytes"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type settingsSessionManager struct{}

func (settingsSessionManager) New(http.ResponseWriter, *http.Request, string, []byte) error {
	return nil
}
func (settingsSessionManager) Get(*http.Request, string) ([]byte, error) { return nil, nil }

func TestSettingsOptionsAndDefaults(t *testing.T) {
	address := types.HostAddress{AddrType: 2, Address: []byte{127, 0, 0, 1}}
	logger := log.New(&bytes.Buffer{}, "", 0)
	manager := settingsSessionManager{}
	bindings := &gssapi.ChannelBindings{ApplicationData: []byte("tls binding")}
	principals := []string{"HTTP/a.example.org", "HTTP/b.example.org"}
	settings := NewSettings(keytab.New(), RequireHostAddr(true), DecodePAC(false), ClientAddress(address), Logger(logger),
		KeytabPrincipal("HTTP/keytab.example.org"), MaxClockSkew(time.Minute), SName("HTTP/service.example.org"),
		SessionManager(manager), ExtendedProtection(ExtendedProtectionRequired), ChannelBindings(bindings), ServicePrincipals(principals...))
	principals[0] = "mutated"
	if !settings.RequireHostAddr() || settings.DecodePAC() || settings.ClientAddress().AddrType != address.AddrType ||
		settings.Logger() != logger || settings.KeytabPrincipal() == nil || settings.KeytabPrincipal().PrincipalNameString() != "HTTP/keytab.example.org" ||
		settings.MaxClockSkew() != time.Minute || settings.SName() != "HTTP/service.example.org" || settings.SessionManager() == nil ||
		settings.ExtendedProtection() != ExtendedProtectionRequired || settings.ChannelBindings() != bindings || settings.ServicePrincipals()[0] != "HTTP/a.example.org" {
		t.Fatalf("settings = %+v", settings)
	}
	returned := settings.ServicePrincipals()
	returned[0] = "mutated again"
	if settings.ServicePrincipals()[0] != "HTTP/a.example.org" {
		t.Fatal("ServicePrincipals exposed internal storage")
	}
	defaults := NewSettings(keytab.New())
	if !defaults.DecodePAC() || defaults.MaxClockSkew() != 5*time.Minute || defaults.Logger() != nil || defaults.SessionManager() != nil || defaults.SName() != "" {
		t.Fatalf("defaults = %+v", defaults)
	}
}

func TestReplayCacheClearOldEntries(t *testing.T) {
	client := types.NewPrincipalName(1, "alice")
	service := types.NewPrincipalName(2, "HTTP/server.example.org")
	oldTime := time.Now().UTC().Add(-time.Hour)
	newTime := time.Now().UTC()
	cache := &Cache{entries: map[string]clientEntries{
		client.PrincipalNameString(): {replayMap: map[time.Time]replayCacheEntry{
			oldTime: {presentedTime: oldTime, sName: service, cTime: oldTime},
			newTime: {presentedTime: newTime, sName: service, cTime: newTime},
		}},
		"expired": {replayMap: map[time.Time]replayCacheEntry{oldTime: {presentedTime: oldTime}}},
	}}
	cache.ClearOldEntries(10 * time.Minute)
	if _, ok := cache.entries["expired"]; ok {
		t.Fatal("empty client cache was retained")
	}
	entries, ok := cache.entries[client.PrincipalNameString()]
	if !ok || len(entries.replayMap) != 1 {
		t.Fatalf("remaining replay entries = %+v", cache.entries)
	}
}
