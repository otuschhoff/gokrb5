package pku2u

import (
	"crypto/x509"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

func TestNewSettingsDefaults(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		identity := new(Identity)
		roots := x509.NewCertPool()
		got := newSettings(identity, roots, nil)
		if got.identity != identity || got.roots != roots {
			t.Error("settings did not retain the supplied identity and roots")
		}
		if got.intermediates != nil || got.requireRevocation || got.httpClient != nil {
			t.Error("intermediates and revocation checking must be opt-in")
		}
		checkSettingsLimits(t, got, 5*time.Minute, 10*time.Hour, 2048)
		if now := got.currentTime(); now != time.Now().UTC() {
			t.Errorf("clock returned %v, want %v", now, time.Now().UTC())
		}
		time.Sleep(time.Second)
		if now := got.currentTime(); now != time.Now().UTC() {
			t.Errorf("clock returned %v after advancing, want %v", now, time.Now().UTC())
		}
	})
}

func TestNewSettingsAppliesOptionsInOrder(t *testing.T) {
	t.Parallel()

	intermediates := x509.NewCertPool()
	client := new(http.Client)
	const (
		skew     = 2 * time.Minute
		lifetime = 3 * time.Hour
		dhBits   = 4096
	)
	got := newSettings(nil, nil, []Option{
		WithClockSkew(time.Minute),
		WithTicketLifetime(time.Hour),
		WithMinimumDHBits(3072),
		WithIntermediates(intermediates),
		WithRevocationChecking(client),
		nil,
		WithClockSkew(skew),
		WithTicketLifetime(lifetime),
		WithMinimumDHBits(dhBits),
	})
	if got.intermediates != intermediates || !got.requireRevocation || got.httpClient != client {
		t.Error("settings did not retain the supplied intermediates and revocation client")
	}
	checkSettingsLimits(t, got, skew, lifetime, dhBits)
}

func checkSettingsLimits(t *testing.T, got settings, skew, lifetime time.Duration, dhBits int) {
	t.Helper()

	if got.clockSkew != skew || got.ticketLifetime != lifetime || got.minimumDHBits != dhBits {
		t.Errorf("settings limits = (%s, %s, %d), want (%s, %s, %d)",
			got.clockSkew, got.ticketLifetime, got.minimumDHBits, skew, lifetime, dhBits)
	}
}
