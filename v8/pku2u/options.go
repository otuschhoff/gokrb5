package pku2u

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/otuschhoff/gokrb5/v8/pkinit"
)

// Identity is a certificate, chain, and private signing key used by PKU2U. Its
// certificate must contain a UPN SAN or a non-empty subject for principal
// mapping; PKINIT KDC EKU requirements do not apply to peer identities.
type Identity = pkinit.Identity

type settings struct {
	identity          *Identity
	roots             *x509.CertPool
	intermediates     *x509.CertPool
	requireRevocation bool
	httpClient        *http.Client
	clockSkew         time.Duration
	ticketLifetime    time.Duration
	minimumDHBits     int
	currentTime       func() time.Time
}

// Option configures a PKU2U mechanism.
type Option func(*settings)

// WithIntermediates adds certificates used to build peer chains.
func WithIntermediates(pool *x509.CertPool) Option {
	return func(settings *settings) { settings.intermediates = pool }
}

// WithRevocationChecking requires a successful OCSP or CRL check. The HTTP
// client is reused and should have deployment-appropriate TLS roots and
// timeouts.
func WithRevocationChecking(client *http.Client) Option {
	return func(settings *settings) {
		settings.requireRevocation = true
		settings.httpClient = client
	}
}

// WithClockSkew sets the permitted authenticator clock difference.
func WithClockSkew(skew time.Duration) Option {
	return func(settings *settings) { settings.clockSkew = skew }
}

// WithTicketLifetime sets the maximum lifetime of issued self-tickets.
func WithTicketLifetime(lifetime time.Duration) Option {
	return func(settings *settings) { settings.ticketLifetime = lifetime }
}

// WithMinimumDHBits sets the minimum accepted PKINIT DH group size.
func WithMinimumDHBits(bits int) Option {
	return func(settings *settings) { settings.minimumDHBits = bits }
}

func newSettings(identity *Identity, roots *x509.CertPool, options []Option) settings {
	settings := settings{
		identity: identity, roots: roots, clockSkew: 5 * time.Minute,
		ticketLifetime: 10 * time.Hour, minimumDHBits: 2048,
		currentTime: func() time.Time { return time.Now().UTC() },
	}
	for _, option := range options {
		if option != nil {
			option(&settings)
		}
	}
	return settings
}
