package pku2u

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestValidatePeerRequiresIdentityAndRoots(t *testing.T) {
	t.Parallel()

	const want = "PKU2U identity and trust anchors are required"
	for _, tt := range []struct {
		name     string
		identity *pkinit.Identity
		roots    *x509.CertPool
	}{
		{name: "missing identity", identity: nil, roots: x509.NewCertPool()},
		{name: "missing roots", identity: new(pkinit.Identity), roots: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := newSettings(tt.identity, tt.roots, nil)
			var target types.PrincipalName
			chain, err := cfg.validatePeer(nil, target)
			if chain != nil || err == nil || err.Error() != want {
				t.Fatalf("validatePeer = (%v, %v), want (nil, %q)", chain, err, want)
			}
		})
	}
}

func TestValidatePeerChecksChainBeforeUsageAndName(t *testing.T) {
	t.Parallel()

	root, rootKey := newPKU2URoot(t)
	leaf, leafKey := newPKU2ULeaf(t, root, rootKey, "Peer", []string{"trust-peer.example.com"}, nil)
	identity, err := pkinit.NewIdentity(leaf, []*x509.Certificate{root}, leafKey, false)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	signer := *leaf
	signer.KeyUsage = x509.KeyUsageKeyEncipherment
	signed := &pkinit.VerifiedSignedData{Content: nil, Signer: &signer, Certificates: nil}
	target := types.NewPrincipalName(nametype.KRB_NT_SRV_HST, "host/other.example.com")

	untrusted := newSettings(identity, x509.NewCertPool(), nil)
	chain, err := untrusted.validatePeer(signed, target)
	requirePKU2UError[x509.UnknownAuthorityError](
		t,
		err,
		"verify PKU2U peer certificate: verify PKINIT certificate chain:",
	)
	if chain != nil {
		t.Fatal("returned a chain for an untrusted signer")
	}

	const want = "PKU2U peer certificate does not permit digital signatures"
	trusted := newSettings(identity, roots, nil)
	chain, err = trusted.validatePeer(signed, target)
	if chain != nil || err == nil || err.Error() != want {
		t.Fatalf("validatePeer = (%v, %v), want (nil, %q)", chain, err, want)
	}
}

func TestCertificateIdentifiesHostname(t *testing.T) {
	t.Parallel()

	var cert x509.Certificate
	const hostname = "trust-name.example.com"
	cert.DNSNames = []string{hostname}
	target := types.NewPrincipalName(nametype.KRB_NT_SRV_HST, "host/instance/"+hostname+".")
	if err := certificateIdentifies(&cert, target); err != nil {
		t.Fatalf("last component with trailing dot did not match: %v", err)
	}

	target = types.NewPrincipalName(nametype.KRB_NT_SRV_HST, "host/other.example.com.")
	err := certificateIdentifies(&cert, target)
	if err == nil {
		t.Fatal("certificateIdentifies accepted the wrong hostname")
	}
	cause, ok := errors.AsType[x509.HostnameError](err)
	if !ok || cause.Host != "other.example.com" {
		t.Fatalf("want hostname error for other.example.com, got %v", err)
	}
	const prefix = "PKU2U certificate does not identify target host/other.example.com.: "
	if want := prefix + cause.Error(); err.Error() != want {
		t.Fatalf("certificateIdentifies error = %q, want %q", err, want)
	}
}

func TestCertificateIdentifiesPrincipal(t *testing.T) {
	t.Parallel()

	var cert x509.Certificate
	cert.Subject.CommonName = "Server"
	for _, tt := range []struct {
		name     string
		cert     *x509.Certificate
		target   types.PrincipalName
		expected string
	}{
		{
			name:     "missing certificate",
			cert:     nil,
			target:   types.NewPrincipalName(nametype.KRB_NT_X500_PRINCIPAL, "CN=Server"),
			expected: "PKU2U certificate is required",
		},
		{
			name:     "single service component uses principal matching",
			cert:     &cert,
			target:   types.NewPrincipalName(nametype.KRB_NT_SRV_HST, "CN=Server"),
			expected: "",
		},
		{
			name:     "principal mismatch",
			cert:     &cert,
			target:   types.NewPrincipalName(nametype.KRB_NT_X500_PRINCIPAL, "CN=Other"),
			expected: "PKU2U certificate identifies CN=Server, not CN=Other",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := certificateIdentifies(tt.cert, tt.target)
			if tt.expected == "" {
				if err != nil {
					t.Fatalf("certificateIdentifies error = %v, want nil", err)
				}

				return
			}
			if err == nil || err.Error() != tt.expected {
				t.Fatalf("certificateIdentifies error = %v, want %q", err, tt.expected)
			}
		})
	}
}
