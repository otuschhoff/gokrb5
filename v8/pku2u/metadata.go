package pku2u

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
)

// TrustedCertifiers is the PKU2U metadata exchanged through NEGOEX. Each
// entry identifies a certification authority trusted by the sender.
type TrustedCertifiers []pkinit.ExternalPrincipalIdentifier

// Marshal encodes trusted-certifier metadata as DER.
func (m TrustedCertifiers) Marshal() ([]byte, error) {
	return asn1.Marshal([]pkinit.ExternalPrincipalIdentifier(m))
}

// Unmarshal decodes trusted-certifier metadata and rejects trailing data or
// entries which do not identify a certifier.
func (m *TrustedCertifiers) Unmarshal(data []byte) error {
	var decoded []pkinit.ExternalPrincipalIdentifier
	rest, err := asn1.Unmarshal(data, &decoded)
	if err != nil {
		return fmt.Errorf("decode PKU2U trusted certifiers: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("PKU2U trusted certifiers contain %d trailing bytes", len(rest))
	}
	for _, certifier := range decoded {
		fields := 0
		if len(certifier.SubjectName) > 0 {
			fields++
		}
		if len(certifier.IssuerAndSerial) > 0 {
			fields++
		}
		if len(certifier.SubjectKeyIdentifier) > 0 {
			fields++
		}
		if fields != 1 {
			return fmt.Errorf("PKU2U trusted certifier must contain exactly one identifier")
		}
	}
	*m = append((*m)[:0], decoded...)
	return nil
}

// TrustedCertifiersFromPool creates metadata entries from a pool's trusted
// subject names.
func TrustedCertifiersFromPool(pool *x509.CertPool) TrustedCertifiers {
	if pool == nil {
		return nil
	}
	subjects := pool.Subjects()
	certifiers := make(TrustedCertifiers, 0, len(subjects))
	for _, subject := range subjects {
		certifiers = append(certifiers, pkinit.ExternalPrincipalIdentifier{SubjectName: append([]byte(nil), subject...)})
	}
	return certifiers
}

// Accepts reports whether metadata identifies an issuer in identity's chain.
// Empty metadata imposes no certificate-selection restriction.
func (m TrustedCertifiers) Accepts(identity *pkinit.Identity) bool {
	if len(m) == 0 {
		return true
	}
	if identity == nil || identity.Certificate == nil {
		return false
	}
	chain := identity.CertificateChain()
	for _, certifier := range m {
		for _, certificate := range chain {
			if len(certifier.SubjectName) > 0 && bytes.Equal(certifier.SubjectName, certificate.RawIssuer) {
				return true
			}
			if len(certifier.SubjectKeyIdentifier) > 0 && bytes.Equal(certifier.SubjectKeyIdentifier, certificate.AuthorityKeyId) {
				return true
			}
		}
	}
	return false
}
