// Package pku2u implements public-key user-to-user authentication from
// MS-PKU2U.
package pku2u

import (
	"crypto/x509"
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// Realm is the well-known Kerberos realm used by PKU2U exchanges.
const Realm = "WELLKNOWN:PKU2U"

// PrincipalFromCertificate maps a certificate identity to the principal form
// used by PKU2U. A UPN SAN takes precedence over the X.500 subject fallback.
func PrincipalFromCertificate(certificate *x509.Certificate) (types.PrincipalName, error) {
	names, err := pkinit.CertificatePrincipalNames(certificate)
	if err != nil {
		return types.PrincipalName{}, err
	}
	if len(names) > 0 {
		return types.NewPrincipalName(nametype.KRB_NT_ENTERPRISE, names[0]), nil
	}
	if certificate.Subject.String() == "" {
		return types.PrincipalName{}, fmt.Errorf("PKU2U certificate has no principal name or subject")
	}
	return types.NewPrincipalName(nametype.KRB_NT_X500_PRINCIPAL, certificate.Subject.String()), nil
}
