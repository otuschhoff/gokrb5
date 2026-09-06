package pku2u

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func (settings settings) validatePeer(signed *pkinit.VerifiedSignedData, expected types.PrincipalName) ([]*x509.Certificate, error) {
	if settings.identity == nil || settings.roots == nil {
		return nil, fmt.Errorf("PKU2U identity and trust anchors are required")
	}
	chain, err := pkinit.ValidateCertificateChain(signed, pkinit.CertificateChainPolicy{
		Roots: settings.roots, Intermediates: settings.intermediates,
		RequireRevocation: settings.requireRevocation,
		CurrentTime:       settings.currentTime(), HTTPClient: settings.httpClient,
	})
	if err != nil {
		return nil, fmt.Errorf("verify PKU2U peer certificate: %w", err)
	}
	if signed.Signer.KeyUsage != 0 && signed.Signer.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("PKU2U peer certificate does not permit digital signatures")
	}
	if err := certificateIdentifies(signed.Signer, expected); err != nil {
		return nil, err
	}
	return chain, nil
}

func certificateIdentifies(certificate *x509.Certificate, expected types.PrincipalName) error {
	if certificate == nil {
		return fmt.Errorf("PKU2U certificate is required")
	}
	if expected.NameType == nametype.KRB_NT_SRV_HST && len(expected.NameString) > 1 {
		if err := certificate.VerifyHostname(strings.TrimSuffix(expected.NameString[len(expected.NameString)-1], ".")); err != nil {
			return fmt.Errorf("PKU2U certificate does not identify target %s: %w", expected.PrincipalNameString(), err)
		}
		return nil
	}
	principal, err := PrincipalFromCertificate(certificate)
	if err != nil {
		return err
	}
	if !principal.Equal(expected) {
		return fmt.Errorf("PKU2U certificate identifies %s, not %s", principal.PrincipalNameString(), expected.PrincipalNameString())
	}
	return nil
}
