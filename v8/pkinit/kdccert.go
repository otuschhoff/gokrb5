package pkinit

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

var oidServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}

// KDCEKUChecking selects the accepted KDC certificate EKU profile.
type KDCEKUChecking string

const (
	KDCEKUKDCAuthentication KDCEKUChecking = "kdc"
	KDCEKUServerAuth        KDCEKUChecking = "kpServerAuth"
	KDCEKUDisabled          KDCEKUChecking = "none"
)

// KDCCertificatePolicy controls PKINIT KDC certificate validation.
type KDCCertificatePolicy struct {
	Roots             *x509.CertPool
	Intermediates     *x509.CertPool
	Realm             string
	Hostname          string
	EKUChecking       KDCEKUChecking
	RequireRevocation bool
	CurrentTime       time.Time
	HTTPClient        *http.Client
}

// ValidateKDCCertificate validates the signer and returns its verified chain.
func ValidateKDCCertificate(signed *VerifiedSignedData, policy KDCCertificatePolicy) ([]*x509.Certificate, error) {
	if signed == nil || signed.Signer == nil || policy.Roots == nil {
		return nil, fmt.Errorf("PKINIT KDC signer and trust anchors are required")
	}
	intermediates := x509.NewCertPool()
	if policy.Intermediates != nil {
		intermediates = policy.Intermediates.Clone()
	}
	for _, certificate := range signed.Certificates {
		if !bytes.Equal(certificate.Raw, signed.Signer.Raw) {
			intermediates.AddCert(certificate)
		}
	}
	now := policy.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	chains, err := signed.Signer.Verify(x509.VerifyOptions{
		Roots: policy.Roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("verify PKINIT KDC certificate chain: %w", err)
	}
	ekuMode := policy.EKUChecking
	if ekuMode == "" {
		ekuMode = KDCEKUKDCAuthentication
	}
	switch ekuMode {
	case KDCEKUKDCAuthentication:
		if !certificateHasEKU(signed.Signer, asn1.ObjectIdentifier(OIDPKINITKDC)) {
			return nil, fmt.Errorf("PKINIT KDC certificate lacks KDC Authentication EKU")
		}
	case KDCEKUServerAuth:
		if !certificateHasEKU(signed.Signer, oidServerAuth) {
			return nil, fmt.Errorf("PKINIT KDC certificate lacks Server Authentication EKU")
		}
	case KDCEKUDisabled:
	default:
		return nil, fmt.Errorf("unknown PKINIT KDC EKU checking mode %q", ekuMode)
	}
	if err := validateKDCName(signed.Signer, policy.Hostname, policy.Realm); err != nil {
		return nil, err
	}
	chain := chains[0]
	if err := checkChainRevocation(chain, policy); err != nil {
		return nil, err
	}
	return chain, nil
}

func validateKDCName(certificate *x509.Certificate, hostname, realm string) error {
	if hostname == "" && realm != "" {
		hostname = strings.ToLower(realm)
	}
	for _, dnsName := range certificate.DNSNames {
		if hostname != "" && strings.EqualFold(strings.TrimSuffix(dnsName, "."), strings.TrimSuffix(hostname, ".")) {
			return nil
		}
	}
	principals, err := certificatePrincipalNames(certificate)
	if err != nil {
		return fmt.Errorf("decode PKINIT KDC certificate names: %w", err)
	}
	for _, principal := range principals {
		if strings.EqualFold(principal, "krbtgt/"+realm+"@"+realm) {
			return nil
		}
	}
	return fmt.Errorf("PKINIT KDC certificate does not identify %s", hostname)
}

func checkChainRevocation(chain []*x509.Certificate, policy KDCCertificatePolicy) error {
	client := policy.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	for index := 0; index+1 < len(chain); index++ {
		certificate, issuer := chain[index], chain[index+1]
		checked, err := checkOCSP(client, certificate, issuer, policy.CurrentTime)
		if err != nil {
			if policy.RequireRevocation {
				return err
			}
		} else if checked {
			continue
		}
		checked, err = checkCRLs(client, certificate, issuer, policy.CurrentTime)
		if err != nil {
			if policy.RequireRevocation {
				return err
			}
		} else if checked {
			continue
		}
		if policy.RequireRevocation {
			return fmt.Errorf("PKINIT revocation status is unavailable for %q", certificate.Subject)
		}
	}
	return nil
}

func checkOCSP(client *http.Client, certificate, issuer *x509.Certificate, now time.Time) (bool, error) {
	if len(certificate.OCSPServer) == 0 {
		return false, nil
	}
	requestDER, err := ocsp.CreateRequest(certificate, issuer, nil)
	if err != nil {
		return false, fmt.Errorf("create PKINIT OCSP request: %w", err)
	}
	for _, endpoint := range certificate.OCSPServer {
		request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(requestDER))
		if err != nil {
			continue
		}
		request.Header.Set("Content-Type", "application/ocsp-request")
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			continue
		}
		parsed, err := ocsp.ParseResponseForCert(body, certificate, issuer)
		if err != nil {
			continue
		}
		if parsed.Status == ocsp.Revoked {
			return false, fmt.Errorf("PKINIT KDC certificate %q is revoked", certificate.Subject)
		}
		if parsed.Status != ocsp.Good || !revocationTimeValid(now, parsed.ThisUpdate, parsed.NextUpdate) {
			continue
		}
		return true, nil
	}
	return false, fmt.Errorf("PKINIT OCSP status is unavailable for %q", certificate.Subject)
}

func checkCRLs(client *http.Client, certificate, issuer *x509.Certificate, now time.Time) (bool, error) {
	if len(certificate.CRLDistributionPoints) == 0 {
		return false, nil
	}
	for _, endpoint := range certificate.CRLDistributionPoints {
		response, err := client.Get(endpoint)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 16*1024*1024))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			continue
		}
		list, err := x509.ParseRevocationList(body)
		if err != nil || list.CheckSignatureFrom(issuer) != nil || !revocationTimeValid(now, list.ThisUpdate, list.NextUpdate) {
			continue
		}
		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
				return false, fmt.Errorf("PKINIT KDC certificate %q is revoked", certificate.Subject)
			}
		}
		return true, nil
	}
	return false, fmt.Errorf("PKINIT CRL status is unavailable for %q", certificate.Subject)
}

func revocationTimeValid(now, thisUpdate, nextUpdate time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	return !now.Before(thisUpdate) && !nextUpdate.IsZero() && !now.After(nextUpdate)
}
