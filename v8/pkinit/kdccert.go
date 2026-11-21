package pkinit

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	maxOCSPResponseBytes     = 1 << 20
	maxCRLResponseBytes      = 16 << 20
	defaultRevocationTimeout = 10 * time.Second
)

// KDCEKUChecking selects the accepted KDC certificate EKU profile.
type KDCEKUChecking string

// KDCEKUChecking policies for the KDC certificate EKU.
const (
	// KDCEKUKDCAuthentication requires the KDC certificate to carry the KDC authentication EKU.
	KDCEKUKDCAuthentication KDCEKUChecking = "kdc"
	// KDCEKUServerAuth requires only the server authentication EKU on the KDC certificate.
	KDCEKUServerAuth KDCEKUChecking = "kpServerAuth"
	KDCEKUDisabled   KDCEKUChecking = "none"
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

// CertificateChainPolicy controls generic CMS signer chain validation.
type CertificateChainPolicy struct {
	Roots             *x509.CertPool
	Intermediates     *x509.CertPool
	RequireRevocation bool
	CurrentTime       time.Time
	HTTPClient        *http.Client
}

// ValidateCertificateChain verifies a CMS signer against configured trust
// anchors without imposing PKINIT KDC EKU or name requirements.
func ValidateCertificateChain(signed *VerifiedSignedData, policy CertificateChainPolicy) ([]*x509.Certificate, error) {
	if signed == nil || signed.Signer == nil || policy.Roots == nil {
		return nil, errors.New("PKINIT signer and trust anchors are required")
	}
	intermediates := x509.NewCertPool()
	if policy.Intermediates != nil {
		intermediates = cloneCertPool(policy.Intermediates)
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
	var options x509.VerifyOptions
	options.Roots = policy.Roots
	options.Intermediates = intermediates
	options.CurrentTime = now
	options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	chains, err := signed.Signer.Verify(options)
	if err != nil {
		return nil, fmt.Errorf("verify PKINIT certificate chain: %w", err)
	}
	chain := chains[0]
	if err := checkChainRevocation(chain, policy); err != nil {
		return nil, err
	}
	return chain, nil
}

// ValidateKDCCertificate validates the signer and returns its verified chain.
func ValidateKDCCertificate(signed *VerifiedSignedData, policy KDCCertificatePolicy) ([]*x509.Certificate, error) {
	chains, err := ValidateCertificateChain(signed, CertificateChainPolicy{
		Roots: policy.Roots, Intermediates: policy.Intermediates,
		RequireRevocation: policy.RequireRevocation, CurrentTime: policy.CurrentTime,
		HTTPClient: policy.HTTPClient,
	})
	if err != nil {
		return nil, fmt.Errorf("verify PKINIT KDC certificate: %w", err)
	}
	ekuMode := policy.EKUChecking
	if ekuMode == "" {
		ekuMode = KDCEKUKDCAuthentication
	}
	switch ekuMode {
	case KDCEKUKDCAuthentication:
		if !certificateHasEKU(signed.Signer, asn1.ObjectIdentifier(OIDPKINITKDC)) {
			return nil, errors.New("PKINIT KDC certificate lacks KDC Authentication EKU")
		}
	case KDCEKUServerAuth:
		if !certificateHasEKU(signed.Signer, serverAuthOID()) {
			return nil, errors.New("PKINIT KDC certificate lacks Server Authentication EKU")
		}
	case KDCEKUDisabled:
	default:
		return nil, fmt.Errorf("unknown PKINIT KDC EKU checking mode %q", ekuMode)
	}
	if err := validateKDCName(signed.Signer, policy.Hostname, policy.Realm); err != nil {
		return nil, err
	}
	return chains, nil
}

func serverAuthOID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
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

func checkChainRevocation(chain []*x509.Certificate, policy CertificateChainPolicy) error {
	client := policy.HTTPClient
	if client == nil {
		client = new(http.Client)
		client.Timeout = defaultRevocationTimeout
	}
	for index := 0; index+1 < len(chain); index++ {
		if err := checkCertificateRevocation(client, chain[index], chain[index+1], policy); err != nil {
			return err
		}
	}
	return nil
}

func checkCertificateRevocation(
	client *http.Client,
	certificate, issuer *x509.Certificate,
	policy CertificateChainPolicy,
) error {
	checked, err := checkOCSP(client, certificate, issuer, policy.CurrentTime)
	if err != nil && policy.RequireRevocation {
		return err
	}
	if err == nil && checked {
		return nil
	}
	checked, err = checkCRLs(client, certificate, issuer, policy.CurrentTime)
	if !policy.RequireRevocation {
		return nil
	}
	if err != nil || checked {
		return err
	}
	return fmt.Errorf("PKINIT revocation status is unavailable for %q", certificate.Subject)
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
		body, ok := fetchOCSPResponse(client, endpoint, requestDER)
		if !ok {
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

func fetchOCSPResponse(client *http.Client, endpoint string, requestDER []byte) ([]byte, bool) {
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(requestDER))
	if err != nil {
		return nil, false
	}
	request.Header.Set("Content-Type", "application/ocsp-request")
	response, err := client.Do(request) //nolint:bodyclose // readRevocationBody owns and closes the body on every path.
	if err != nil {
		return nil, false
	}
	body, err := readRevocationBody(response.Body, maxOCSPResponseBytes)
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, false
	}
	return body, true
}

func checkCRLs(client *http.Client, certificate, issuer *x509.Certificate, now time.Time) (bool, error) {
	if len(certificate.CRLDistributionPoints) == 0 {
		return false, nil
	}
	for _, endpoint := range certificate.CRLDistributionPoints {
		response, err := client.Get(endpoint) //nolint:bodyclose // readRevocationBody owns and closes the body on every path.
		if err != nil {
			continue
		}
		body, readErr := readRevocationBody(response.Body, maxCRLResponseBytes)
		if readErr != nil || response.StatusCode != http.StatusOK {
			continue
		}
		if usable, err := checkCRLResponse(body, certificate, issuer, now); usable {
			return err == nil, err
		}
	}
	return false, fmt.Errorf("PKINIT CRL status is unavailable for %q", certificate.Subject)
}

// checkCRLResponse reports whether this response establishes revocation status.
func checkCRLResponse(body []byte, certificate, issuer *x509.Certificate, now time.Time) (bool, error) {
	list, err := x509.ParseCRL(body) //nolint:staticcheck // Preserve PEM and legacy DER parsing accepted by ParseCRL.
	if err != nil {
		return false, fmt.Errorf("parse PKINIT CRL: %w", err)
	}
	//nolint:staticcheck // CheckSignatureFrom adds issuer constraints.
	if err := issuer.CheckCRLSignature(list); err != nil {
		return false, fmt.Errorf("verify PKINIT CRL signature: %w", err)
	}
	tbs := list.TBSCertList
	if !revocationTimeValid(now, tbs.ThisUpdate, tbs.NextUpdate) {
		return false, nil
	}
	for _, entry := range tbs.RevokedCertificates {
		if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return true, fmt.Errorf("PKINIT KDC certificate %q is revoked", certificate.Subject)
		}
	}
	return true, nil
}

func readRevocationBody(body io.ReadCloser, maximum int64) ([]byte, error) {
	data, readErr := io.ReadAll(io.LimitReader(body, maximum+1))
	closeErr := body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read revocation response: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close revocation response: %w", closeErr)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("revocation response exceeds %d bytes", maximum)
	}
	return data, nil
}

func revocationTimeValid(now, thisUpdate, nextUpdate time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	return !now.Before(thisUpdate) && !nextUpdate.IsZero() && !now.After(nextUpdate)
}
