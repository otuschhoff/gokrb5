package pkinit

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pkcs12"

	"github.com/otuschhoff/gokrb5/v8/types"
)

//nolint:gochecknoglobals // Fixed OIDs shared with the client certificate fixtures; never mutated.
var (
	oidExtendedKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidClientAuth             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

func upnOID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
}

func smartCardLogonOID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
}

// Identity combines a client certificate with its signing key and intermediates.
type Identity struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	Signer      crypto.Signer
	SID         string
	KeyTrust    bool
}

// IdentityPolicy controls client certificate selection.
type IdentityPolicy struct {
	DisableEKUCheck  bool
	AllowSubjectName bool
	CurrentTime      time.Time
}

// NewIdentity validates that signer owns certificate's public key.
func NewIdentity(
	certificate *x509.Certificate,
	chain []*x509.Certificate,
	signer crypto.Signer,
	keyTrust bool,
) (*Identity, error) {
	if certificate == nil || signer == nil {
		return nil, errors.New("PKINIT certificate and signer are required")
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT certificate key: %w", err)
	}
	signerKey, err := marshalSignerPublicKey(signer)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certificateKey, signerKey) {
		return nil, errors.New("PKINIT signer does not match certificate")
	}
	sid, _ := certificateSID(certificate) // SID extraction is optional; malformed extensions leave it empty.
	return &Identity{Certificate: certificate, Chain: chain, Signer: signer, SID: sid, KeyTrust: keyTrust}, nil
}

// FromPEM loads a certificate chain and private key from PEM data.
func FromPEM(certificatePEM, keyPEM, password []byte) (*Identity, error) {
	certificates, err := parsePEMCertificates(certificatePEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("PKINIT private key PEM is missing")
	}
	keyDER := block.Bytes
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // Preserve detection of legacy RFC 1423 PEM imports.
		keyDER, err = x509.DecryptPEMBlock(block, password) //nolint:staticcheck // Import-only RFC 1423 compatibility.
		if err != nil {
			return nil, fmt.Errorf("decrypt PKINIT private key: %w", err)
		}
	}
	signer, err := parsePrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	leaf, chain, err := selectSigningCertificate(certificates, signer)
	if err != nil {
		return nil, err
	}
	return NewIdentity(leaf, chain, signer, false)
}

// FromPKCS12 loads an identity from a PFX/PKCS#12 value.
func FromPKCS12(pfx []byte, password string) (*Identity, error) {
	blocks, err := pkcs12.ToPEM(pfx, password)
	if err != nil {
		return nil, fmt.Errorf("decode PKINIT PKCS#12 identity: %w", err)
	}
	var certificatePEM, keyPEM []byte
	for _, block := range blocks {
		encoded := pem.EncodeToMemory(block)
		if block.Type == "CERTIFICATE" {
			certificatePEM = append(certificatePEM, encoded...)
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			keyPEM = append(keyPEM, encoded...)
		}
	}
	return FromPEM(certificatePEM, keyPEM, nil)
}

// CertificateChain returns the leaf followed by non-root intermediates for CMS.
func (identity *Identity) CertificateChain() []*x509.Certificate {
	chain := make([]*x509.Certificate, 0, len(identity.Chain)+1)
	chain = append(chain, identity.Certificate)
	for _, certificate := range identity.Chain {
		if !isSelfSigned(certificate) {
			chain = append(chain, certificate)
		}
	}
	return chain
}

// ValidateForPrincipal applies the MS-PKCA client certificate selection rules.
func (identity *Identity) ValidateForPrincipal(
	principal types.PrincipalName,
	realm string,
	policy IdentityPolicy,
) error {
	if err := identity.validateCertificate(policy); err != nil {
		return err
	}
	principalName := principal.PrincipalNameString()
	return matchCertificatePrincipal(identity.Certificate, principalName, realm, policy.AllowSubjectName)
}

func (identity *Identity) validateCertificate(policy IdentityPolicy) error {
	now := policy.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	certificate := identity.Certificate
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return fmt.Errorf("PKINIT client certificate is not valid at %s", now.UTC().Format(time.RFC3339))
	}
	if !policy.DisableEKUCheck && !certificateHasEKU(certificate, oidClientAuth, smartCardLogonOID()) {
		return errors.New("PKINIT client certificate lacks Client Authentication or Smart Card Logon EKU")
	}
	if isSelfSigned(certificate) && !identity.KeyTrust {
		return errors.New("self-signed PKINIT client certificate requires key-trust mode")
	}
	return nil
}

func matchCertificatePrincipal(certificate *x509.Certificate, principal, realm string, allowSubjectName bool) error {
	want := principal + "@" + realm
	names, err := certificatePrincipalNames(certificate)
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.EqualFold(name, want) {
			return nil
		}
	}
	commonName := certificate.Subject.CommonName
	if allowSubjectName && (strings.EqualFold(commonName, want) || strings.EqualFold(commonName, principal)) {
		return nil
	}
	return fmt.Errorf("PKINIT client certificate does not identify principal %s", want)
}

// CertificatePrincipalNames returns UPN and PKINIT principal names carried in
// the certificate's subject alternative name extension.
func CertificatePrincipalNames(certificate *x509.Certificate) ([]string, error) {
	if certificate == nil {
		return nil, errors.New("PKINIT certificate is required")
	}
	return certificatePrincipalNames(certificate)
}

func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		data = rest
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKINIT certificate: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, errors.New("PKINIT certificate PEM is missing")
	}
	return certificates, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported PKINIT private key")
}

func selectSigningCertificate(
	certificates []*x509.Certificate,
	signer crypto.Signer,
) (*x509.Certificate, []*x509.Certificate, error) {
	want, err := marshalSignerPublicKey(signer)
	if err != nil {
		return nil, nil, err
	}
	for index, certificate := range certificates {
		got, marshalErr := x509.MarshalPKIXPublicKey(certificate.PublicKey)
		if marshalErr == nil && bytes.Equal(got, want) {
			chain := append([]*x509.Certificate(nil), certificates[:index]...)
			chain = append(chain, certificates[index+1:]...)
			return certificate, chain, nil
		}
	}
	return nil, nil, errors.New("PKINIT certificate matching private key was not found")
}

func marshalSignerPublicKey(signer crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT signer public key: %w", err)
	}
	return der, nil
}

func certificateHasEKU(certificate *x509.Certificate, accepted ...asn1.ObjectIdentifier) bool {
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidExtendedKeyUsage) {
			continue
		}
		var usages []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(extension.Value, &usages); err != nil {
			return false
		}
		for _, usage := range usages {
			if slices.ContainsFunc(accepted, usage.Equal) {
				return true
			}
		}
	}
	return false
}

func certificatePrincipalNames(certificate *x509.Certificate) ([]string, error) {
	var names []string
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidSubjectAlternativeName) {
			continue
		}
		var err error
		names, err = appendSANPrincipalNames(names, extension.Value)
		if err != nil {
			return nil, err
		}
	}
	return names, nil
}

func appendSANPrincipalNames(names []string, der []byte) ([]string, error) {
	var generalNames asn1.RawValue
	if err := strictStdUnmarshal(der, &generalNames); err != nil || generalNames.Tag != asn1.TagSequence {
		return nil, errors.New("decode PKINIT client certificate SAN")
	}
	remaining := generalNames.Bytes
	for len(remaining) > 0 {
		var generalName asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &generalName)
		if err != nil {
			return nil, fmt.Errorf("decode PKINIT client certificate SAN: %w", err)
		}
		if generalName.Class != asn1.ClassContextSpecific || generalName.Tag != 0 {
			continue
		}
		name, recognized, err := parsePrincipalOtherName(generalName.Bytes)
		if err != nil {
			return nil, err
		}
		if recognized {
			names = append(names, name)
		}
	}
	return names, nil
}

func parsePrincipalOtherName(der []byte) (string, bool, error) {
	var typeID asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(der, &typeID)
	if err != nil {
		return "", false, fmt.Errorf("decode PKINIT SAN otherName type: %w", err)
	}
	var value asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &value)
	if err != nil || len(rest) != 0 || value.Class != asn1.ClassContextSpecific || value.Tag != 0 {
		return "", false, errors.New("decode PKINIT SAN otherName value")
	}
	if typeID.Equal(upnOID()) {
		var upn string
		if err := strictStdUnmarshal(value.Bytes, &upn); err != nil {
			return "", false, fmt.Errorf("decode PKINIT UPN SAN: %w", err)
		}
		return upn, true, nil
	}
	if typeID.Equal(asn1.ObjectIdentifier(OIDPKINITSAN)) {
		var principal KRB5PrincipalName
		if err := strictUnmarshal(value.Bytes, &principal); err != nil {
			return "", false, fmt.Errorf("decode PKINIT principal SAN: %w", err)
		}
		return principal.PrincipalName.PrincipalNameString() + "@" + principal.Realm, true, nil
	}
	return "", false, nil
}

func certificateSID(certificate *x509.Certificate) (string, error) {
	oidNtdsSecurityExtension := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2}
	oidObjectSID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2, 1}
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidNtdsSecurityExtension) {
			continue
		}
		var sequence struct {
			TypeID asn1.ObjectIdentifier
			Value  asn1.RawValue `asn1:"explicit,tag:0"`
		}
		if err := strictStdUnmarshal(extension.Value, &sequence); err != nil || !sequence.TypeID.Equal(oidObjectSID) {
			return "", errors.New("decode PKINIT SID extension")
		}
		var sid []byte
		if err := strictStdUnmarshal(sequence.Value.Bytes, &sid); err != nil {
			return "", fmt.Errorf("decode PKINIT SID: %w", err)
		}
		return formatSID(sid)
	}
	return "", nil
}

func formatSID(sid []byte) (string, error) {
	const (
		headerSize       = 8
		subAuthoritySize = 4
		bitsPerByte      = 8
	)
	// The count is a single byte, so the expected length cannot overflow int.
	if len(sid) < headerSize || len(sid) != headerSize+subAuthoritySize*int(sid[1]) {
		return "", errors.New("invalid binary SID")
	}
	authority := uint64(0)
	for _, value := range sid[2:headerSize] {
		authority = authority<<bitsPerByte | uint64(value)
	}
	parts := []string{fmt.Sprintf("S-%d-%d", sid[0], authority)}
	for field := range slices.Chunk(sid[headerSize:], subAuthoritySize) {
		subAuthority := binary.LittleEndian.Uint32(field)
		parts = append(parts, strconv.FormatUint(uint64(subAuthority), 10))
	}
	return strings.Join(parts, "-"), nil
}
