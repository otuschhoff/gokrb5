package pkinit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type unsupportedPublicKeySigner struct{ crypto.Signer }

func (unsupportedPublicKeySigner) Public() crypto.PublicKey { return struct{}{} }

func TestPEMIdentityAndUPNSelection(t *testing.T) {
	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", smartCardLogonOID())
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	identity, err := FromPEM(
		encodeIdentityPEM("CERTIFICATE", certificate.Raw),
		encodeIdentityPEM("PRIVATE KEY", keyDER),
		nil,
	)
	require.NoError(t, err)
	identity.KeyTrust = true
	var policy IdentityPolicy
	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	err = identity.ValidateForPrincipal(principal, "EXAMPLE.COM", policy)
	require.NoError(t, err)
	require.Len(t, identity.CertificateChain(), 1)
}

func TestIdentityRejectsWrongPrincipalAndEKU(t *testing.T) {
	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", asn1.ObjectIdentifier{1, 2, 3})
	identity, err := NewIdentity(certificate, nil, key, true)
	require.NoError(t, err)
	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "bob")
	var policy IdentityPolicy
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", policy), "lacks")
	policy.DisableEKUCheck = true
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", policy), "does not identify")
}

func TestIdentityPublicHelpersAndErrors(t *testing.T) {
	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	names, err := CertificatePrincipalNames(certificate)
	require.NoError(t, err)
	require.Equal(t, []string{"alice@EXAMPLE.COM"}, names)
	_, err = CertificatePrincipalNames(nil)
	require.Error(t, err)

	identity, err := NewIdentity(certificate, []*x509.Certificate{certificate}, key, true)
	require.NoError(t, err)
	require.Len(t, identity.CertificateChain(), 1)
	_, err = NewIdentity(nil, nil, key, false)
	require.Error(t, err)
	otherCertificate, _ := testClientCertificate(t, "other@EXAMPLE.COM", oidClientAuth)
	_, err = NewIdentity(otherCertificate, nil, key, false)
	require.ErrorContains(t, err, "does not match")

	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "Alice")
	var policy IdentityPolicy
	policy.AllowSubjectName = true
	require.NoError(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", policy))
	policy.AllowSubjectName = false
	policy.CurrentTime = certificate.NotAfter.Add(time.Hour)
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", policy), "not valid")

	sid := []byte{1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 244, 1, 0, 0}
	formatted, err := formatSID(sid)
	require.NoError(t, err)
	require.Equal(t, "S-1-5-21-1-2-500", formatted)
	for _, malformed := range [][]byte{nil, {1, 1, 0, 0, 0, 0, 0, 5}} {
		_, err = formatSID(malformed)
		require.Error(t, err)
	}
	_, err = FromPKCS12([]byte("invalid"), "password")
	require.ErrorContains(t, err, "decode PKINIT PKCS#12")
}

func TestIdentitySignerPublicKeyError(t *testing.T) {
	t.Parallel()

	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	signer := unsupportedPublicKeySigner{Signer: key}
	_, cause := x509.MarshalPKIXPublicKey(signer.Public())
	require.Error(t, cause)

	identity, err := NewIdentity(certificate, nil, signer, false)
	require.Nil(t, identity)
	require.ErrorContains(t, err, "marshal PKINIT signer public key")
	require.EqualError(t, errors.Unwrap(err), cause.Error())

	leaf, chain, err := selectSigningCertificate([]*x509.Certificate{certificate}, signer)
	require.Nil(t, leaf)
	require.Nil(t, chain)
	require.ErrorContains(t, err, "marshal PKINIT signer public key")
	require.EqualError(t, errors.Unwrap(err), cause.Error())
}

func TestPEMIdentityFormatsAndFailures(t *testing.T) {
	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	certificatePEM := encodeIdentityPEM("CERTIFICATE", certificate.Raw)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	//nolint:staticcheck // Exercise the RFC 1423 import path with a legacy encrypted fixture.
	encrypted, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, []byte("secret"), x509.PEMCipherAES256)
	require.NoError(t, err)
	identity, err := FromPEM(certificatePEM, pem.EncodeToMemory(encrypted), []byte("secret"))
	require.NoError(t, err)
	require.NotNil(t, identity.Signer)
	_, err = FromPEM(certificatePEM, pem.EncodeToMemory(encrypted), []byte("wrong"))
	// Legacy PEM encryption may accept padding with a wrong password and fail later when parsing the key.
	require.Error(t, err)

	_, err = FromPEM([]byte("not PEM"), nil, nil)
	require.ErrorContains(t, err, "certificate PEM is missing")
	_, err = FromPEM(certificatePEM, nil, nil)
	require.ErrorContains(t, err, "private key PEM is missing")
	_, err = FromPEM(certificatePEM, encodeIdentityPEM("PRIVATE KEY", []byte("invalid")), nil)
	require.ErrorContains(t, err, "unsupported PKINIT private key")
	_, err = parsePEMCertificates(encodeIdentityPEM("CERTIFICATE", []byte("invalid")))
	require.ErrorContains(t, err, "parse PKINIT certificate")

	otherCertificate, _ := testClientCertificate(t, "other@EXAMPLE.COM", oidClientAuth)
	_, err = FromPEM(encodeIdentityPEM("CERTIFICATE", otherCertificate.Raw), encodeIdentityPEM("PRIVATE KEY", keyDER), nil)
	require.ErrorContains(t, err, "matching private key was not found")
}

func encodeIdentityPEM(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Headers: nil, Bytes: der})
}

func TestPrivateKeyFormatsAndIdentityPolicies(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := parsePrivateKey(x509.MarshalPKCS1PrivateKey(rsaKey))
	require.NoError(t, err)
	require.True(t, rsaKey.PublicKey.Equal(signer.Public()))

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	_, err = parsePrivateKey(ecDER)
	require.NoError(t, err)

	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	identity, err := NewIdentity(certificate, nil, key, false)
	require.NoError(t, err)
	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	var policy IdentityPolicy
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", policy), "self-signed")
	identity.KeyTrust = true
	policy.CurrentTime = certificate.NotBefore.Add(-time.Hour)
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", policy), "not valid")

	withoutSAN := *certificate
	withoutSAN.Extensions = append([]pkix.Extension(nil), certificate.Extensions...)
	withoutSAN.Extensions = slices.DeleteFunc(withoutSAN.Extensions, func(extension pkix.Extension) bool {
		return extension.Id.Equal(oidSubjectAlternativeName)
	})
	identity.Certificate = &withoutSAN
	policy.CurrentTime = time.Time{}
	policy.AllowSubjectName = true
	subjectPrincipal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "Alice")
	require.NoError(t, identity.ValidateForPrincipal(subjectPrincipal, "EXAMPLE.COM", policy))
}

func testClientCertificate(t *testing.T, upn string, eku asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := new(x509.Certificate)
	template.SerialNumber = big.NewInt(7)
	template.Subject.CommonName = "Alice"
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.ExtraExtensions = []pkix.Extension{
		{Id: oidExtendedKeyUsage, Critical: false, Value: mustMarshal(t, []asn1.ObjectIdentifier{eku})},
		{Id: oidSubjectAlternativeName, Critical: false, Value: testUPNSAN(t, upn)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate, key
}

func testUPNSAN(t *testing.T, upn string) []byte {
	t.Helper()
	upnDER, err := asn1.MarshalWithParams(upn, "utf8")
	require.NoError(t, err)
	typeDER, err := asn1.Marshal(upnOID())
	require.NoError(t, err)
	value := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: upnDER, FullBytes: nil}
	typeDER = append(typeDER, mustMarshal(t, value)...)
	otherName := value
	otherName.Bytes = typeDER
	generalNames := asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: mustMarshal(t, otherName), FullBytes: nil,
	}
	return mustMarshal(t, generalNames)
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	require.NoError(t, err)
	return der
}
