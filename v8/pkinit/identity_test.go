package pkinit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/require"
)

func TestPEMIdentityAndUPNSelection(t *testing.T) {
	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", oidSmartCardLogon)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	identity, err := FromPEM(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil,
	)
	require.NoError(t, err)
	identity.KeyTrust = true
	err = identity.ValidateForPrincipal(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"), "EXAMPLE.COM", IdentityPolicy{})
	require.NoError(t, err)
	require.Len(t, identity.CertificateChain(), 1)
}

func TestIdentityRejectsWrongPrincipalAndEKU(t *testing.T) {
	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", asn1.ObjectIdentifier{1, 2, 3})
	identity, err := NewIdentity(certificate, nil, key, true)
	require.NoError(t, err)
	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "bob")
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", IdentityPolicy{}), "lacks")
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", IdentityPolicy{DisableEKUCheck: true}), "does not identify")
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
	require.NoError(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", IdentityPolicy{AllowSubjectName: true}))
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", IdentityPolicy{CurrentTime: certificate.NotAfter.Add(time.Hour)}), "not valid")

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

func TestPEMIdentityFormatsAndFailures(t *testing.T) {
	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	encrypted, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, []byte("secret"), x509.PEMCipherAES256)
	require.NoError(t, err)
	identity, err := FromPEM(certificatePEM, pem.EncodeToMemory(encrypted), []byte("secret"))
	require.NoError(t, err)
	require.NotNil(t, identity.Signer)
	_, err = FromPEM(certificatePEM, pem.EncodeToMemory(encrypted), []byte("wrong"))
	require.ErrorContains(t, err, "decrypt PKINIT private key")

	_, err = FromPEM([]byte("not PEM"), nil, nil)
	require.ErrorContains(t, err, "certificate PEM is missing")
	_, err = FromPEM(certificatePEM, nil, nil)
	require.ErrorContains(t, err, "private key PEM is missing")
	_, err = FromPEM(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}), nil)
	require.ErrorContains(t, err, "unsupported PKINIT private key")
	_, err = parsePEMCertificates(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}))
	require.ErrorContains(t, err, "parse PKINIT certificate")

	otherCertificate, _ := testClientCertificate(t, "other@EXAMPLE.COM", oidClientAuth)
	_, err = FromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherCertificate.Raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil)
	require.ErrorContains(t, err, "matching private key was not found")
}

func TestPrivateKeyFormatsAndIdentityPolicies(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	signer, err := parsePrivateKey(x509.MarshalPKCS1PrivateKey(rsaKey))
	require.NoError(t, err)
	require.Equal(t, rsaKey.PublicKey, *signer.Public().(*rsa.PublicKey))

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
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", IdentityPolicy{}), "self-signed")
	identity.KeyTrust = true
	require.ErrorContains(t, identity.ValidateForPrincipal(principal, "EXAMPLE.COM", IdentityPolicy{CurrentTime: certificate.NotBefore.Add(-time.Hour)}), "not valid")

	withoutSAN := *certificate
	withoutSAN.Extensions = append([]pkix.Extension(nil), certificate.Extensions...)
	for index := len(withoutSAN.Extensions) - 1; index >= 0; index-- {
		if withoutSAN.Extensions[index].Id.Equal(oidSubjectAlternativeName) {
			withoutSAN.Extensions = append(withoutSAN.Extensions[:index], withoutSAN.Extensions[index+1:]...)
		}
	}
	identity.Certificate = &withoutSAN
	require.NoError(t, identity.ValidateForPrincipal(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "Alice"), "EXAMPLE.COM", IdentityPolicy{AllowSubjectName: true}))
}

func testClientCertificate(t *testing.T, upn string, eku asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Alice"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtendedKeyUsage, Value: mustMarshal(t, []asn1.ObjectIdentifier{eku})},
			{Id: oidSubjectAlternativeName, Value: testUPNSAN(t, upn)},
		},
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
	typeDER, err := asn1.Marshal(oidUPN)
	require.NoError(t, err)
	otherNameDER := append(typeDER, mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: upnDER})...)
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: otherNameDER})})
}

func mustMarshal(t *testing.T, value interface{}) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	require.NoError(t, err)
	return der
}
