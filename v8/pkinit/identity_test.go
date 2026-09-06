package pkinit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
