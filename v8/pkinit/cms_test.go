package pkinit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSignedDataRoundTripWithPKINITContentType(t *testing.T) {
	leaf, key := testSigningIdentity(t)
	content := []byte("auth-pack")
	der, err := SignSignedData(OIDPKINITAuthData, content, []*x509.Certificate{leaf}, key)
	require.NoError(t, err)

	verified, err := VerifySignedData(der, OIDPKINITAuthData)
	require.NoError(t, err)
	require.Equal(t, content, verified.Content)
	require.Equal(t, leaf.Raw, verified.Signer.Raw)
	require.Len(t, verified.Certificates, 1)
}

func TestSignedDataRejectsUnexpectedContentTypeAndTrailingData(t *testing.T) {
	leaf, key := testSigningIdentity(t)
	der, err := SignSignedData(OIDPKINITAuthData, []byte("auth-pack"), []*x509.Certificate{leaf}, key)
	require.NoError(t, err)
	_, err = VerifySignedData(der, OIDPKINITDHKeyData)
	require.ErrorContains(t, err, "unexpected PKINIT CMS eContentType")
	_, err = VerifySignedData(append(der, 0), OIDPKINITAuthData)
	require.ErrorContains(t, err, "trailing bytes")
}

func testSigningIdentity(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	var rootTemplate x509.Certificate
	rootTemplate.SerialNumber = big.NewInt(1)
	rootTemplate.Subject.CommonName = "PKINIT test root"
	rootTemplate.NotBefore = now.Add(-time.Hour)
	rootTemplate.NotAfter = now.Add(time.Hour)
	rootTemplate.IsCA = true
	rootTemplate.BasicConstraintsValid = true
	rootTemplate.KeyUsage = x509.KeyUsageCertSign
	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	var leafTemplate x509.Certificate
	leafTemplate.SerialNumber = big.NewInt(2)
	leafTemplate.Subject.CommonName = "PKINIT test signer"
	leafTemplate.NotBefore = now.Add(-time.Hour)
	leafTemplate.NotAfter = now.Add(time.Hour)
	leafTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return leaf, leafKey
}
