package pkinit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEnvelopedDataRoundTrip(t *testing.T) {
	certificate, privateKey := testRSARecipient(t)
	for _, algorithm := range []ContentEncryptionAlgorithm{AES128CBC, AES256CBC, TripleDESCBC} {
		t.Run(string(rune('0'+algorithm)), func(t *testing.T) {
			der, err := EncryptEnvelopedData([]byte("reply-key-pack"), certificate, algorithm)
			require.NoError(t, err)
			plaintext, err := DecryptEnvelopedData(der, certificate, privateKey)
			require.NoError(t, err)
			require.Equal(t, []byte("reply-key-pack"), plaintext)
		})
	}
}

func TestEnvelopedDataRejectsWrongRecipientAndTrailingData(t *testing.T) {
	certificate, privateKey := testRSARecipient(t)
	der, err := EncryptEnvelopedData([]byte("reply-key-pack"), certificate, AES256CBC)
	require.NoError(t, err)
	other, _ := testRSARecipient(t)
	other.SerialNumber = big.NewInt(43)
	_, err = DecryptEnvelopedData(der, other, privateKey)
	require.ErrorContains(t, err, "recipient does not match")
	_, err = DecryptEnvelopedData(append(der, 0), certificate, privateKey)
	require.ErrorContains(t, err, "trailing bytes")
}

func testRSARecipient(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "PKINIT RSA recipient"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate, privateKey
}
