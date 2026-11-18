package pkinit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEnvelopedDataRoundTrip(t *testing.T) {
	certificate, privateKey := testRSARecipient(t)
	for _, algorithm := range []ContentEncryptionAlgorithm{AES128CBC, AES256CBC, TripleDESCBC} {
		t.Run(fmt.Sprint(algorithm), func(t *testing.T) {
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

func TestEnvelopedDataDERDecodeErrors(t *testing.T) {
	t.Parallel()

	certificate, privateKey := testRSARecipient(t)
	plaintext, err := DecryptEnvelopedData([]byte{0x30}, certificate, privateKey)
	require.Nil(t, plaintext)
	require.ErrorContains(t, err, "decode PKINIT CMS ContentInfo: parse DER")
	require.ErrorAs(t, err, new(asn1.SyntaxError))
}

func TestEnvelopedDataInvalidIV(t *testing.T) {
	t.Parallel()

	certificate, privateKey := testRSARecipient(t)
	der, err := EncryptEnvelopedData([]byte("reply-key-pack"), certificate, AES128CBC)
	require.NoError(t, err)

	var info cmsContentInfo
	require.NoError(t, strictStdUnmarshal(der, &info))
	var envelope cmsEnvelopedData
	require.NoError(t, strictStdUnmarshal(info.Content.Bytes, &envelope))

	tests := []struct {
		name       string
		parameters asn1.RawValue
		wantCause  bool
	}{
		{name: "not an octet string", parameters: asn1.NullRawValue, wantCause: true},
		{name: "wrong size", parameters: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte{1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters = tt.parameters
			inner, err := asn1.Marshal(envelope)
			require.NoError(t, err)
			info.Content.FullBytes = nil
			info.Content.Bytes = inner
			invalid, err := asn1.Marshal(info)
			require.NoError(t, err)

			plaintext, err := DecryptEnvelopedData(invalid, certificate, privateKey)
			require.Nil(t, plaintext)
			const context = "invalid PKINIT CMS content cipher IV"
			if tt.wantCause {
				require.ErrorContains(t, err, context)
				require.ErrorAs(t, err, new(asn1.StructuralError))
				return
			}
			require.EqualError(t, err, context)
		})
	}
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
