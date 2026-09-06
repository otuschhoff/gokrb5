package pkinit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateKDCCertificate(t *testing.T) {
	root, signer, _ := testKDCChain(t, asn1.ObjectIdentifier(OIDPKINITKDC), "example.com", time.Now().Add(time.Hour))
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	chain, err := ValidateKDCCertificate(&VerifiedSignedData{Signer: signer, Certificates: []*x509.Certificate{signer}}, KDCCertificatePolicy{
		Roots: anchors, Realm: "EXAMPLE.COM", CurrentTime: time.Now(),
	})
	require.NoError(t, err)
	require.Len(t, chain, 2)
}

func TestValidateKDCCertificateRejectsPolicyViolations(t *testing.T) {
	root, signer, _ := testKDCChain(t, oidServerAuth, "dc.example.com", time.Now().Add(time.Hour))
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	verified := &VerifiedSignedData{Signer: signer, Certificates: []*x509.Certificate{signer}}
	_, err := ValidateKDCCertificate(verified, KDCCertificatePolicy{Roots: anchors, Realm: "EXAMPLE.COM", Hostname: "dc.example.com"})
	require.ErrorContains(t, err, "lacks KDC Authentication")
	_, err = ValidateKDCCertificate(verified, KDCCertificatePolicy{Roots: anchors, Realm: "EXAMPLE.COM", Hostname: "other.example.com", EKUChecking: KDCEKUServerAuth})
	require.ErrorContains(t, err, "does not identify")
}

func testKDCChain(t *testing.T, eku asn1.ObjectIdentifier, dnsName string, notAfter time.Time) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "KDC"}, DNSNames: []string{dnsName},
		NotBefore: now.Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: oidExtendedKeyUsage, Value: mustMarshal(t, []asn1.ObjectIdentifier{eku})}},
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, root, &signerKey.PublicKey, rootKey)
	require.NoError(t, err)
	signer, err := x509.ParseCertificate(signerDER)
	require.NoError(t, err)
	return root, signer, signerKey
}
