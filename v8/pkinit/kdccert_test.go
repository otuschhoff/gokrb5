package pkinit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

type closeErrorReader struct {
	io.Reader
}

func (closeErrorReader) Close() error { return errors.New("close failed") }

type readErrorCloser struct{}

func (readErrorCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (readErrorCloser) Close() error             { return nil }

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

func TestReadRevocationBodyRejectsOversizeAndCloseErrors(t *testing.T) {
	data, err := readRevocationBody(io.NopCloser(strings.NewReader("data")), 4)
	require.NoError(t, err)
	require.Equal(t, []byte("data"), data)

	_, err = readRevocationBody(io.NopCloser(strings.NewReader("12345")), 4)
	require.ErrorContains(t, err, "exceeds")

	_, err = readRevocationBody(closeErrorReader{Reader: strings.NewReader("data")}, 4)
	require.ErrorContains(t, err, "close")

	_, err = readRevocationBody(readErrorCloser{}, 4)
	require.ErrorContains(t, err, "read")
}

func TestCheckOCSP(t *testing.T) {
	root, signer, rootKey := testRevocationChain(t)
	now := time.Now().UTC().Truncate(time.Second)
	var responseDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(responseDER)
	}))
	defer server.Close()
	signer.OCSPServer = []string{server.URL}

	responseDER = mustOCSPResponse(t, root, signer, rootKey, ocsp.Good, now)
	checked, err := checkOCSP(server.Client(), signer, root, now)
	require.NoError(t, err)
	require.True(t, checked)

	responseDER = mustOCSPResponse(t, root, signer, rootKey, ocsp.Revoked, now)
	checked, err = checkOCSP(server.Client(), signer, root, now)
	require.ErrorContains(t, err, "revoked")
	require.False(t, checked)
}

func TestCheckCRLs(t *testing.T) {
	root, signer, rootKey := testRevocationChain(t)
	now := time.Now().UTC().Truncate(time.Second)
	var responseDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(responseDER)
	}))
	defer server.Close()
	signer.CRLDistributionPoints = []string{server.URL}

	responseDER = mustCRL(t, root, rootKey, now, nil)
	checked, err := checkCRLs(server.Client(), signer, root, now)
	require.NoError(t, err)
	require.True(t, checked)

	responseDER = mustCRL(t, root, rootKey, now, []pkix.RevokedCertificate{{SerialNumber: signer.SerialNumber, RevocationTime: now.Add(-time.Minute)}})
	checked, err = checkCRLs(server.Client(), signer, root, now)
	require.ErrorContains(t, err, "revoked")
	require.False(t, checked)
}

func TestRevocationTimeValid(t *testing.T) {
	now := time.Now().UTC()
	require.True(t, revocationTimeValid(now, now.Add(-time.Minute), now.Add(time.Minute)))
	require.False(t, revocationTimeValid(now, now.Add(time.Minute), now.Add(2*time.Minute)))
	require.False(t, revocationTimeValid(now, now.Add(-2*time.Minute), now.Add(-time.Minute)))
	require.False(t, revocationTimeValid(now, now.Add(-time.Minute), time.Time{}))
}

func testRevocationChain(t *testing.T) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(200), Subject: pkix.Name{CommonName: "root"}, SubjectKeyId: []byte{1, 2, 3, 4},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(201), Subject: pkix.Name{CommonName: "KDC"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, root, &signerKey.PublicKey, rootKey)
	require.NoError(t, err)
	signer, err := x509.ParseCertificate(signerDER)
	require.NoError(t, err)
	return root, signer, rootKey
}

func mustOCSPResponse(t *testing.T, issuer, certificate *x509.Certificate, issuerKey *ecdsa.PrivateKey, status int, now time.Time) []byte {
	t.Helper()
	response, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
		Status: status, SerialNumber: certificate.SerialNumber, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute), RevokedAt: now.Add(-time.Minute),
	}, issuerKey)
	require.NoError(t, err)
	return response
}

func mustCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, now time.Time, entries []pkix.RevokedCertificate) []byte {
	t.Helper()
	list, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute), RevokedCertificates: entries,
	}, issuer, issuerKey)
	require.NoError(t, err)
	return list
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
